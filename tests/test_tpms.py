import json
import os
import sys
import unittest

import tpms
import watcher
import web
from tests.helpers import make_cfg, tmpdir

H = {"X-Requested-With": "tripline"}


def line(model="Toyota", sid="1a2b3c4d", **kw):
    d = {"time": 1700000000, "model": model, "type": "TPMS", "id": sid, "pressure_kPa": 230.0,
         "rssi": -12.5, "freq": 314.97}
    d.update(kw)
    return json.dumps(d)


class Parse(unittest.TestCase):
    def test_tpms_message(self):
        m = tpms.parse(line())
        self.assertEqual((m["vid"], m["rssi"]), ("Toyota:1a2b3c4d", -12.5))

    def test_pressure_key_without_type(self):
        d = json.loads(line()); del d["type"]
        self.assertIsNotNone(tpms.parse(json.dumps(d)))

    def test_ignores_other_sensors_and_garbage(self):
        self.assertIsNone(tpms.parse(json.dumps({"model": "Acurite-Tower", "id": 5, "temperature_C": 20})))
        self.assertIsNone(tpms.parse("not json"))
        self.assertIsNone(tpms.parse("[1,2]"))
        self.assertIsNone(tpms.parse(json.dumps({"type": "TPMS"})))

    def test_numeric_id(self):
        self.assertEqual(tpms.parse(line(sid=12345))["vid"], "Toyota:12345")


class Record(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        self.db = watcher.db_connect(self.cfg)
        self.msg = tpms.parse(line())

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def alerts(self):
        return self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def test_learning_mode_logs_without_alert(self):
        self.assertFalse(tpms.record(self.cfg, self.db, self.msg, 1000, {}))
        self.assertEqual(self.db.execute("SELECT seen_count FROM vehicles").fetchone()[0], 1)

    def test_unknown_vehicle_alerts_once_per_cooldown(self):
        watcher.meta_set(self.db, "mode", "home")
        seen, t0 = {}, 1_700_000_000
        self.assertTrue(tpms.record(self.cfg, self.db, self.msg, t0, seen))
        self.assertFalse(tpms.record(self.cfg, self.db, self.msg, t0 + 10, seen))
        self.assertTrue(tpms.record(self.cfg, self.db, self.msg, t0 + 31 * 60, seen))
        self.assertEqual(self.alerts(), 2)

    def test_known_vehicle_does_not_alert(self):
        watcher.meta_set(self.db, "mode", "away")
        tpms.record(self.cfg, self.db, self.msg, 1000, {})
        self.db.execute("UPDATE vehicles SET known=1"); self.db.commit()
        self.assertFalse(tpms.record(self.cfg, self.db, self.msg, 2000, {}))
        self.assertEqual(self.alerts(), 0)

    def test_guest_window_suppresses(self):
        watcher.meta_set(self.db, "mode", "home")
        watcher.meta_set(self.db, "quiet_until", 9999999999)
        self.assertFalse(tpms.record(self.cfg, self.db, self.msg, 1000, {}))

    def test_known_status_survives_new_messages(self):
        tpms.record(self.cfg, self.db, self.msg, 1000, {})
        self.db.execute("UPDATE vehicles SET known=1, label='Truck'"); self.db.commit()
        tpms.record(self.cfg, self.db, self.msg, 1100, {})
        self.assertEqual(self.db.execute("SELECT known,label,seen_count FROM vehicles").fetchone(), (1, "Truck", 2))


class Command(unittest.TestCase):
    def cfgv(self, **kv):
        t = tmpdir(); self.addCleanup(t.cleanup)
        return make_cfg(t.name, vehicles=kv)

    def test_default_watches_both_bands_and_hops_fast(self):
        self.assertEqual(tpms.command(self.cfgv()),
                         "rtl_433 -d 0 -f 315M -f 433.92M -H 10 -F json -M level -M protocol -M time:unix")

    def test_single_frequency_does_not_hop(self):
        c = tpms.command(self.cfgv(frequencies="433.92M"))
        self.assertEqual(c, "rtl_433 -d 0 -f 433.92M -F json -M level -M protocol -M time:unix")

    def test_hop_seconds_configurable(self):
        self.assertIn("-H 5", tpms.command(self.cfgv(hop_seconds="5")))

    def test_custom_command_gets_substitutions(self):
        c = tpms.command(self.cfgv(command="myrtl -d {device} {freqs}", device="1"))
        self.assertEqual(c, "myrtl -d 1 -f 315M -f 433.92M -H 10")

    def test_shell_metacharacters_are_quoted(self):
        c = tpms.command(self.cfgv(device="0; rm -rf /"))
        self.assertIn("'0; rm -rf /'", c)


class RunWithFakeDecoder(unittest.TestCase):
    def test_consume_from_subprocess(self):
        import subprocess
        with tmpdir() as t:
            cfg = make_cfg(t)
            db = watcher.db_connect(cfg)
            script = os.path.join(t, "fake.py")
            with open(script, "w") as fh:
                fh.write("import sys\nprint('garbage')\nprint(%r)\nprint(%r)\n" % (line(), line(sid="ff00ff00")))
            p = subprocess.Popen([sys.executable, script], stdout=subprocess.PIPE, text=True)
            tpms.consume(cfg, db, p.stdout)
            p.wait()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0], 2)
            db.close()


class RadioHealth(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        self.db = watcher.db_connect(self.cfg)

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def status(self, now):
        return watcher.radio_status(self.db, now)["state"]

    def test_never_started(self):
        self.assertEqual(self.status(1000), "never")

    def test_quiet_then_ok_after_any_message(self):
        radio = tpms.Radio(self.db)
        radio.started()
        now = int(__import__("time").time())
        watcher.meta_set(self.db, "sdr_beat", now)
        self.assertEqual(self.status(now), "quiet")
        # a weather station, not a tyre sensor: still proves the radio works
        tpms.consume(self.cfg, self.db, [json.dumps({"model": "Acurite-Tower", "id": 5, "temperature_C": 20})], radio)
        self.assertEqual(self.status(now), "ok")
        self.assertEqual(watcher.radio_status(self.db, now)["total"], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0], 0)

    def test_garbage_lines_do_not_count(self):
        radio = tpms.Radio(self.db)
        radio.started()
        now = int(__import__("time").time())
        watcher.meta_set(self.db, "sdr_beat", now)
        tpms.consume(self.cfg, self.db, ["not json", "[1]"], radio)
        self.assertEqual(self.status(now), "quiet")

    def test_failed_decoder_and_recovery(self):
        radio = tpms.Radio(self.db)
        now = int(__import__("time").time())
        radio.started()
        watcher.meta_set(self.db, "sdr_beat", now)
        radio.exited(2)
        r = watcher.radio_status(self.db, now)
        self.assertEqual((r["state"], r["exit_code"]), ("failed", 2))
        watcher.meta_set(self.db, "sdr_started", now + 10)  # restarted
        self.assertEqual(self.status(now + 10), "quiet")

    def test_stale_heartbeat_means_service_stopped(self):
        radio = tpms.Radio(self.db)
        radio.started()
        watcher.meta_set(self.db, "sdr_beat", 1000)
        self.assertEqual(self.status(1000 + 300), "stopped")

    def test_old_message_from_a_previous_run_is_not_ok(self):
        watcher.meta_set(self.db, "sdr_last", 500)
        watcher.meta_set(self.db, "sdr_started", 1000)
        watcher.meta_set(self.db, "sdr_beat", 1000)
        self.assertEqual(self.status(1010), "quiet")


class Passes(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        self.db = watcher.db_connect(self.cfg)

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def hit(self, sid, ts, **kw):
        tpms.record(self.cfg, self.db, tpms.parse(line(sid=sid, **kw)), ts, {})

    def test_repeat_messages_log_one_hit_per_ten_seconds(self):
        for ts in (1000, 1001, 1002, 1009, 1010, 1030):
            self.hit("aa", ts)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM vehicle_hits").fetchone()[0], 3)

    def test_sensors_of_one_car_form_one_pass(self):
        import identity
        for i, sid in enumerate(("a1", "a2", "a3", "a4")):
            self.hit(sid, 1000 + i * 20, rssi=-30 - i)
        self.hit("a1", 1000 + 3600)  # an hour later: a second pass
        passes = identity.vehicle_passes(self.db, 1000 + 3700)
        self.assertEqual([p["sensors"] for p in passes], [1, 4])
        self.assertEqual(passes[1]["best_rssi"], -30)
        self.assertFalse(passes[1]["known"])

    def test_pass_is_known_only_when_every_sensor_is_known(self):
        import identity
        self.hit("a1", 1000); self.hit("a2", 1010)
        self.db.execute("UPDATE vehicles SET known=1, label='Truck' WHERE vid='Toyota:a1'")
        p = identity.vehicle_passes(self.db, 1100)[0]
        self.assertEqual((p["known"], p["unknown_sensors"], p["name"]), (False, 1, "Truck"))
        self.db.execute("UPDATE vehicles SET known=1")
        self.assertTrue(identity.vehicle_passes(self.db, 1100)[0]["known"])

    def test_window_excludes_old_hits(self):
        import identity
        self.hit("a1", 1000)
        self.assertEqual(identity.vehicle_passes(self.db, 1000 + 25 * 3600), [])

    def test_purge_drops_old_hits_and_reset_clears_them(self):
        self.hit("a1", 1000)
        watcher.purge(self.db, self.cfg, 1000 + 40 * 86400)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM vehicle_hits").fetchone()[0], 0)
        self.hit("a1", 5000)
        watcher.reset_db(self.db)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM vehicle_hits").fetchone()[0], 0)


class VehicleApi(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        web._cfg = self.cfg
        self.client = web.app.test_client()
        self.db = watcher.db_connect(self.cfg)
        tpms.record(self.cfg, self.db, tpms.parse(line()), 1000, {})

    def tearDown(self):
        web._cfg = None
        self.db.close()
        self.t.cleanup()

    def test_list_and_mark_known(self):
        d = self.client.get("/api/vehicles").get_json()
        self.assertEqual(d["vehicles"][0]["vid"], "Toyota:1a2b3c4d")
        r = self.client.post("/api/vehicles/known", json={"vid": "Toyota:1a2b3c4d", "label": "Truck"}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.db.execute("SELECT known,label FROM vehicles").fetchone(), (1, "Truck"))
        self.client.post("/api/vehicles/known", json={"vid": "Toyota:1a2b3c4d", "known": False}, headers=H)
        self.assertEqual(self.db.execute("SELECT known,label FROM vehicles").fetchone(), (0, None))

    def test_api_reports_radio_state(self):
        d = self.client.get("/api/vehicles").get_json()
        self.assertEqual(d["radio"]["state"], "never")
        self.assertEqual(d["radio"]["last_sensor"], 1000)

    def test_passes_endpoint(self):
        now = int(__import__("time").time())
        tpms.record(self.cfg, self.db, tpms.parse(line(sid="zz")), now - 120, {})
        d = self.client.get("/api/vehicles/passes").get_json()
        self.assertEqual((d["count"], d["unknown"]), (1, 1))
        self.assertEqual(d["passes"][0]["sensors"], 1)
        self.assertIn("state", d["radio"])

    def test_hits_endpoint_returns_raw_decoder_output(self):
        now = int(__import__("time").time())
        tpms.record(self.cfg, self.db, tpms.parse(line(sid="zz", protocol=110)), now - 60, {})
        d = self.client.get("/api/vehicles/hits?from=%d&to=%d" % (now - 120, now)).get_json()
        h = d["hits"][0]
        self.assertEqual((h["vid"], h["raw"]["protocol"], h["raw"]["pressure_kPa"]), ("Toyota:zz", 110, 230.0))
        self.assertIn('"id": "zz"', h["raw_text"])
        self.assertEqual(self.client.get("/api/vehicles/hits").status_code, 400)

    def test_unknown_vid_404_and_csrf(self):
        self.assertEqual(self.client.post("/api/vehicles/known", json={"vid": "x"}, headers=H).status_code, 404)
        self.assertEqual(self.client.post("/api/vehicles/known", json={"vid": "x"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
