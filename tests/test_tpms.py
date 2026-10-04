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

    def test_default_single_frequency(self):
        self.assertEqual(tpms.command(self.cfgv()), "rtl_433 -d 0 -f 315M -F json -M level -M time:unix")

    def test_multiple_frequencies_hop(self):
        c = tpms.command(self.cfgv(frequencies="315M, 433.92M"))
        self.assertIn("-f 315M -f 433.92M -H 30", c)

    def test_custom_command_gets_substitutions(self):
        c = tpms.command(self.cfgv(command="myrtl -d {device} {freqs}", device="1"))
        self.assertEqual(c, "myrtl -d 1 -f 315M")

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

    def test_unknown_vid_404_and_csrf(self):
        self.assertEqual(self.client.post("/api/vehicles/known", json={"vid": "x"}, headers=H).status_code, 404)
        self.assertEqual(self.client.post("/api/vehicles/known", json={"vid": "x"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
