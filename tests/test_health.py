import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import watcher
import web
from tests.helpers import make_cfg, tmpdir

H = {"X-Requested-With": "tripline"}
NOW = 100000


def hook_server(status=200):
    got = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(status); self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, got


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        self.db = watcher.db_connect(self.cfg)

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def health(self, cfg=None):
        return {c["id"]: c for c in watcher.component_health(cfg or self.cfg, self.db, NOW)}

    def good_kismet(self, sources=None):
        watcher.meta_set(self.db, "kismet_ok", NOW - 3)
        watcher.meta_set(self.db, "kismet_sources", json.dumps(sources if sources is not None else [
            {"name": "wifi", "iface": "wlan1", "running": True, "kind": "wifi"},
            {"name": "bt", "iface": "hci0", "running": True, "kind": "bt"}]))

    def device(self, mac, phy, age=10):
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known) VALUES(?,?,0,1,?,-50,0)",
                        (mac, phy, NOW - age))
        self.db.commit()


class KismetHealth(Base):
    def test_not_polled_yet(self):
        self.assertEqual(self.health()["kismet"]["state"], "warn")

    def test_ok_failing_and_stale(self):
        self.good_kismet()
        self.assertEqual(self.health()["kismet"]["state"], "ok")
        watcher.meta_set(self.db, "kismet_fail", "%d|connection refused" % (NOW - 120))
        h = self.health()["kismet"]
        self.assertEqual(h["state"], "bad")
        self.assertIn("connection refused", h["detail"])
        self.db.execute("DELETE FROM meta WHERE k='kismet_fail'")
        watcher.meta_set(self.db, "kismet_ok", NOW - 600)
        self.assertEqual(self.health()["kismet"]["state"], "bad")

    def test_record_poll_tracks_failure_then_recovery(self):
        watcher.record_poll(self.cfg, self.db, NOW, (NOW - 5, "boom"))
        self.assertEqual(self.health()["kismet"]["state"], "bad")
        watcher.record_poll(self.cfg, self.db, NOW, None)
        self.db.commit()
        self.assertIsNone(watcher.meta_get(self.db, "kismet_fail"))
        self.assertEqual(self.health()["kismet"]["state"], "ok")

    def test_radios_are_unknown_while_kismet_is_down(self):
        self.good_kismet()
        watcher.meta_set(self.db, "kismet_fail", "%d|x" % NOW)
        self.assertEqual((self.health()["wifi"]["state"], self.health()["bt"]["state"]), ("warn", "warn"))


class RadioHealth(Base):
    def test_source_kind(self):
        self.assertEqual(watcher.source_kind({"iface": "hci0", "name": "bt"}), "bt")
        self.assertEqual(watcher.source_kind({"iface": "wlan1", "name": "wifi"}), "wifi")

    def test_wifi_ok_and_bluetooth_without_signal_warns(self):
        self.good_kismet()
        self.device("aa:00:00:00:00:01", "IEEE802.11")
        self.device("bb:00:00:00:00:01", "Bluetooth")
        h = self.health()
        self.assertEqual(h["wifi"]["state"], "ok")
        self.assertEqual(h["bt"]["state"], "warn")
        self.assertIn("signal", h["bt"]["detail"])
        self.db.execute("INSERT INTO sightings VALUES(?,?,?,?,?)", (NOW - 5, "bb:00:00:00:00:01", "Bluetooth", -70, 0))
        self.assertEqual(self.health()["bt"]["state"], "ok")

    def test_source_down_missing_and_quiet(self):
        self.good_kismet([{"name": "wifi", "iface": "wlan1", "running": False, "kind": "wifi"}])
        h = self.health()
        self.assertEqual(h["wifi"]["state"], "bad")
        self.assertIn("wlan1", h["wifi"]["detail"])
        self.assertEqual(h["bt"]["state"], "off")
        self.good_kismet()
        self.assertEqual(self.health()["wifi"]["state"], "warn")  # running, nothing heard

    def test_no_wifi_source_is_red(self):
        self.good_kismet([{"name": "bt", "iface": "hci0", "running": True, "kind": "bt"}])
        self.assertEqual(self.health()["wifi"]["state"], "bad")

    def test_old_devices_do_not_count(self):
        self.good_kismet()
        self.device("aa:00:00:00:00:01", "IEEE802.11", age=900)
        self.assertEqual(self.health()["wifi"]["state"], "warn")


class SdrAndAlerts(Base):
    def test_sdr_hidden_until_enabled_and_maps_states(self):
        self.assertNotIn("sdr", self.health())
        cfg = make_cfg(self.t.name, vehicles={"enabled": "true"})
        self.assertEqual(self.health(cfg)["sdr"]["state"], "bad")  # never started
        for k, v in (("sdr_started", NOW - 60), ("sdr_beat", NOW)):
            watcher.meta_set(self.db, k, v)
        self.assertEqual(self.health(cfg)["sdr"]["state"], "warn")
        watcher.meta_set(self.db, "sdr_last", NOW - 5)
        self.assertEqual(self.health(cfg)["sdr"]["state"], "ok")

    def test_alerts_off_never_ok_and_failed(self):
        self.assertEqual(self.health()["alerts"]["state"], "off")
        cfg = make_cfg(self.t.name, webhook={"url": "http://127.0.0.1:9/"})
        self.assertEqual(self.health(cfg)["alerts"]["state"], "warn")
        watcher.meta_set(self.db, "notify_webhook", "%d|ok|" % (NOW - 30))
        self.assertEqual(self.health(cfg)["alerts"]["state"], "ok")
        watcher.meta_set(self.db, "notify_webhook", "%d|fail|timed out" % (NOW - 5))
        h = self.health(cfg)["alerts"]
        self.assertEqual(h["state"], "bad")
        self.assertIn("timed out", h["detail"])

    def test_delivery_results_are_recorded(self):
        srv, got = hook_server()
        try:
            cfg = make_cfg(self.t.name, webhook={"url": "http://127.0.0.1:%d/" % srv.server_port})
            watcher.notify(cfg, self.db, "T", "M")
            self.assertIn("|ok|", watcher.meta_get(self.db, "notify_webhook"))
        finally:
            srv.shutdown()
        cfg = make_cfg(self.t.name, webhook={"url": "http://127.0.0.1:9/"})
        watcher.notify(cfg, self.db, "T", "M")
        self.assertIn("|fail|", watcher.meta_get(self.db, "notify_webhook"))

    def test_send_test_records_no_alert(self):
        srv, got = hook_server()
        try:
            cfg = make_cfg(self.t.name, webhook={"url": "http://127.0.0.1:%d/" % srv.server_port})
            res = watcher.send_test(cfg, self.db)
        finally:
            srv.shutdown()
        self.assertEqual([(r[0], r[1]) for r in res], [("webhook", True)])
        self.assertEqual(got[0]["title"], "Tripline test")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)


class Api(Base):
    def setUp(self):
        super().setUp()
        web._cfg = self.cfg
        self.client = web.app.test_client()

    def tearDown(self):
        web._cfg = None
        super().tearDown()

    def test_state_carries_health(self):
        ids = [c["id"] for c in self.client.get("/api/state").get_json()["health"]]
        self.assertEqual(ids, ["kismet", "wifi", "bt", "alerts"])

    def test_test_alert_with_nothing_configured(self):
        d = self.client.post("/api/test-alert", json={}, headers=H).get_json()
        self.assertFalse(d["ok"])
        self.assertIn("No ntfy", d["error"])

    def test_test_alert_delivers_and_needs_csrf(self):
        srv, got = hook_server()
        try:
            web._cfg = make_cfg(self.t.name, webhook={"url": "http://127.0.0.1:%d/" % srv.server_port})
            self.assertEqual(self.client.post("/api/test-alert", json={}).status_code, 403)
            d = self.client.post("/api/test-alert", json={}, headers=H).get_json()
        finally:
            srv.shutdown()
        self.assertEqual((d["ok"], d["results"][0]["channel"]), (True, "webhook"))


if __name__ == "__main__":
    unittest.main()
