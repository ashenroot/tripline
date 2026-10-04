import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import watcher
from tests.helpers import make_cfg, tmpdir


def kismet(devices):
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization")
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"])).decode()
            b = json.dumps(devices).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def dev(mac, rssi, phy="IEEE802.11", manuf="Acme"):
    return {"kismet.device.base.macaddr": mac, "kismet.device.base.phyname": phy,
            "kismet.device.base.manuf": manuf, "kismet.device.base.name": "", "rssi": rssi}


class RunOnce(unittest.TestCase):
    def run_loop(self, devices, mode, **detect):
        srv, seen = kismet(devices)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.t = tmpdir()
        self.addCleanup(self.t.cleanup)
        d = {"dwell_seconds": "0"}
        d.update(detect)
        cfg = make_cfg(self.t.name, kismet={"url": f"http://127.0.0.1:{srv.server_port}"}, detect=d)
        db = watcher.db_connect(cfg)
        self.addCleanup(db.close)
        watcher.meta_set(db, "mode", mode)
        watcher.run(cfg, db, once=True)
        return db, seen

    def alerts(self, db):
        return [r[0] for r in db.execute("SELECT title FROM alerts")]

    def test_request_shape(self):
        db, seen = self.run_loop([], "home")
        self.assertIn("/devices/last-time/", seen["path"])
        self.assertTrue(seen["auth"].startswith("Basic "))
        self.assertIn("kismet.device.base.macaddr", seen["body"])

    def test_unknown_strong_static_device_alerts_in_home_mode(self):
        db, _ = self.run_loop([dev("00:10:20:30:40:50", -60)], "home")
        self.assertEqual(self.alerts(db), ["Unknown device near house"])

    def test_weak_signal_does_not_alert(self):
        db, _ = self.run_loop([dev("00:10:20:30:40:50", -92)], "home")
        self.assertEqual(self.alerts(db), [])

    def test_learning_mode_never_alerts(self):
        db, _ = self.run_loop([dev("00:10:20:30:40:50", -50)], "learning")
        self.assertEqual(self.alerts(db), [])

    def test_known_device_does_not_alert(self):
        srv, _ = kismet([dev("00:10:20:30:40:50", -50)])
        self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)
        t = tmpdir(); self.addCleanup(t.cleanup)
        cfg = make_cfg(t.name, kismet={"url": f"http://127.0.0.1:{srv.server_port}"}, detect={"dwell_seconds": "0"})
        db = watcher.db_connect(cfg); self.addCleanup(db.close)
        db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known) "
                   "VALUES('00:10:20:30:40:50','IEEE802.11',0,1,1,-50,1)")
        db.commit()
        watcher.meta_set(db, "mode", "home")
        watcher.run(cfg, db, once=True)
        self.assertEqual(self.alerts(db), [])

    def test_guest_window_suppresses_alerts(self):
        srv, _ = kismet([dev("00:10:20:30:40:50", -50)])
        self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)
        t = tmpdir(); self.addCleanup(t.cleanup)
        cfg = make_cfg(t.name, kismet={"url": f"http://127.0.0.1:{srv.server_port}"}, detect={"dwell_seconds": "0"})
        db = watcher.db_connect(cfg); self.addCleanup(db.close)
        watcher.meta_set(db, "mode", "home")
        watcher.meta_set(db, "quiet_until", 9999999999)
        watcher.run(cfg, db, once=True)
        self.assertEqual(self.alerts(db), [])

    def test_rotating_devices_alert_by_count_in_away_mode(self):
        devs = [dev(f"da:00:00:00:00:{i:02x}", -60) for i in range(3)]
        db, _ = self.run_loop(devs, "away", burst_confirm_seconds="0", random_margin_away="0")
        self.assertEqual(self.alerts(db), ["Unusual device count near house"])

    def test_unreachable_kismet_returns_in_once_mode(self):
        t = tmpdir(); self.addCleanup(t.cleanup)
        cfg = make_cfg(t.name, kismet={"url": "http://127.0.0.1:9"})
        db = watcher.db_connect(cfg); self.addCleanup(db.close)
        watcher.run(cfg, db, once=True)


if __name__ == "__main__":
    unittest.main()
