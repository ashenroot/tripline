import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import known_sync
import sources
import watcher
from sources import unifi
from tests.helpers import make_cfg, tmpdir

MAC1, MAC2, MAC3 = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"


class FileSource(unittest.TestCase):
    def test_parse(self):
        with tmpdir() as t:
            p = os.path.join(t, "k.txt")
            with open(p, "w") as fh:
                fh.write("# c\n\naa-bb-cc-dd-ee-01 Living room TV # tail\nAABBCCDDEE02\nbogus line\n")
            devs = sources.load("file", {"path": p}).devices()
        self.assertEqual(devs, [{"mac": MAC1, "label": "Living room TV"}, {"mac": MAC2, "label": None}])

    def test_missing_file_raises(self):
        with self.assertRaises(OSError):
            sources.load("file", {"path": "/nonexistent/x"}).devices()


class Rules(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.db = watcher.db_connect(make_cfg(self.t.name))

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def row(self, mac):
        return self.db.execute("SELECT known, src, label FROM devices WHERE mac=?", (mac,)).fetchone()

    def test_adds_new_device_as_known_with_source(self):
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": "TV"}])
        self.assertEqual(self.row(MAC1), (1, "s", "TV"))

    def test_promotes_existing_unknown_and_keeps_user_label(self):
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,label) "
                        "VALUES(?,?,0,1,1,-50,0,'Mine')", (MAC1, "IEEE802.11"))
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": "Theirs"}])
        self.assertEqual(self.row(MAC1), (1, "s", "Mine"))

    def test_user_marked_device_is_not_claimed_or_revoked(self):
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,src) "
                        "VALUES(?,?,0,1,1,-50,1,NULL)", (MAC1, "IEEE802.11"))
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": "x"}])
        known_sync.apply(self.db, "s", [{"mac": MAC2, "label": "y"}])
        self.assertEqual(self.row(MAC1)[:2], (1, None))

    def test_unmarked_is_respected(self):
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": "TV"}])
        self.db.execute("UPDATE devices SET known=0, label=NULL, src='unmarked' WHERE mac=?", (MAC1,))
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": "TV"}])
        self.assertEqual(self.row(MAC1), (0, "unmarked", None))

    def test_revokes_devices_the_source_dropped(self):
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": None}, {"mac": MAC2, "label": None}])
        _, revoked, _ = known_sync.apply(self.db, "s", [{"mac": MAC2, "label": None}])
        self.assertEqual(revoked, 1)
        self.assertEqual(self.row(MAC1)[:2], (0, None))
        self.assertEqual(self.row(MAC2)[0], 1)

    def test_empty_answer_does_not_purge(self):
        known_sync.apply(self.db, "s", [{"mac": MAC1, "label": None}])
        known_sync.apply(self.db, "s", [])
        self.assertEqual(self.row(MAC1)[0], 1)

    def test_sources_do_not_revoke_each_other(self):
        known_sync.apply(self.db, "a", [{"mac": MAC1, "label": None}])
        known_sync.apply(self.db, "b", [{"mac": MAC2, "label": None}])
        known_sync.apply(self.db, "b", [{"mac": MAC3, "label": None}])
        self.assertEqual(self.row(MAC1)[0], 1)

    def test_failing_source_changes_nothing(self):
        cfg = make_cfg(self.t.name, sync={"sources": "file"}, **{"source.file": {"path": "/nonexistent"}})
        known_sync.apply(self.db, "file", [{"mac": MAC1, "label": None}])
        known_sync.sync_once(cfg, self.db)
        self.assertEqual(self.row(MAC1)[0], 1)


class UnifiMock(unittest.TestCase):
    CLIENTS = [{"mac": "AA:BB:CC:DD:EE:01", "name": "Phone"},
               {"mac": "aa:bb:cc:dd:ee:02", "hostname": "printer"},
               {"mac": "aa:bb:cc:dd:ee:03"}, {"mac": "junk"}]

    def serve(self, legacy=False):
        seen = {"auth": [], "paths": []}
        clients = self.CLIENTS

        class H(BaseHTTPRequestHandler):
            def reply(self, obj, code=200, cookie=False):
                b = json.dumps(obj).encode()
                self.send_response(code)
                if cookie:
                    self.send_header("Set-Cookie", "csrf_token=abc; Path=/")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path == ("/api/login" if legacy else "/api/auth/login"):
                    self.reply({}, cookie=True)
                else:
                    self.reply({}, 404)

            def do_GET(self):
                seen["paths"].append(self.path)
                seen["auth"].append(self.headers.get("X-API-KEY"))
                pre = "" if legacy else "/proxy/network"
                if self.path == f"{pre}/api/s/default/rest/user":
                    self.reply({"data": clients})
                else:
                    self.reply({}, 404)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}", seen

    def test_login_unifi_os(self):
        url, seen = self.serve()
        devs = unifi.Source({"url": url, "username": "u", "password": "p"}).devices()
        self.assertEqual([d["mac"] for d in devs], [MAC1, MAC2, MAC3])
        self.assertEqual([d["label"] for d in devs], ["Phone", "printer", None])

    def test_login_legacy_controller(self):
        url, seen = self.serve(legacy=True)
        devs = unifi.Source({"url": url, "username": "u", "password": "p"}).devices()
        self.assertEqual(len(devs), 3)

    def test_api_key_header_sent(self):
        url, seen = self.serve()
        unifi.Source({"url": url, "api_key": "KEY"}).devices()
        self.assertEqual(seen["auth"], ["KEY"])

    def test_named_only(self):
        url, _ = self.serve()
        devs = unifi.Source({"url": url, "api_key": "k", "include": "named"}).devices()
        self.assertEqual([d["mac"] for d in devs], [MAC1])

    def with_ages(self, ages, **cfg):
        now = time.time()
        self.CLIENTS = [{"mac": m, "name": m[-2:], **({} if a is None else {"last_seen": now - a * 86400})}
                        for m, a in zip((MAC1, MAC2, MAC3), ages)]
        url, _ = self.serve()
        s = unifi.Source({"url": url, "api_key": "k", **cfg})
        return s, [d["mac"] for d in s.devices()]

    def test_idle_clients_are_skipped_by_default(self):
        s, macs = self.with_ages([2, 45, 400])
        self.assertEqual(macs, [MAC1])
        self.assertEqual(s.skipped_idle, 2)

    def test_max_age_is_configurable_and_zero_keeps_all(self):
        self.assertEqual(self.with_ages([2, 45, 400], max_age_days="60")[1], [MAC1, MAC2])
        self.assertEqual(self.with_ages([2, 45, 400], max_age_days="0")[1], [MAC1, MAC2, MAC3])

    def test_client_without_last_seen_is_kept(self):
        self.assertEqual(self.with_ages([None, 45, None])[1], [MAC1, MAC3])

    def test_bad_max_age_is_a_clear_error(self):
        with self.assertRaises(RuntimeError):
            unifi.Source({"url": "http://x", "api_key": "k", "max_age_days": "soon"})

    def test_idle_client_is_revoked_on_next_sync(self):
        s, macs = self.with_ages([2, 2, 2])
        t = tmpdir()
        self.addCleanup(t.cleanup)
        db = watcher.db_connect(make_cfg(t.name))
        self.addCleanup(db.close)
        known_sync.apply(db, "unifi", [{"mac": m, "label": None} for m in macs])
        s2, macs2 = self.with_ages([2, 45, 2])
        _, revoked, _ = known_sync.apply(db, "unifi", [{"mac": m, "label": None} for m in macs2])
        self.assertEqual(revoked, 1)

    def test_bad_login_raises(self):
        url, _ = self.serve()
        s = unifi.Source({"url": url + "/nope", "username": "u", "password": "p"})
        with self.assertRaises(Exception):
            s.devices()


if __name__ == "__main__":
    unittest.main()
