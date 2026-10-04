import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import sources
import watcher
from tests.helpers import make_cfg, rec, tmpdir


class Helpers(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(sources.norm_mac("AA-BB-CC-DD-EE-01"), "aa:bb:cc:dd:ee:01")
        self.assertEqual(sources.norm_mac("aabbccddee01"), "aa:bb:cc:dd:ee:01")
        self.assertIsNone(sources.norm_mac("aa:bb:cc"))
        self.assertIsNone(sources.norm_mac(None))

    def test_clean_label(self):
        self.assertEqual(sources.clean_label("  TV\n\x00 "), "TV")
        self.assertIsNone(sources.clean_label("   "))
        self.assertEqual(len(sources.clean_label("x" * 200)), 60)

    def test_is_random(self):
        self.assertEqual(watcher.is_random("IEEE802.11", "da:11:22:33:44:55", ""), 1)
        self.assertEqual(watcher.is_random("IEEE802.11", "00:11:22:33:44:55", ""), 0)
        self.assertEqual(watcher.is_random("Bluetooth", "5a:11:22:33:44:55", ""), 1)
        self.assertEqual(watcher.is_random("Bluetooth", "5a:11:22:33:44:55", "Apple"), 0)


class Ingest(unittest.TestCase):
    HOME = frozenset({"aa:bb:cc:00:00:01"})

    def setUp(self):
        self.t = tmpdir()
        self.db = watcher.db_connect(make_cfg(self.t.name))

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def state(self, mac):
        return self.db.execute("SELECT rand, known FROM devices WHERE mac=?", (mac,)).fetchone()

    def test_private_mac_on_home_ap_is_known_static(self):
        watcher.ingest(self.db, rec("da:11:22:33:44:55", "AA:BB:CC:00:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("da:11:22:33:44:55"), (0, 1))

    def test_private_mac_without_association_is_rotating(self):
        watcher.ingest(self.db, rec("da:aa:aa:aa:aa:aa"), 1000, self.HOME)
        self.assertEqual(self.state("da:aa:aa:aa:aa:aa"), (1, 0))

    def test_later_association_promotes(self):
        watcher.ingest(self.db, rec("da:aa:aa:aa:aa:aa"), 1000, self.HOME)
        watcher.ingest(self.db, rec("da:aa:aa:aa:aa:aa", "aa:bb:cc:00:00:01"), 1005, self.HOME)
        self.assertEqual(self.state("da:aa:aa:aa:aa:aa"), (0, 1))

    def test_client_on_sibling_bssid_of_my_ap_is_known(self):
        # same prefix and same last two bytes, only the middle byte differs (another SSID or band)
        watcher.ingest(self.db, rec("da:11:22:33:44:55", "AA:BB:CC:07:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("da:11:22:33:44:55"), (0, 1))

    def test_sibling_bssid_beacon_is_known(self):
        watcher.ingest(self.db, rec("aa:bb:cc:09:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("aa:bb:cc:09:00:01")[1], 1)

    def test_sibling_with_virtual_ap_first_byte(self):
        # UniFi virtual APs also change the low bits of the first byte: 74 and 7a are the same AP
        watcher.ingest(self.db, rec("da:11:22:33:44:55", "AE:BB:CC:07:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("da:11:22:33:44:55"), (0, 1))
        watcher.ingest(self.db, rec("da:11:22:33:44:56", "5E:BB:CC:07:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("da:11:22:33:44:56")[1], 0)

    def test_other_ap_with_same_prefix_stays_unknown(self):
        watcher.ingest(self.db, rec("00:10:20:30:40:50", "aa:bb:cc:07:00:02"), 1000, self.HOME)
        self.assertEqual(self.state("00:10:20:30:40:50"), (0, 0))

    def test_foreign_ap_stays_unknown(self):
        watcher.ingest(self.db, rec("00:10:20:30:40:50", "11:22:33:44:55:66"), 1000, self.HOME)
        self.assertEqual(self.state("00:10:20:30:40:50"), (0, 0))

    def test_own_ap_is_known(self):
        watcher.ingest(self.db, rec("aa:bb:cc:00:00:01"), 1000, self.HOME)
        self.assertEqual(self.state("aa:bb:cc:00:00:01"), (0, 1))

    def test_no_home_set(self):
        watcher.ingest(self.db, rec("da:99:99:99:99:99", "aa:bb:cc:00:00:01"), 1000)
        self.assertEqual(self.state("da:99:99:99:99:99"), (1, 0))

    def test_known_survives_unassociated_sighting(self):
        watcher.ingest(self.db, rec("da:11:22:33:44:55", "aa:bb:cc:00:00:01"), 1000, self.HOME)
        watcher.ingest(self.db, rec("da:11:22:33:44:55"), 1010, self.HOME)
        self.assertEqual(self.state("da:11:22:33:44:55"), (0, 1))

    def test_label_kept(self):
        watcher.ingest(self.db, rec("00:10:20:30:40:50"), 1000, self.HOME)
        self.db.execute("UPDATE devices SET label='TV' WHERE mac='00:10:20:30:40:50'")
        watcher.ingest(self.db, rec("00:10:20:30:40:50"), 1020, self.HOME)
        self.assertEqual(self.db.execute("SELECT label FROM devices").fetchone()[0], "TV")

    def test_unmarked_stays_unknown(self):
        watcher.ingest(self.db, rec("00:10:20:30:40:50", "aa:bb:cc:00:00:01"), 1000, self.HOME)
        self.db.execute("UPDATE devices SET known=0, src='unmarked'")
        watcher.ingest(self.db, rec("00:10:20:30:40:50", "aa:bb:cc:00:00:01"), 1010, self.HOME)
        self.assertEqual(self.state("00:10:20:30:40:50"), (0, 0))


class Notify(unittest.TestCase):
    def test_no_channels_configured_makes_no_requests(self):
        with tmpdir() as t:
            cfg = make_cfg(t)
            db = watcher.db_connect(cfg)
            self.assertEqual(cfg.get("ntfy", "topic"), "")
            watcher.notify(cfg, db, "T", "M")  # would raise or hang if it tried the network
            self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            db.close()

    def test_webhook_receives_json(self):
        got = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.end_headers()

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tmpdir() as t:
                cfg = make_cfg(t, webhook={"url": f"http://127.0.0.1:{srv.server_port}/"})
                db = watcher.db_connect(cfg)
                watcher.notify(cfg, db, "Title", "Body", "high")
                db.close()
        finally:
            srv.shutdown()
        self.assertEqual((got[0]["title"], got[0]["message"], got[0]["priority"]), ("Title", "Body", "high"))

    def test_failing_webhook_does_not_raise(self):
        with tmpdir() as t:
            cfg = make_cfg(t, webhook={"url": "http://127.0.0.1:9/"})
            db = watcher.db_connect(cfg)
            watcher.notify(cfg, db, "T", "M")
            db.close()


if __name__ == "__main__":
    unittest.main()


class MacCaseMigration(unittest.TestCase):
    def test_old_uppercase_rows_are_merged(self):
        tmp = tmpdir()
        self.addCleanup(tmp.cleanup)
        cfg = make_cfg(tmp.name)
        db = watcher.db_connect(cfg)
        db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,seen_count,known) "
                   "VALUES('AA:BB:CC:00:00:01','x',0,10,20,-50,3,0)")
        db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,seen_count,known,label) "
                   "VALUES('aa:bb:cc:00:00:01','',0,15,15,0,0,1,'Mine')")
        db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,seen_count,known) "
                   "VALUES('AA:BB:CC:00:00:02','x',0,10,20,-50,1,0)")
        db.execute("INSERT INTO sightings VALUES(1,'AA:BB:CC:00:00:01','x',-50,0)")
        db.execute("DELETE FROM meta WHERE k='mac_case_v1'")
        db.commit()
        watcher._lowercase_macs(db)
        rows = db.execute("SELECT mac,known,label,seen_count,first_seen FROM devices ORDER BY mac").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("aa:bb:cc:00:00:01", 1, "Mine", 3, 10),
                                                    ("aa:bb:cc:00:00:02", 0, None, 1, 10)])
        self.assertEqual(db.execute("SELECT mac FROM sightings").fetchone()[0], "aa:bb:cc:00:00:01")
        db.close()
