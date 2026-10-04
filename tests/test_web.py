import os
import re
import shutil
import subprocess
import unittest

import web
import watcher
from tests.helpers import ROOT, make_cfg, tmpdir

H = {"X-Requested-With": "tripline"}


class WebBase(unittest.TestCase):
    password = ""

    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name, web={"password": self.password})
        web._cfg = self.cfg
        self.client = web.app.test_client()
        self.db = watcher.db_connect(self.cfg)

    def tearDown(self):
        web._cfg = None
        self.db.close()
        self.t.cleanup()

    def add(self, mac, known=0, rand=0, label=None, src=None):
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,label,src) "
                        "VALUES(?,?,?,1,1,-50,?,?,?)", (mac, "IEEE802.11", rand, known, label, src))
        self.db.commit()

    def row(self, mac):
        return self.db.execute("SELECT known, label, src FROM devices WHERE mac=?", (mac,)).fetchone()


class Api(WebBase):
    def test_read_endpoints_ok(self):
        for p in ("/", "/api/state", "/api/radar", "/api/signals", "/api/activity", "/api/feed", "/api/devices"):
            self.assertEqual(self.client.get(p).status_code, 200, p)

    def test_devices_radio_filter_and_sort(self):
        self.add("00:10:20:30:40:50")
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,name) "
                        "VALUES('11:22:33:44:55:66','Bluetooth',0,1,5,-70,0,'Watch')")
        self.db.commit()
        get = lambda q: [d["mac"] for d in self.client.get("/api/devices?filter=all&" + q).get_json()["devices"]]
        self.assertEqual(get("radio=bt"), ["11:22:33:44:55:66"])
        self.assertEqual(get("radio=wifi"), ["00:10:20:30:40:50"])
        self.assertEqual(get("sort=last_seen&dir=asc")[0], "00:10:20:30:40:50")
        self.assertEqual(get("sort=last_seen&dir=desc")[0], "11:22:33:44:55:66")
        self.assertEqual(self.client.get("/api/devices?sort=1;DROP").status_code, 200)

    def test_uppercase_kismet_mac_is_one_device_and_mark_known_sticks(self):
        d = {"kismet.device.base.macaddr": "00:10:20:30:40:5A", "kismet.device.base.phyname": "IEEE802.11",
             "kismet.device.base.manuf": "Acme", "kismet.device.base.name": "", "rssi": -50,
             "bssid": "74:83:C2:24:FE:57"}
        watcher.ingest(self.db, d, 1000)
        self.db.commit()
        self.client.post("/api/known", json={"mac": "00:10:20:30:40:5a"}, headers=H)
        watcher.ingest(self.db, d, 1100)
        self.db.commit()
        rows = self.db.execute("SELECT mac, known, bssid FROM devices").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("00:10:20:30:40:5a", 1, "74:83:c2:24:fe:57")])

    def test_device_detail(self):
        self.add("00:10:20:30:40:50", label="Cam")
        watcher.ingest(self.db, {"kismet.device.base.macaddr": "00:10:20:30:40:50",
                                 "kismet.device.base.phyname": "IEEE802.11", "rssi": -61,
                                 "probes": {"1": {"dot11.probedssid.ssid": "Cabin"}}}, int(__import__("time").time()))
        self.db.commit()
        r = self.client.get("/api/device/00:10:20:30:40:50").get_json()
        self.assertEqual(r["label"], "Cam")
        self.assertEqual([p["ssid"] for p in r["probes"]], ["Cabin"])
        self.assertEqual(len(r["hourly"]), 24)
        self.assertEqual(self.client.get("/api/device/00:00:00:00:00:99").status_code, 404)
        self.assertEqual(self.client.get("/api/device/nope").status_code, 400)

    def test_tile_filters_and_alert_list(self):
        now = int(__import__("time").time())
        self.add("00:10:20:30:40:50")
        self.db.execute("INSERT INTO sightings VALUES(?,?,?,?,?)", (now - 5, "00:10:20:30:40:50", "IEEE802.11", -60, 0))
        self.db.execute("INSERT INTO alerts VALUES(?,?,?,?)", (now - 5, "Unknown device", "x", "default"))
        self.db.commit()
        got = self.client.get("/api/devices?filter=unknown_now").get_json()["devices"]
        self.assertEqual([d["mac"] for d in got], ["00:10:20:30:40:50"])
        self.assertEqual(self.client.get("/api/devices?filter=rotating_now").get_json()["devices"], [])
        self.assertEqual(len(self.client.get("/api/alerts").get_json()["alerts"]), 1)

    def test_security_headers(self):
        r = self.client.get("/")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_post_requires_custom_header(self):
        self.assertEqual(self.client.post("/api/mode", json={"mode": "home"}).status_code, 403)
        self.assertEqual(self.client.post("/api/mode", json={"mode": "home"}, headers=H).status_code, 200)

    def test_mode_validation_and_persist(self):
        self.assertEqual(self.client.post("/api/mode", json={"mode": "x"}, headers=H).status_code, 400)
        self.client.post("/api/mode", json={"mode": "away"}, headers=H)
        self.assertEqual(watcher.meta_get(self.db, "mode"), "away")

    def test_guest_window(self):
        r = self.client.post("/api/guest", json={"hours": 2}, headers=H).get_json()
        self.assertGreater(float(watcher.meta_get(self.db, "quiet_until")), r["quiet_until"] - 1)
        self.client.post("/api/guest", json={"hours": "off"}, headers=H)
        self.assertEqual(float(watcher.meta_get(self.db, "quiet_until")), 0)
        self.assertEqual(self.client.post("/api/guest", json={"hours": "abc"}, headers=H).status_code, 400)

    def test_known_add_delete_roundtrip(self):
        mac = "aa:bb:cc:dd:ee:01"
        self.assertEqual(self.client.post("/api/known", json={"mac": "bad"}, headers=H).status_code, 400)
        self.client.post("/api/known", json={"mac": mac.upper(), "label": "TV"}, headers=H)
        self.assertEqual(self.row(mac), (1, "TV", None))
        self.client.post("/api/known/delete", json={"mac": mac}, headers=H)
        self.assertEqual(self.row(mac), (0, None, "unmarked"))

    def test_bulk_marks_only_static(self):
        self.add("aa:bb:cc:dd:ee:01"); self.add("da:bb:cc:dd:ee:02", rand=1)
        r = self.client.post("/api/known/bulk", json={"macs": ["aa:bb:cc:dd:ee:01", "da:bb:cc:dd:ee:02", "zz"]},
                             headers=H).get_json()
        self.assertEqual(r["count"], 2)
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01")[0], 1)
        self.assertEqual(self.row("da:bb:cc:dd:ee:02")[0], 0)

    def test_user_readd_clears_unmarked(self):
        self.add("aa:bb:cc:dd:ee:01", src="unmarked")
        self.client.post("/api/known", json={"mac": "aa:bb:cc:dd:ee:01"}, headers=H)
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01"), (1, None, None))


class Networks(WebBase):
    def test_add_marks_beacon_known_and_lists(self):
        r = self.client.post("/api/networks", json={"bssid": "AA-BB-CC-DD-EE-01", "label": "Router 5G"}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01"), (1, "Router 5G", None))
        n = self.client.get("/api/networks").get_json()["networks"]
        self.assertEqual([(x["bssid"], x["label"]) for x in n], [("aa:bb:cc:dd:ee:01", "Router 5G")])

    def test_bad_bssid_rejected(self):
        self.assertEqual(self.client.post("/api/networks", json={"bssid": "nope"}, headers=H).status_code, 400)

    def test_existing_unknown_device_gets_known(self):
        self.add("aa:bb:cc:dd:ee:01", src="unmarked")
        self.client.post("/api/networks", json={"bssid": "aa:bb:cc:dd:ee:01"}, headers=H)
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01")[0::2], (1, None))

    def test_remove_undoes_the_network_and_unmarks_the_device(self):
        self.client.post("/api/networks", json={"bssid": "aa:bb:cc:dd:ee:01"}, headers=H)
        d = self.client.get("/api/devices?filter=all").get_json()["devices"][0]
        self.assertEqual(d["is_network"], 1)
        self.client.post("/api/networks/delete", json={"bssid": "aa:bb:cc:dd:ee:01"}, headers=H)
        self.assertEqual(self.client.get("/api/networks").get_json()["networks"], [])
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01")[0], 0)
        d = self.client.get("/api/devices?filter=all").get_json()["devices"][0]
        self.assertEqual(d["is_network"], 0)
        # a later sighting must not quietly make it known again
        from tests.helpers import rec
        watcher.ingest(self.db, rec("aa:bb:cc:dd:ee:01"), 5000, watcher.home_set(self.cfg, self.db))
        self.assertEqual(self.row("aa:bb:cc:dd:ee:01")[0], 0)

    def test_watcher_uses_ui_added_network_for_clients(self):
        self.client.post("/api/networks", json={"bssid": "aa:bb:cc:00:00:01"}, headers=H)
        home = watcher.home_set(self.cfg, self.db)
        self.assertIn("aa:bb:cc:00:00:01", home)
        from tests.helpers import rec
        watcher.ingest(self.db, rec("da:11:22:33:44:55", "AA:BB:CC:00:00:01"), 1000, home)
        self.assertEqual(self.row("da:11:22:33:44:55")[0], 1)


class Auth(WebBase):
    password = "s3cret"

    def test_requires_password(self):
        self.assertEqual(self.client.get("/api/state").status_code, 401)
        self.assertEqual(self.client.get("/api/state", headers={"Authorization": "Basic YWRtaW46d3Jvbmc="}).status_code, 401)
        self.assertEqual(self.client.get("/api/state", headers={"Authorization": "Basic YWRtaW46czNjcmV0"}).status_code, 200)


class Dashboard(unittest.TestCase):
    def setUp(self):
        self.html = open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8").read()

    def test_no_duplicate_ids(self):
        ids = re.findall(r'\sid="([^"]+)"', self.html)
        dups = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(dups, [])

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_script_parses(self):
        js = "\n".join(re.findall(r"<script>(.*?)</script>", self.html, re.S))
        with tmpdir() as d:
            p = os.path.join(d, "dash.js")
            with open(p, "w") as fh:
                fh.write(js)
            r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_no_innerhtml_with_device_data(self):
        # Device names/vendors are attacker-controlled: render with textContent only.
        self.assertIsNone(re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML", self.html))


if __name__ == "__main__":
    unittest.main()
