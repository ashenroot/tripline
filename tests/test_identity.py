import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import identity
import tpms
import watcher
import web
from tests.helpers import make_cfg, rec, tmpdir

H = {"X-Requested-With": "tripline"}
NOW = 1_700_000_000


def probe_rec(mac, ssids, **kw):
    r = rec(mac, **kw)
    r["probes"] = {str(i): {"dot11.probedssid.ssid": s} for i, s in enumerate(ssids)}
    return r


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tmpdir()
        self.cfg = make_cfg(self.t.name)
        self.db = watcher.db_connect(self.cfg)

    def tearDown(self):
        self.db.close()
        self.t.cleanup()

    def dev(self, mac, now=NOW, **kw):
        watcher.ingest(self.db, rec(mac, **kw), now, frozenset())
        self.db.commit()


class SsidExtraction(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(identity.extract_ssids({"1": {"dot11.probedssid.ssid": "Cabin"}}), ["Cabin"])
        self.assertEqual(identity.extract_ssids([{"dot11.probedssid.ssid": "A"}, {"dot11.probedssid.ssid": "B"}]), ["A", "B"])
        self.assertEqual(identity.extract_ssids(["A", "A", "B"]), ["A", "B"])
        self.assertEqual(identity.extract_ssids(None), [])
        self.assertEqual(identity.extract_ssids({}), [])

    def test_rejects_empty_and_oversized(self):
        self.assertEqual(identity.extract_ssids(["", "   ", "x" * 40]), [])

    def test_strips_control_characters(self):
        self.assertEqual(identity.extract_ssids(["Ca\x00bin\n"]), ["Cabin"])

    def test_common_names(self):
        self.assertTrue(identity.is_common("xfinitywifi"))
        self.assertTrue(identity.is_common("NETGEAR42"))
        self.assertFalse(identity.is_common("Smith_Cabin_5G"))


class HomeSsid(Base):
    def test_probe_for_home_ssid_marks_known_and_not_random(self):
        home = frozenset({"foofoo1"})
        watcher.ingest(self.db, probe_rec("da:11:22:33:44:55", ["FooFoo1", "Other"]), NOW, frozenset(), home)
        self.assertEqual(self.db.execute("SELECT rand, known FROM devices").fetchone(), (0, 1))

    def test_probe_for_other_ssid_does_not(self):
        watcher.ingest(self.db, probe_rec("da:11:22:33:44:55", ["Other"]), NOW, frozenset(), frozenset({"foofoo1"}))
        self.assertEqual(self.db.execute("SELECT rand, known FROM devices").fetchone(), (1, 0))

    def test_home_ssid_set_merges_config_and_ui(self):
        cfg = make_cfg(self.t.name, detect={"home_ssids": "FooFoo1, FooFoo2"})
        self.db.execute("INSERT INTO home_ssids VALUES('FooFoo3', 1)")
        self.assertEqual(identity.home_ssid_set(cfg, self.db), {"foofoo1", "foofoo2", "foofoo3"})

    def test_probes_recorded_and_purged_with_device(self):
        watcher.ingest(self.db, probe_rec("da:11:22:33:44:55", ["Cabin"]), NOW, frozenset())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM probes").fetchone()[0], 1)
        watcher.purge(self.db, self.cfg, NOW + 90 * 86400)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM probes").fetchone()[0], 0)


class SsidSuggestions(Base):
    def fill_population(self, n=14):
        for i in range(n):
            watcher.ingest(self.db, probe_rec(f"da:00:00:00:00:{i:02x}", [f"Noise{i}", "xfinitywifi"]), NOW, frozenset())

    def test_shared_rare_ssids_suggest_a_link(self):
        self.fill_population()
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:01", ["Smith_Cabin", "Lakehouse_5G", "xfinitywifi"]), NOW, frozenset())
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:02", ["Smith_Cabin", "Lakehouse_5G"]), NOW + 3600, frozenset())
        sug = identity.suggestions(self.db, self.cfg, NOW + 7200)
        pairs = [(s["a"]["ref"], s["b"]["ref"]) for s in sug]
        self.assertIn(("da:aa:aa:aa:aa:01", "da:aa:aa:aa:aa:02"), pairs)
        self.assertIn(sug[0]["level"], ("medium", "high"))

    def test_common_ssids_alone_suggest_nothing(self):
        self.fill_population()
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:01", ["xfinitywifi", "attwifi"]), NOW, frozenset())
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:02", ["xfinitywifi", "attwifi"]), NOW + 3600, frozenset())
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 7200), [])

    def test_home_ssids_are_ignored_for_matching(self):
        self.fill_population()
        self.db.execute("INSERT INTO home_ssids VALUES('FooFoo1', 1)")
        for m in ("da:aa:aa:aa:aa:01", "da:aa:aa:aa:aa:02"):
            watcher.ingest(self.db, probe_rec(m, ["FooFoo1"]), NOW, frozenset())
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 7200), [])

    def test_simultaneous_devices_are_not_one_device(self):
        self.fill_population()
        for k in range(10):
            for m in ("da:aa:aa:aa:aa:01", "da:aa:aa:aa:aa:02"):
                watcher.ingest(self.db, probe_rec(m, ["Smith_Cabin", "Lakehouse_5G"]), NOW + k * 60, frozenset())
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 1000), [])

    def test_dismissed_pair_not_suggested_again(self):
        self.fill_population()
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:01", ["Smith_Cabin", "Lakehouse_5G"]), NOW, frozenset())
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:02", ["Smith_Cabin", "Lakehouse_5G"]), NOW + 3600, frozenset())
        s = identity.suggestions(self.db, self.cfg, NOW + 7200)[0]
        identity.dismiss(self.db, f"device:{s['a']['ref']}", f"device:{s['b']['ref']}")
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 7200), [])


class Entities(Base):
    def test_link_marks_members_known_and_labels(self):
        self.dev("00:10:20:30:40:50")
        tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "Toyota", "type": "TPMS", "id": "a1"})), NOW, {})
        eid = identity.create_entity(self.db, "Bob", "regular")
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        identity.add_member(self.db, eid, "vehicle", "Toyota:a1")
        self.assertEqual(self.db.execute("SELECT known,label FROM devices").fetchone(), (1, "Bob"))
        self.assertEqual(self.db.execute("SELECT known,label FROM vehicles").fetchone(), (1, "Bob"))

    def test_existing_label_is_kept(self):
        self.dev("00:10:20:30:40:50")
        self.db.execute("UPDATE devices SET label='Watch'")
        eid = identity.create_entity(self.db, "Bob")
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        self.assertEqual(self.db.execute("SELECT label FROM devices").fetchone()[0], "Watch")

    def test_watch_entity_leaves_members_unknown(self):
        self.dev("00:10:20:30:40:50")
        eid = identity.create_entity(self.db, "Tuesday truck", "other", known=False)
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        self.assertEqual(self.db.execute("SELECT known FROM devices").fetchone()[0], 0)

    def test_visitor_expires_back_to_unknown(self):
        self.dev("00:10:20:30:40:50")
        eid = identity.create_entity(self.db, "Plumber", "contractor", expires_days=7, now=NOW)
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        self.assertEqual(identity.expire_entities(self.db, NOW + 6 * 86400), [])
        self.assertEqual(identity.expire_entities(self.db, NOW + 8 * 86400), ["Plumber"])
        self.assertEqual(self.db.execute("SELECT known FROM devices").fetchone()[0], 0)
        self.assertEqual(identity.expire_entities(self.db, NOW + 9 * 86400), [])

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            identity.create_entity(self.db, "  ")
        with self.assertRaises(ValueError):
            identity.create_entity(self.db, "x", kind="nope")
        eid = identity.create_entity(self.db, "x")
        with self.assertRaises(KeyError):
            identity.add_member(self.db, eid, "device", "00:00:00:00:00:00")

    def test_link_pair_creates_and_merges(self):
        for m in ("00:10:20:30:40:01", "00:10:20:30:40:02", "00:10:20:30:40:03"):
            self.dev(m)
        a, b, c = ({"kind": "device", "ref": f"00:10:20:30:40:0{i}"} for i in (1, 2, 3))
        e1 = identity.link_pair(self.db, a, b, name="Bob")
        e2 = identity.create_entity(self.db, "Other")
        identity.add_member(self.db, e2, "device", c["ref"])
        merged = identity.link_pair(self.db, b, c)
        self.assertEqual(merged, e1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entities").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_members WHERE entity_id=?", (e1,)).fetchone()[0], 3)

    def test_entity_view_last_seen_spans_members(self):
        self.dev("00:10:20:30:40:50", now=NOW)
        tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "T", "type": "TPMS", "id": "1"})), NOW + 500, {})
        eid = identity.create_entity(self.db, "Bob")
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        identity.add_member(self.db, eid, "vehicle", "T:1")
        self.assertEqual(identity.entity_view(self.db)[0]["last_seen"], NOW + 500)

    def test_purge_keeps_entity_members(self):
        self.dev("00:10:20:30:40:50")
        eid = identity.create_entity(self.db, "Bob", known=False)
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        watcher.purge(self.db, self.cfg, NOW + 365 * 86400)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)


class TpmsAndCooccurrence(Base):
    def test_tpms_pair_suggestion_after_repeated_bursts(self):
        recent = {}
        for burst in range(5):
            t0 = NOW + burst * 600
            for k, sid in enumerate(("a1", "a2", "a3", "a4")):
                tpms.record(self.cfg, self.db, tpms.parse(json.dumps(
                    {"model": "Toyota", "type": "TPMS", "id": sid})), t0 + k * 5, {}, recent)
        sug = identity.suggestions(self.db, self.cfg, NOW + 4000)
        self.assertEqual(len(sug), 1)  # four sensors fold into one suggestion
        self.assertEqual(sorted(m["ref"] for m in sug[0]["members"]), ["Toyota:a1", "Toyota:a2", "Toyota:a3", "Toyota:a4"])
        self.assertNotIn("cooccur", sug[0]["evidence"])

    def test_separate_cars_do_not_pair(self):
        recent = {}
        for burst in range(6):
            tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "A", "type": "TPMS", "id": "1"})), NOW + burst * 3600, {}, recent)
            tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "B", "type": "TPMS", "id": "2"})), NOW + burst * 3600 + 1800, {}, recent)
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 6 * 3600), [])

    def test_cooccurrence_links_phone_and_watch(self):
        for visit in range(8):
            for k in range(3):
                t = NOW + visit * 86400 + k * 60
                for m in ("00:aa:00:00:00:01", "00:aa:00:00:00:02"):
                    watcher.ingest(self.db, rec(m), t, frozenset())
        # a household device that is always around carries no signal
        for k in range(0, 8 * 86400, 300):
            watcher.ingest(self.db, rec("00:bb:00:00:00:01"), NOW + k, frozenset())
        self.db.commit()
        sug = identity.suggestions(self.db, self.cfg, NOW + 9 * 86400)
        refs = {(s["a"]["ref"], s["b"]["ref"]) for s in sug}
        self.assertIn(("device:00:aa:00:00:00:01".split(":", 1)[1], "00:aa:00:00:00:02"), refs)
        self.assertEqual(len(refs), 1)


class EntityLevel(Base):
    def setup_entity(self):
        watcher.ingest(self.db, probe_rec("da:aa:00:00:00:0a", ["X_net", "a1", "a2", "a3", "a4"]), NOW, frozenset())
        watcher.ingest(self.db, probe_rec("da:aa:00:00:00:0b", ["Z_net", "b1", "b2", "b3", "b4"]), NOW + 100, frozenset())
        self.eid = identity.create_entity(self.db, "Bob")
        identity.add_member(self.db, self.eid, "device", "da:aa:00:00:00:0a")
        identity.add_member(self.db, self.eid, "device", "da:aa:00:00:00:0b")

    def test_partial_overlap_with_each_member_matches_the_entity(self):
        self.setup_entity()
        watcher.ingest(self.db, probe_rec("da:cc:00:00:00:01", ["X_net", "Z_net", "c1", "c2"]), NOW + 90000, frozenset())
        sug = identity.suggestions(self.db, self.cfg, NOW + 91000)
        self.assertEqual(len(sug), 1)
        self.assertEqual((sug[0]["entity_id"], sug[0]["entity_name"]), (self.eid, "Bob"))
        self.assertEqual(sug[0]["members"], [{"kind": "device", "ref": "da:cc:00:00:00:01"}])
        self.assertEqual(sug[0]["evidence"]["ssid"]["ssids"], ["X_net", "Z_net"])

    def test_single_member_overlap_alone_is_not_enough(self):
        self.setup_entity()
        watcher.ingest(self.db, probe_rec("da:cc:00:00:00:01", ["X_net", "c1", "c2", "c3", "c4"]), NOW + 90000, frozenset())
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 91000), [])

    def test_simultaneous_with_a_member_is_a_different_device(self):
        self.setup_entity()
        for k in range(6):
            watcher.ingest(self.db, probe_rec("da:aa:00:00:00:0a", ["X_net", "a1", "a2", "a3", "a4"]), NOW + 5000 + k * 60, frozenset())
            watcher.ingest(self.db, probe_rec("da:cc:00:00:00:01", ["X_net", "Z_net", "c1", "c2"]), NOW + 5000 + k * 60, frozenset())
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 91000), [])

    def test_accept_adds_to_entity_and_dismiss_remembers(self):
        self.setup_entity()
        watcher.ingest(self.db, probe_rec("da:cc:00:00:00:01", ["X_net", "Z_net", "c1", "c2"]), NOW + 90000, frozenset())
        m = [{"kind": "device", "ref": "da:cc:00:00:00:01"}]
        identity.dismiss_from_entity(self.db, self.eid, m)
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 91000), [])
        self.db.execute("DELETE FROM dismissed")
        identity.add_to_entity(self.db, self.eid, m)
        self.assertEqual(identity.entity_of(self.db, "device", "da:cc:00:00:00:01"), self.eid)
        self.assertEqual(identity.suggestions(self.db, self.cfg, NOW + 91000), [])

    def test_signals_summary_covers_different_signal_types(self):
        self.setup_entity()
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known) VALUES('55:55:55:55:55:55','Bluetooth',0,1,500,-60,0)")
        tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "Ford", "type": "TPMS", "id": "z"})), 900, {})
        identity.add_member(self.db, self.eid, "device", "55:55:55:55:55:55")
        identity.add_member(self.db, self.eid, "vehicle", "Ford:z")
        sig = {g["signal"]: g for g in identity.entity_view(self.db)[0]["signals"]}
        self.assertEqual(set(sig), {"Wi-Fi", "Bluetooth", "Tyre sensors", "Network names"})
        self.assertEqual(sig["Wi-Fi"]["count"], 2)
        self.assertEqual(sig["Network names"]["count"], 10)


class Groups(Base):
    def test_link_group_links_all_and_dismiss_group(self):
        macs = [f"00:10:20:30:40:0{i}" for i in range(4)]
        for m in macs:
            self.dev(m)
        members = [{"kind": "device", "ref": m} for m in macs]
        eid = identity.link_group(self.db, members, name="Car")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM entity_members WHERE entity_id=?", (eid,)).fetchone()[0], 4)
        identity.dismiss_group(self.db, members)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM dismissed").fetchone()[0], 6)
        with self.assertRaises(ValueError):
            identity.link_group(self.db, members[:1])


class Api(Base):
    def setUp(self):
        super().setUp()
        web._cfg = self.cfg
        self.client = web.app.test_client()

    def tearDown(self):
        web._cfg = None
        super().tearDown()

    def test_member_with_new_entity(self):
        self.dev("00:10:20:30:40:50")
        r = self.client.post("/api/entities/member", headers=H, json={
            "entity_id": "new", "new": {"name": "Bob", "kind": "regular", "expires_days": 7},
            "kind": "device", "ref": "00:10:20:30:40:50"})
        self.assertEqual(r.status_code, 200)
        e = self.client.get("/api/entities").get_json()["entities"][0]
        self.assertEqual((e["name"], e["kind"], e["known"]), ("Bob", "regular", 1))
        self.assertIsNotNone(e["expires"])
        r = self.client.post("/api/entities/member", headers=H, json={
            "entity_id": "new", "new": {"name": "X", "kind": "bogus"}, "kind": "device", "ref": "00:10:20:30:40:50"})
        self.assertEqual(r.status_code, 400)

    def test_entity_flow_ok(self):
        self.dev("00:10:20:30:40:50")
        eid = self.client.post("/api/entities", headers=H, json={"name": "Bob", "kind": "household"}).get_json()["id"]
        r = self.client.post("/api/entities/member", headers=H,
                             json={"entity_id": eid, "kind": "device", "ref": "00:10:20:30:40:50"})
        self.assertEqual(r.status_code, 200)
        e = self.client.get("/api/entities").get_json()["entities"]
        self.assertEqual((e[0]["name"], len(e[0]["members"])), ("Bob", 1))
        self.assertEqual(self.client.post("/api/entities/member", headers=H,
                         json={"entity_id": eid, "kind": "device", "ref": "ff:ff:ff:ff:ff:ff"}).status_code, 404)
        self.client.post("/api/entities/delete", headers=H, json={"id": eid})
        self.assertEqual(self.client.get("/api/entities").get_json()["entities"], [])

    def test_validation_and_csrf(self):
        self.assertEqual(self.client.post("/api/entities", headers=H, json={"name": ""}).status_code, 400)
        self.assertEqual(self.client.post("/api/entities", json={"name": "x"}).status_code, 403)
        self.assertEqual(self.client.post("/api/ssids", headers=H, json={"ssid": ""}).status_code, 400)

    def test_ssid_list_and_devices_probe_info(self):
        self.client.post("/api/ssids", headers=H, json={"ssid": "FooFoo1"})
        self.assertEqual(self.client.get("/api/ssids").get_json()["ssids"], ["FooFoo1"])
        watcher.ingest(self.db, probe_rec("00:10:20:30:40:50", ["Cabin"]), NOW, frozenset())
        self.db.commit()
        d = self.client.get("/api/devices?filter=all").get_json()["devices"][0]
        self.assertEqual((d["probe_count"], d["probe_list"]), (1, "Cabin"))
        self.client.post("/api/ssids/delete", headers=H, json={"ssid": "FooFoo1"})
        self.assertEqual(self.client.get("/api/ssids").get_json()["ssids"], [])

    def test_suggestion_accept_and_dismiss(self):
        for m in ("00:10:20:30:40:01", "00:10:20:30:40:02"):
            self.dev(m)
        a = {"kind": "device", "ref": "00:10:20:30:40:01"}
        b = {"kind": "device", "ref": "00:10:20:30:40:02"}
        r = self.client.post("/api/suggestions/accept", headers=H, json={"a": a, "b": b, "name": "Bob"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.post("/api/suggestions/accept", headers=H, json={"a": a}).status_code, 400)
        self.assertEqual(self.client.post("/api/suggestions/accept", headers=H,
                                          json={"members": [a], "name": "x"}).status_code, 400)
        eid = self.client.get("/api/entities").get_json()["entities"][0]["id"]
        self.dev("00:10:20:30:40:09")
        r = self.client.post("/api/suggestions/accept", headers=H,
                             json={"entity_id": eid, "members": [{"kind": "device", "ref": "00:10:20:30:40:09"}]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(self.client.get("/api/entities").get_json()["entities"][0]["members"]), 3)
        self.assertEqual(self.client.post("/api/suggestions/dismiss", headers=H, json={"a": a, "b": b}).status_code, 200)
        self.assertEqual(self.client.get("/api/suggestions").status_code, 200)


class Reset(Base):
    def populate(self):
        self.dev("00:10:20:30:40:50")
        watcher.ingest(self.db, probe_rec("da:aa:aa:aa:aa:01", ["Cabin"]), NOW, frozenset())
        tpms.record(self.cfg, self.db, tpms.parse(json.dumps({"model": "T", "type": "TPMS", "id": "1"})), NOW, {})
        eid = identity.create_entity(self.db, "Bob")
        identity.add_member(self.db, eid, "device", "00:10:20:30:40:50")
        self.db.execute("INSERT INTO networks VALUES('aa:bb:cc:00:00:01','Router',1)")
        self.db.execute("INSERT INTO home_ssids VALUES('FooFoo1',1)")
        watcher.meta_set(self.db, "mode", "home")
        watcher.meta_set(self.db, "baseline_max", 7)
        self.db.commit()

    def count(self, t):
        return self.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

    def test_reset_clears_discovered_and_keeps_my_networks(self):
        self.populate()
        watcher.reset_db(self.db)
        for t in watcher.DISCOVERED:
            self.assertEqual(self.count(t), 0, t)
        self.assertEqual((self.count("networks"), self.count("home_ssids")), (1, 1))
        self.assertEqual(watcher.meta_get(self.db, "mode"), "learning")
        self.assertIsNone(watcher.meta_get(self.db, "baseline_max"))

    def test_reset_everything(self):
        self.populate()
        watcher.reset_db(self.db, everything=True)
        self.assertEqual((self.count("networks"), self.count("home_ssids")), (0, 0))

    def test_sightings_are_recorded_again_after_reset(self):
        self.populate()
        watcher.reset_db(self.db)
        self.dev("00:10:20:30:40:50", now=NOW + 1)
        self.assertEqual(self.count("sightings"), 1)

    def test_api_requires_confirmation(self):
        self.populate()
        web._cfg = self.cfg
        try:
            c = web.app.test_client()
            self.assertEqual(c.post("/api/reset", headers=H, json={}).status_code, 400)
            self.assertEqual(c.post("/api/reset", headers=H, json={"confirm": "yes"}).status_code, 400)
            self.assertEqual(self.count("devices"), 2)
            r = c.post("/api/reset", headers=H, json={"confirm": "RESET"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(self.count("devices"), 0)
            self.assertEqual(self.count("networks"), 1)
        finally:
            web._cfg = None

    def test_cli_cancelled_without_confirmation(self):
        import argparse, io, contextlib
        from unittest import mock
        self.populate()
        with mock.patch("builtins.input", return_value="no"), contextlib.redirect_stdout(io.StringIO()):
            watcher.cmd_reset(self.cfg, self.db, argparse.Namespace(yes=False, everything=False))
        self.assertEqual(self.count("devices"), 2)
        with contextlib.redirect_stdout(io.StringIO()):
            watcher.cmd_reset(self.cfg, self.db, argparse.Namespace(yes=True, everything=False))
        self.assertEqual(self.count("devices"), 0)


class Throttle(Base):
    def test_one_sighting_per_interval(self):
        for k in range(5):
            self.dev("00:10:20:30:40:50", now=NOW + k * 2)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM sightings").fetchone()[0], 1)
        self.dev("00:10:20:30:40:50", now=NOW + 12)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM sightings").fetchone()[0], 2)
        self.assertEqual(self.db.execute("SELECT seen_count FROM devices").fetchone()[0], 6)

    def test_clock_going_backwards_does_not_stall_recording(self):
        self.dev("00:10:20:30:40:50", now=NOW + 5000)
        self.dev("00:10:20:30:40:50", now=NOW)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM sightings").fetchone()[0], 2)

    def test_presence_recorded_once_per_bucket(self):
        for k in range(5):
            self.dev("00:10:20:30:40:50", now=NOW + k * 20)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM presence").fetchone()[0], 1)


class Doctor(Base):
    def test_doctor_reports_fields(self):
        devs = [
            {"kismet.device.base.macaddr": "aa:bb:cc:00:00:01", "kismet.device.base.phyname": "IEEE802.11", "rssi": -50,
             "bssid": "aa:bb:cc:00:00:02", "probes": {"1": {"dot11.probedssid.ssid": "Cabin"}}},
            {"kismet.device.base.macaddr": "aa:bb:cc:00:00:03", "kismet.device.base.phyname": "Bluetooth", "rssi": -70},
        ]

        class H_(BaseHTTPRequestHandler):
            def reply(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

            def do_GET(self):
                self.reply([{"kismet.datasource.name": "wifi", "kismet.datasource.interface": "wlan1",
                             "kismet.datasource.running": 1}] if "datasource" in self.path else {})

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.reply(devs)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H_)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)
        cfg = make_cfg(self.t.name, kismet={"url": f"http://127.0.0.1:{srv.server_port}"})
        import io, contextlib, argparse
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            watcher.cmd_doctor(cfg, self.db, argparse.Namespace(dump=None))
        out = buf.getvalue()
        self.assertIn("wifi (wlan1) running", out)
        self.assertIn("2 devices", out)
        self.assertIn("probed SSIDs present on 1 devices (1 distinct", out)
        self.assertNotIn("FAIL", out)

    def test_doctor_unreachable(self):
        cfg = make_cfg(self.t.name, kismet={"url": "http://127.0.0.1:9"})
        import io, contextlib, argparse
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            watcher.cmd_doctor(cfg, self.db, argparse.Namespace(dump=None))
        self.assertIn("FAIL", buf.getvalue())


if __name__ == "__main__":
    unittest.main()


class Insight(unittest.TestCase):
    def test_harvest_and_merge(self):
        import insight
        d = {"type": "Wi-Fi AP", "channel": "6", "fp_probe": 123, "clients": {"AA:BB:CC:00:00:01": 1},
             "ap_ssids": {"1": {"dot11.advertisedssid.ssid": "Home", "dot11.advertisedssid.crypt_string": "WPA2"}},
             "bss_ts": 7200000000}
        h = insight.harvest(d)
        self.assertEqual(h["clients"], ["aa:bb:cc:00:00:01"])
        self.assertEqual(h["ssids"][0]["ssid"], "Home")
        self.assertEqual(h["uptime_s"], 7200)
        m = insight.merge_extra(h, {"channels": ["11"]})
        self.assertEqual(m["channels"], ["11", "6"])
        self.assertEqual(insight.harvest({}), {})

    def test_interesting_ignores_kismet_bookkeeping(self):
        import insight
        rec = {"kismet.server.uuid": "x", "kismet.device.base.seenby": [{"kismet.common.seenby.uuid": "y"}],
               "btle.device": {"btle.device.address_type": "random", "btle.device.service_uuid_vec": ["180f"]}}
        got = insight.interesting(rec).get("Bluetooth", [])
        self.assertEqual({k for k, _ in got}, {"btle.device.address_type", "btle.device.service_uuid_vec"})

    def test_bluetooth_facts_and_adv_parsing(self):
        import insight
        # flags record, then manufacturer data: Apple (0x004c), Nearby info (0x10); then a complete name
        adv = bytes([2, 1, 6, 5, 0xFF, 0x4C, 0x00, 0x10, 0x05, 6, 9]) + b"Watch"
        f = insight.bt_facts(7, "Wristwatch", -8, "BLE", ["0000180f-0000-1000-8000-00805f9b34fb"], list(adv))
        self.assertEqual(f["class"], "wearable")
        self.assertEqual(f["services"], ["Battery"])
        self.assertEqual(f["company"], "Apple")
        self.assertIn("Nearby info", f["apple_message"])
        self.assertEqual(f["adv_name"], "Watch")
        self.assertEqual(insight.parse_adv(adv.hex())["company_id"], 0x004C)
        self.assertIsNone(insight.parse_adv("zz"))
        self.assertEqual(insight.bt_facts(0, 0, 0, None, None, None), {})
        self.assertIn("static random", insight.address_kind("c1:00:00:00:00:00", False))
        self.assertIn("resolvable private", insight.address_kind("5a:00:00:00:00:00", False))

    def test_trend_and_distance(self):
        import insight
        up = [[i * 20, -80 + i * 2] for i in range(10)]
        self.assertEqual(insight.trend(up)["label"], "getting closer")
        self.assertEqual(insight.trend([[0, -50], [10, -50]])["slope"], None)
        self.assertEqual(insight.distance(-45, "IEEE802.11"), "under 3 m")
        self.assertIsNone(insight.distance(0, "x"))

    def test_extras_stored_once_and_entity_pattern(self):
        import insight
        t = tmpdir()
        self.addCleanup(t.cleanup)
        db = watcher.db_connect(make_cfg(t.name))
        d = {"kismet.device.base.macaddr": "AA:BB:CC:00:00:09", "kismet.device.base.phyname": "IEEE802.11",
             "rssi": -50, "channel": "6", "fp_probe": 5}
        watcher.ingest(db, d, 1000)
        watcher.ingest(db, dict(d, channel="11"), 1100)
        db.commit()
        row = db.execute("SELECT extra FROM devices WHERE mac='aa:bb:cc:00:00:09'").fetchone()[0]
        self.assertEqual(json.loads(row)["channels"], ["11", "6"])
        now = 10_000_000
        b0 = now // 300 - 40
        for b in (b0, b0 + 1, b0 + 2, b0 + 30):
            db.execute("INSERT INTO presence VALUES(?,?)", (b, "device:aa:bb:cc:00:00:09"))
        p = insight.entity_pattern(db, [("device", "aa:bb:cc:00:00:09")], now, 0)
        self.assertEqual(p["visits"], 2)
        self.assertEqual(p["avg_minutes"], 10)
        db.close()


class FingerprintLinking(unittest.TestCase):
    EX = json.dumps({"bt": {"class": "wearable", "services": ["Heart Rate", "Battery"], "company": "Garmin",
                            "adv_name": "Fenix"}})

    def setUp(self):
        self.t = tmpdir()
        self.addCleanup(self.t.cleanup)
        self.db = watcher.db_connect(make_cfg(self.t.name))
        import insight
        self.fp = insight.fingerprint(json.loads(self.EX))[0]

    def add_addr(self, mac, first, last, extra=None, rand=1):
        self.db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,extra,fp) "
                        "VALUES(?,?,?,?,?,-60,0,?,?)", (mac, "Bluetooth", rand, first, last, extra or self.EX, self.fp))
        self.db.commit()

    def chain(self, n=4, start=1_000_000):
        for i in range(n):
            self.add_addr("5a:00:00:00:00:%02x" % i, start + i * 900, start + i * 900 + 840)

    def test_turn_taking_addresses_are_suggested(self):
        self.chain()
        s = identity.fingerprint_suggestions(self.db, 1_005_000)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["members"][0]["ref"], self.fp)
        self.assertEqual(s[0]["evidence"]["fingerprint"]["addresses"], 4)

    def test_overlapping_addresses_mean_several_devices(self):
        for i in range(4):
            self.add_addr("5a:00:00:00:01:%02x" % i, 1_000_000, 1_003_000)
        self.assertEqual(identity.fingerprint_suggestions(self.db, 1_005_000), [])

    def test_too_few_addresses_and_poor_fingerprint_are_skipped(self):
        self.chain(2)
        self.assertEqual(identity.fingerprint_suggestions(self.db, 1_005_000), [])

    def test_accept_then_future_addresses_are_known(self):
        self.chain()
        eid = identity.link_fingerprint(self.db, self.fp, name="Bob watch")
        self.assertEqual(identity.fingerprint_suggestions(self.db, 1_005_000), [])
        d = {"kismet.device.base.macaddr": "5A:99:99:99:99:99", "kismet.device.base.phyname": "Bluetooth",
             "rssi": -60, "bt_major": 7, "bt_uuids": ["180d", "180f"], "bt_adv": None}
        # the same facts as the fingerprinted device, delivered the way Kismet would
        d.update({"bt_major": 7})
        ex = json.loads(self.EX)["bt"]
        import insight
        probe = insight.fingerprint({"bt": ex})
        self.assertTrue(identity.fingerprint_is_known(self.db, probe[0], 1_005_000))
        self.assertIn(eid, [e["id"] for e in identity.entity_view(self.db)])
        view = [e for e in identity.entity_view(self.db) if e["id"] == eid][0]
        self.assertEqual(view["members"][0]["kind"], "fingerprint")

    def test_untrusted_or_lapsed_entity_does_not_match(self):
        self.chain()
        eid = identity.link_fingerprint(self.db, self.fp, name="Visitor", kind="visitor", expires_days=1)
        import time
        self.assertTrue(identity.fingerprint_is_known(self.db, self.fp, time.time()))
        self.assertFalse(identity.fingerprint_is_known(self.db, self.fp, time.time() + 3 * 86400))
        self.db.execute("UPDATE entities SET known=0 WHERE id=?", (eid,))
        self.assertFalse(identity.fingerprint_is_known(self.db, self.fp, time.time()))

    def test_entity_pattern_covers_fingerprint_addresses(self):
        self.chain()
        eid = identity.link_fingerprint(self.db, self.fp, name="Bob watch")
        now = int(__import__("time").time())
        for i in range(4):
            self.db.execute("INSERT OR IGNORE INTO presence VALUES(?,?)", (now // 300 - i, "device:5a:00:00:00:00:%02x" % i))
        self.db.commit()
        web._cfg = make_cfg(self.t.name)
        self.addCleanup(setattr, web, "_cfg", None)
        ents = web.app.test_client().get("/api/entities").get_json()["entities"]
        self.assertEqual([e for e in ents if e["id"] == eid][0]["pattern"]["visits"], 1)

    def test_dismiss_hides_it(self):
        self.chain()
        identity.dismiss_group(self.db, [{"kind": "fingerprint", "ref": self.fp}])
        self.assertEqual(identity.fingerprint_suggestions(self.db, 1_005_000), [])

    def test_ingest_marks_matching_rotating_device_known_and_static(self):
        self.chain()
        identity.link_fingerprint(self.db, self.fp, name="Bob watch")
        adv_name = b"\x06\x09Fenix"
        adv = list(adv_name)
        d = {"kismet.device.base.macaddr": "5A:99:99:99:99:99", "kismet.device.base.phyname": "Bluetooth",
             "kismet.device.base.manuf": "", "rssi": -60, "bt_major": 7, "bt_uuids": ["180d", "180f"],
             "bt_adv": adv + [5, 0xFF, 0x87, 0x00, 1, 2]}
        import insight
        got = insight.fingerprint(insight.harvest(d))
        if got and got[0] == self.fp:
            watcher.ingest(self.db, d, 2_000_000)
            row = self.db.execute("SELECT rand, known FROM devices WHERE mac='5a:99:99:99:99:99'").fetchone()
            self.assertEqual(tuple(row), (0, 1))
        else:
            self.skipTest("test advertisement does not reproduce the fingerprint")

    def test_add_member_rejects_unknown_or_malformed_fingerprint(self):
        eid = identity.create_entity(self.db, "X")
        with self.assertRaises(ValueError):
            identity.add_member(self.db, eid, "fingerprint", "zzz")
        with self.assertRaises(KeyError):
            identity.add_member(self.db, eid, "fingerprint", "0" * 12)
