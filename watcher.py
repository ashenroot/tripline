#!/usr/bin/env python3
"""WUDS2 watcher.

Polls the local Kismet REST API, logs sightings to SQLite, and sends ntfy alerts
for unknown devices near the house.

Modes
  learning  log everything, never alert (run this 1-2 weeks)
  home      household present: static unknown devices alert; rotating-address
            devices alert only when their count exceeds the learned household peak
  away      house empty: any strong rotating-address device alerts (after margin)

Commands: run, status, arm, home, away, guest, known, report
"""
import argparse
import base64
import configparser
import json
import os
import sqlite3
import sys
import time
import urllib.parse
import urllib.request

CFG_PATH = os.environ.get("WUDS_CONFIG", "/etc/wuds/config.ini")

FIELDS = [
    "kismet.device.base.macaddr",
    "kismet.device.base.phyname",
    "kismet.device.base.manuf",
    "kismet.device.base.name",
    "kismet.device.base.last_time",
    ["kismet.device.base.signal/kismet.common.signal.last_signal", "rssi"],
    # BSSID of the access point a Wi-Fi client is associated with. Verify this field
    # name against your Kismet version; if it is absent, home_bssids simply has no effect.
    ["dot11.device/dot11.device.last_bssid", "bssid"],
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    ts INTEGER, mac TEXT, phy TEXT, rssi INTEGER, rand INTEGER);
CREATE INDEX IF NOT EXISTS ix_sightings_ts ON sightings(ts);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, phy TEXT, manuf TEXT, name TEXT, rand INTEGER,
    first_seen INTEGER, last_seen INTEGER, max_rssi INTEGER,
    seen_count INTEGER DEFAULT 0, known INTEGER DEFAULT 0, label TEXT);
CREATE TABLE IF NOT EXISTS counts (ts INTEGER, n INTEGER);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS alerts (
    ts INTEGER, title TEXT, message TEXT, priority TEXT);
"""


# ---------- config / db helpers ----------

def load_cfg():
    cp = configparser.ConfigParser()
    if not cp.read(CFG_PATH):
        sys.exit(f"Config not found: {CFG_PATH} (set WUDS_CONFIG or create it)")
    return cp


def db_connect(cfg):
    path = cfg.get("detect", "db_path")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")  # lets the web app read while the watcher writes
    db.executescript(SCHEMA)
    # Who made a device known: NULL (you, home_bssids or arm), 'unifi', or 'unmarked'
    # (you removed it by hand, so automatic sources leave it alone).
    cols = {r[1] for r in db.execute("PRAGMA table_info(devices)")}
    for col, ddl in (("src", "TEXT"), ("synced_at", "INTEGER")):
        if col not in cols:
            db.execute(f"ALTER TABLE devices ADD COLUMN {col} {ddl}")
    db.commit()
    return db


def meta_get(db, key, default=None):
    row = db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(db, key, value):
    db.execute("INSERT INTO meta(k,v) VALUES(?,?) "
               "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, str(value)))
    db.commit()


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ---------- device classification ----------

def is_bt(phy):
    return "bluetooth" in (phy or "").lower() or (phy or "").lower() in ("btle", "bt")


def is_random(phy, mac, manuf):
    """Heuristic: does this address rotate?

    Wi-Fi: locally-administered bit set in the first octet.
    Bluetooth: no vendor (OUI) resolved. Verify against your Kismet output.
    """
    if is_bt(phy):
        return 1 if (not manuf or manuf.lower() == "unknown") else 0
    try:
        return 1 if int(mac.split(":")[0], 16) & 0x02 else 0
    except ValueError:
        return 0


# ---------- Kismet / notifications ----------

def kismet_devices(cfg, since_ts):
    base = cfg.get("kismet", "url").rstrip("/")
    url = f"{base}/devices/last-time/{since_ts}/devices.json"
    body = urllib.parse.urlencode({"json": json.dumps({"fields": FIELDS})}).encode()
    req = urllib.request.Request(url, data=body)
    cred = f"{cfg.get('kismet', 'user')}:{cfg.get('kismet', 'password')}".encode()
    req.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def notify(cfg, db, title, message, priority="default", tags=""):
    """Record the alert, then deliver it to every configured channel.

    Channels: ntfy (only if [ntfy] topic is set), a JSON webhook (only if
    [webhook] url is set). With neither, the alert is logged and shown in the web UI.
    """
    db.execute("INSERT INTO alerts VALUES(?,?,?,?)",
               (int(time.time()), title, message, priority))
    db.commit()
    log(f"ALERT: {title} - {message}")
    topic = cfg.get("ntfy", "topic", fallback="").strip()
    if topic:
        url = cfg.get("ntfy", "url", fallback="https://ntfy.sh").rstrip("/") + "/" + topic
        req = urllib.request.Request(
            url, data=message.encode(),
            headers={"Title": title, "Priority": priority, "Tags": tags})
        _deliver(req, "ntfy")
    hook = cfg.get("webhook", "url", fallback="").strip()
    if hook:
        body = json.dumps({"title": title, "message": message,
                           "priority": priority, "ts": int(time.time())}).encode()
        _deliver(urllib.request.Request(
            hook, data=body, headers={"Content-Type": "application/json"}), "webhook")


def _deliver(req, name):
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as exc:  # alerting must never crash the loop
        log(f"{name} delivery failed: {exc}")


# ---------- detection ----------

def random_count(db, cfg, now):
    window = cfg.getint("detect", "random_window_seconds")
    wifi_thr = cfg.getint("detect", "wifi_rssi")
    bt_thr = cfg.getint("detect", "bt_rssi")
    row = db.execute(
        "SELECT COUNT(DISTINCT mac) FROM sightings WHERE ts>=? AND rand=1 AND "
        "((phy LIKE '%luetooth%' AND rssi>=?) OR (phy NOT LIKE '%luetooth%' AND rssi>=?))",
        (now - window, bt_thr, wifi_thr)).fetchone()
    return row[0] or 0


def ingest(db, d, now, home=frozenset()):
    """Log one Kismet device record.

    `home` holds your own access-point BSSIDs. A client associated with one is part
    of your network: it is marked known and never treated as a rotating address
    (phones use a stable per-network MAC while associated).
    """
    mac = d.get("kismet.device.base.macaddr")
    rssi = d.get("rssi")
    if not mac or not isinstance(rssi, int) or rssi == 0:
        return None
    phy = d.get("kismet.device.base.phyname") or ""
    manuf = d.get("kismet.device.base.manuf") or ""
    name = d.get("kismet.device.base.name") or ""
    at_home = 1 if (mac.lower() in home or (d.get("bssid") or "").lower() in home) else 0
    rand = 0 if at_home else is_random(phy, mac, manuf)
    db.execute("INSERT INTO sightings VALUES(?,?,?,?,?)", (now, mac, phy, rssi, rand))
    db.execute(
        "INSERT INTO devices(mac,phy,manuf,name,rand,first_seen,last_seen,max_rssi,seen_count,known) "
        "VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(mac) DO UPDATE SET "
        "last_seen=excluded.last_seen, max_rssi=MAX(max_rssi, excluded.max_rssi), "
        "seen_count=seen_count+1, name=COALESCE(NULLIF(excluded.name,''), name), "
        "rand=MIN(rand, excluded.rand), "
        "known=CASE WHEN src='unmarked' THEN known ELSE MAX(known, excluded.known) END",
        (mac, phy, manuf, name, rand, now, now, rssi, at_home))
    known = db.execute("SELECT known FROM devices WHERE mac=?", (mac,)).fetchone()[0]
    return mac, phy, manuf, rssi, rand, known


def purge(db, cfg, now):
    cutoff = now - cfg.getint("detect", "retention_days") * 86400
    db.execute("DELETE FROM sightings WHERE ts<?", (cutoff,))
    db.execute("DELETE FROM devices WHERE known=0 AND last_seen<?", (cutoff,))
    db.commit()


def run(cfg, db, once=False):
    poll = cfg.getint("detect", "poll_seconds")
    dwell = cfg.getint("detect", "dwell_seconds")
    gap = cfg.getint("detect", "gap_seconds")
    cooldown = cfg.getint("detect", "alert_cooldown_minutes") * 60
    confirm = cfg.getint("detect", "burst_confirm_seconds")
    home = frozenset(m.strip().lower()
                     for m in cfg.get("detect", "home_bssids", fallback="").split(",") if m.strip())

    if meta_get(db, "mode") is None:
        meta_set(db, "mode", "learning")
        meta_set(db, "learning_start", int(time.time()))

    presence = {}      # mac -> [first_ts, last_ts] above the RSSI floor
    alerted = {}       # key -> last alert ts
    burst_since = None
    last_count = last_purge = 0
    kismet_fail_since = None
    last_poll = int(time.time()) - 60

    while True:
        now = int(time.time())
        mode = meta_get(db, "mode", "learning")
        quiet = now < float(meta_get(db, "quiet_until", 0))

        try:
            devices = kismet_devices(cfg, last_poll - 2)
            if kismet_fail_since is not None:
                log("Kismet reachable again")
            kismet_fail_since = None
        except Exception as exc:
            log(f"Kismet poll failed: {exc}")
            kismet_fail_since = kismet_fail_since or now
            if now - kismet_fail_since > 600 and now - alerted.get("down", 0) > 3600:
                notify(cfg, db, "WUDS sensor down", "Kismet unreachable for 10+ minutes",
                       "high", "warning")
                alerted["down"] = now
            if once:
                return
            time.sleep(poll)
            continue
        last_poll = now

        for d in devices:
            row = ingest(db, d, now, home)
            if row is None or mode == "learning" or quiet:
                continue
            mac, phy, manuf, rssi, rand, known = row
            if rand or known:
                continue
            thr = cfg.getint("detect", "bt_rssi" if is_bt(phy) else "wifi_rssi")
            if rssi < thr:
                continue
            p = presence.get(mac)
            if p is None or now - p[1] > gap:
                presence[mac] = p = [now, now]
            else:
                p[1] = now
            if p[1] - p[0] >= dwell and now - alerted.get(mac, 0) > cooldown:
                alerted[mac] = now
                notify(cfg, db, "Unknown device near house",
                       f"{phy} {mac} {manuf or 'unknown vendor'} at {rssi} dBm "
                       f"for {p[1] - p[0]}s", "high", "satellite")
        db.commit()

        # rotating-address devices: count-based logic
        n = random_count(db, cfg, now)
        if mode == "learning":
            if now - last_count >= 60:
                db.execute("INSERT INTO counts VALUES(?,?)", (now, n))
                db.commit()
                last_count = now
        elif not quiet:
            if mode == "away":
                limit = cfg.getint("detect", "random_margin_away")
            else:
                limit = int(meta_get(db, "baseline_max", 0)) + \
                    cfg.getint("detect", "random_margin_home")
            if n > limit:
                burst_since = burst_since or now
                if now - burst_since >= confirm and now - alerted.get("burst", 0) > cooldown:
                    alerted["burst"] = now
                    notify(cfg, db, "Unusual device count near house",
                           f"{n} rotating-address devices nearby (limit {limit}, mode {mode})",
                           "high", "satellite")
            else:
                burst_since = None

        if now - last_purge > 3600:
            purge(db, cfg, now)
            last_purge = now
        if once:
            return
        time.sleep(poll)


# ---------- commands ----------

def cmd_status(cfg, db, args):
    now = int(time.time())
    total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    static = db.execute("SELECT COUNT(*) FROM devices WHERE rand=0").fetchone()[0]
    known = db.execute("SELECT COUNT(*) FROM devices WHERE known=1").fetchone()[0]
    last = db.execute("SELECT MAX(ts) FROM sightings").fetchone()[0]
    quiet = float(meta_get(db, "quiet_until", 0))
    print(f"mode:            {meta_get(db, 'mode', 'learning')}")
    ls = meta_get(db, "learning_start")
    if ls:
        print(f"learning start:  {fmt_ts(ls)}")
    print(f"devices:         {total} total, {static} static-address, {known} known")
    print(f"random count now:{random_count(db, cfg, now)}   learned peak: "
          f"{meta_get(db, 'baseline_max', 'n/a')}")
    print(f"last sighting:   {fmt_ts(last) if last else 'none'}")
    print(f"guest/quiet:     {'until ' + fmt_ts(quiet) if quiet > now else 'off'}")


def do_arm(db):
    """End learning: mark static devices known, store the household peak, go to home mode."""
    counts = sorted(r[0] for r in db.execute("SELECT n FROM counts"))
    peak = counts[int(0.99 * (len(counts) - 1))] if counts else 0
    db.execute("UPDATE devices SET known=1 WHERE rand=0 AND COALESCE(src,'')!='unmarked'")
    db.commit()
    meta_set(db, "baseline_max", peak)
    meta_set(db, "mode", "home")
    return peak, len(counts)


def cmd_arm(cfg, db, args):
    peak, minutes = do_arm(db)
    if minutes < 60 * 24:
        print(f"WARNING: only {minutes} minutes of baseline "
              f"(recommended: 14 days). Armed anyway.")
    print(f"Armed in home mode. Learned rotating-address peak (p99): {peak}. "
          f"Static devices seen so far are now known.")


def cmd_mode(mode):
    def fn(cfg, db, args):
        meta_set(db, "mode", mode)
        print(f"mode: {mode}")
    return fn


def cmd_guest(cfg, db, args):
    if args.hours.lower() == "off":
        meta_set(db, "quiet_until", 0)
        print("guest/quiet window cleared")
        return
    until = time.time() + float(args.hours) * 3600
    meta_set(db, "quiet_until", until)
    print(f"alerts suppressed until {fmt_ts(until)} (sightings still logged)")


def cmd_known(cfg, db, args):
    mac = args.mac.lower() if args.mac else None
    if args.action == "list":
        for r in db.execute("SELECT mac,phy,manuf,label,last_seen FROM devices "
                            "WHERE known=1 AND rand=0 ORDER BY last_seen DESC"):
            print(f"{r[0]}  {r[1]:<12} {r[2] or '-':<20} {r[3] or '-':<20} {fmt_ts(r[4])}")
        return
    if not mac:
        sys.exit("MAC required")
    if args.action == "add":
        now = int(time.time())
        db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,label) "
                   "VALUES(?,?,0,?,?,0,1,?) ON CONFLICT(mac) DO UPDATE SET known=1, "
                   "label=COALESCE(?, label), src=NULL",
                   (mac, "", now, now, args.label, args.label))
    else:
        db.execute("UPDATE devices SET known=0, src='unmarked' WHERE mac=?", (mac,))
    db.commit()
    print(f"{args.action}: {mac}")


def cmd_report(cfg, db, args):
    cutoff = int(time.time()) - args.hours * 3600
    rows = db.execute(
        "SELECT mac,phy,manuf,name,max_rssi,seen_count,first_seen,last_seen FROM devices "
        "WHERE known=0 AND rand=0 AND last_seen>=? ORDER BY max_rssi DESC LIMIT 50",
        (cutoff,)).fetchall()
    print(f"Unknown static-address devices, last {args.hours}h (strongest first):")
    for r in rows:
        print(f"{r[0]}  {r[1]:<12} {r[2] or '-':<18} {r[3] or '-':<16} "
              f"max {r[4]} dBm  seen {r[5]}x  {fmt_ts(r[6])} -> {fmt_ts(r[7])}")
    if not rows:
        print("  none")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="main loop")
    p.add_argument("--once", action="store_true", help="one poll cycle (testing)")
    sub.add_parser("status")
    sub.add_parser("arm", help="end learning, mark baseline, switch to home mode")
    sub.add_parser("home")
    sub.add_parser("away")
    p = sub.add_parser("guest", help="suppress alerts: guest HOURS | guest off")
    p.add_argument("hours")
    p = sub.add_parser("known", help="known add MAC [label] | del MAC | list")
    p.add_argument("action", choices=["add", "del", "list"])
    p.add_argument("mac", nargs="?")
    p.add_argument("label", nargs="?")
    p = sub.add_parser("report", help="unknown static devices, for tagging")
    p.add_argument("--hours", type=int, default=24)
    args = ap.parse_args()

    cfg = load_cfg()
    db = db_connect(cfg)
    if args.cmd == "run":
        run(cfg, db, once=args.once)
        return
    {"status": cmd_status, "arm": cmd_arm, "home": cmd_mode("home"),
     "away": cmd_mode("away"), "guest": cmd_guest, "known": cmd_known,
     "report": cmd_report}[args.cmd](cfg, db, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
