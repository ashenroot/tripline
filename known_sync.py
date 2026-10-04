#!/usr/bin/env python3
"""Keep the known-device list in step with external sources (see sources/).

    known_sync.py once     run every configured source once and exit
    known_sync.py run      run forever, every [sync] interval_minutes

Rules, applied per source:
  * A listed device that is unknown becomes known, recorded as src=<source name>.
  * Devices you marked or removed by hand are never overridden (src NULL / 'unmarked').
  * Your own labels are kept; a source label is used only when none exists.
  * A device this source previously added, and that it no longer lists, is revoked.
  * If a source fails, or suddenly returns nothing, nothing is revoked.
"""
import argparse
import sys
import time

import sources
import watcher
from watcher import log


def source_sections(cfg):
    names = [n.strip() for n in cfg.get("sync", "sources", fallback="").split(",") if n.strip()]
    return [(n, dict(cfg.items(f"source.{n}"))) for n in names if cfg.has_section(f"source.{n}")]


def apply(db, name, devs, now=None):
    """Apply one source's device list. Returns (added, revoked, relabelled)."""
    now = int(now or time.time())
    listed = {d["mac"]: d.get("label") for d in devs}
    added = revoked = relabelled = 0
    for mac, label in listed.items():
        row = db.execute("SELECT known, src, label FROM devices WHERE mac=?", (mac,)).fetchone()
        if row is None:
            db.execute("INSERT INTO devices(mac,phy,manuf,name,rand,first_seen,last_seen,max_rssi,"
                       "seen_count,known,label,src,synced_at) VALUES(?,?,?,?,0,?,?,-100,0,1,?,?,?)",
                       (mac, "IEEE802.11", "", "", now, now, label, name, now))
            added += 1
            continue
        known, src, cur = row
        if src == "unmarked":
            continue
        if not known:
            db.execute("UPDATE devices SET known=1, src=?, synced_at=?, rand=0, "
                       "label=COALESCE(label, ?) WHERE mac=?", (name, now, label, mac))
            added += 1
        elif src == name:
            if label and label != cur and (cur is None):
                relabelled += 1
            db.execute("UPDATE devices SET synced_at=?, label=COALESCE(label, ?) WHERE mac=?",
                       (now, label, mac))
    prev = [r[0] for r in db.execute("SELECT mac FROM devices WHERE src=?", (name,))]
    if listed or not prev:  # an empty answer is more likely an outage than a purge
        for mac in prev:
            if mac not in listed:
                db.execute("UPDATE devices SET known=0, src=NULL WHERE mac=?", (mac,))
                revoked += 1
    db.commit()
    return added, revoked, relabelled


def sync_once(cfg, db):
    for name, section in source_sections(cfg):
        try:
            devs = sources.load(name, section).devices()
        except Exception as exc:
            log(f"sync {name}: failed, nothing changed ({exc})")
            continue
        a, r, l = apply(db, name, devs)
        log(f"sync {name}: {len(devs)} listed, {a} added, {r} revoked")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["once", "run"])
    args = ap.parse_args()
    cfg = watcher.load_cfg()
    if not source_sections(cfg):
        sys.exit("No sources configured: set [sync] sources = ... and a [source.<name>] section.")
    db = watcher.db_connect(cfg)
    every = cfg.getint("sync", "interval_minutes", fallback=15) * 60
    while True:
        sync_once(cfg, db)
        if args.cmd == "once":
            return
        time.sleep(every)


if __name__ == "__main__":
    main()
