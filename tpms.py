#!/usr/bin/env python3
"""Vehicle detection from tyre-pressure (TPMS) sensors, via rtl_433 and an RTL-SDR dongle.

    tpms.py run            start rtl_433 (see [vehicles]) and record what it decodes
    tpms.py run --stdin    read rtl_433 JSON lines from stdin instead (testing, other SDR setups)

Each TPMS sensor has a fixed ID, so a car shows up as up to four IDs. Sensors transmit
while the wheels turn, so this sees vehicles arriving and leaving, not parked ones.
An unknown sensor seen in home or away mode raises an alert (unless a guest window is
open). Mark your own vehicles known in the web UI. Sensors are never marked known
automatically.
"""
import argparse
import json
import shlex
import subprocess
import sys
import time

import identity
import watcher
from watcher import log, meta_get, notify

DEFAULT_CMD = "rtl_433 -d {device} {freqs} -F json -M level -M time:unix"


def parse(line):
    """One rtl_433 JSON line -> {"vid","model","id","rssi","freq"} for TPMS messages, else None."""
    try:
        m = json.loads(line)
    except ValueError:
        return None
    if not isinstance(m, dict) or "id" not in m:
        return None
    is_tpms = str(m.get("type", "")).upper() == "TPMS" or any(str(k).startswith("pressure") for k in m)
    if not is_tpms:
        return None
    model = str(m.get("model", "unknown"))[:40]
    sid = str(m["id"])[:32]
    rssi = m.get("rssi")
    freq = m.get("freq")
    return {"vid": f"{model}:{sid}", "model": model, "id": sid,
            "rssi": float(rssi) if isinstance(rssi, (int, float)) else None,
            "freq": float(freq) if isinstance(freq, (int, float)) else None}


def record(cfg, db, msg, now, last_alert, recent=None):
    """Store one decoded message; alert on an unknown vehicle. Returns True if an alert was sent."""
    db.execute(
        "INSERT INTO vehicles(vid,model,sensor_id,first_seen,last_seen,seen_count,known,last_rssi,last_freq) "
        "VALUES(?,?,?,?,?,1,0,?,?) ON CONFLICT(vid) DO UPDATE SET last_seen=excluded.last_seen, "
        "seen_count=seen_count+1, last_rssi=excluded.last_rssi, last_freq=excluded.last_freq",
        (msg["vid"], msg["model"], msg["id"], now, now, msg["rssi"], msg["freq"]))
    db.execute("INSERT INTO vehicle_sightings(ts,vid) VALUES(?,?)", (now, msg["vid"]))
    if recent is not None:
        identity.note_tpms(db, recent, msg["vid"], now)
    db.commit()
    known = db.execute("SELECT known FROM vehicles WHERE vid=?", (msg["vid"],)).fetchone()[0]
    mode = meta_get(db, "mode", "learning")
    if known or mode == "learning" or now < float(meta_get(db, "quiet_until", 0)):
        return False
    cooldown = cfg.getint("detect", "alert_cooldown_minutes") * 60
    if now - last_alert.get(msg["vid"], 0) <= cooldown:
        return False
    last_alert[msg["vid"]] = now
    notify(cfg, db, "Unknown vehicle near house",
           f"TPMS sensor {msg['model']} {msg['id']}"
           + (f" at {msg['rssi']:.0f} dB" if msg["rssi"] is not None else ""), "high", "car")
    return True


def command(cfg):
    custom = cfg.get("vehicles", "command", fallback="").strip()
    freqs = [f.strip() for f in cfg.get("vehicles", "frequencies", fallback="315M, 433.92M").split(",") if f.strip()]
    fargs = " ".join(f"-f {shlex.quote(f)}" for f in freqs)
    if len(freqs) > 1:
        # rtl_433 defaults to hopping every 600 s, far too slow to catch a passing car.
        hop = max(1, cfg.getint("vehicles", "hop_seconds", fallback=10))
        fargs += f" -H {hop}"
    tmpl = custom or DEFAULT_CMD
    return tmpl.format(device=shlex.quote(cfg.get("vehicles", "device", fallback="0")), freqs=fargs)


def consume(cfg, db, lines):
    last_alert, last_purge, recent = {}, 0, {}
    for line in lines:
        msg = parse(line)
        if msg is None:
            continue
        now = int(time.time())
        record(cfg, db, msg, now, last_alert, recent)
        if now - last_purge > 3600:
            cutoff = now - cfg.getint("detect", "retention_days") * 86400
            db.execute("DELETE FROM vehicles WHERE known=0 AND last_seen<?", (cutoff,))
            db.commit()
            last_purge = now


def run(cfg, db):
    while True:
        cmd = command(cfg)
        log(f"starting: {cmd}")
        try:
            proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, text=True, bufsize=1)
            consume(cfg, db, proc.stdout)
            proc.wait()
            log(f"decoder exited with {proc.returncode}")
        except FileNotFoundError:
            sys.exit(f"Decoder not found: {shlex.split(cmd)[0]}. Install rtl-433 or set [vehicles] command.")
        time.sleep(10)  # SDR unplugged or busy: retry


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("--stdin", action="store_true")
    args = ap.parse_args()
    cfg = watcher.load_cfg()
    db = watcher.db_connect(cfg)
    if args.stdin:
        consume(cfg, db, sys.stdin)
    else:
        run(cfg, db)


if __name__ == "__main__":
    main()
