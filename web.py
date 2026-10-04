#!/usr/bin/env python3
"""Tripline web UI: live dashboard plus device management.

Reads and writes the same SQLite database as watcher.py. Binds to localhost by
default. To expose it on a LAN interface, set [web] bind and [web] password in
config.ini; the app refuses to start on a non-loopback address without a password.
"""
import hmac
import os
import re
import sqlite3
import sys
import time

from flask import Flask, Response, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import watcher  # noqa: E402

app = Flask(__name__)
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_cfg = None


def cfg():
    global _cfg
    if _cfg is None:
        _cfg = watcher.load_cfg()
    return _cfg


def get_db():
    db = watcher.db_connect(cfg())
    db.row_factory = sqlite3.Row
    return db


def thr_for(phy):
    return cfg().getint("detect", "bt_rssi" if watcher.is_bt(phy) else "wifi_rssi")


# ---------- guards ----------

@app.before_request
def guard():
    pw = cfg().get("web", "password", fallback="")
    if pw:
        user = cfg().get("web", "user", fallback="admin")
        a = request.authorization
        ok = (a is not None
              and hmac.compare_digest((a.username or "").encode(), user.encode())
              and hmac.compare_digest((a.password or "").encode(), pw.encode()))
        if not ok:
            return Response("Authentication required", 401,
                            {"WWW-Authenticate": 'Basic realm="Tripline"'})
    # Custom header forces a CORS preflight for cross-site requests, which we never allow.
    if request.method == "POST" and request.headers.get("X-Requested-With") != "tripline":
        return Response("Forbidden", 403)


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
    return resp


# ---------- pages ----------

@app.get("/")
def index():
    with open(os.path.join(HERE, "dashboard.html"), encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")


# ---------- read API ----------

@app.get("/api/state")
def api_state():
    c, db, now = cfg(), get_db(), int(time.time())
    mode = watcher.meta_get(db, "mode", "learning")
    base = int(watcher.meta_get(db, "baseline_max", 0))
    limit = None
    if mode == "home":
        limit = base + c.getint("detect", "random_margin_home")
    elif mode == "away":
        limit = c.getint("detect", "random_margin_away")
    last = db.execute("SELECT MAX(ts) FROM sightings").fetchone()[0]
    quiet = float(watcher.meta_get(db, "quiet_until", 0))
    minutes = db.execute("SELECT COUNT(*) FROM counts").fetchone()[0]
    unknown_now = db.execute(
        "SELECT COUNT(DISTINCT s.mac) FROM sightings s LEFT JOIN devices d ON d.mac=s.mac "
        "WHERE s.ts>=? AND s.rand=0 AND COALESCE(d.known,0)=0", (now - 60,)).fetchone()[0]
    known_now = db.execute(
        "SELECT COUNT(DISTINCT s.mac) FROM sightings s JOIN devices d ON d.mac=s.mac "
        "WHERE s.ts>=? AND s.rand=0 AND d.known=1", (now - 60,)).fetchone()[0]
    alerts24 = db.execute("SELECT COUNT(*) FROM alerts WHERE ts>=?",
                          (now - 86400,)).fetchone()[0]
    la = db.execute("SELECT ts,title,message FROM alerts ORDER BY ts DESC LIMIT 1").fetchone()
    return jsonify({
        "now": now,
        "mode": mode,
        "baseline_max": base,
        "random_limit": limit,
        "random_now": watcher.random_count(db, c, now),
        "unknown_static_now": unknown_now,
        "known_static_now": known_now,
        "last_sighting": last,
        "sensor_ok": bool(last and now - last < 120),
        "quiet_until": quiet if quiet > now else 0,
        "learning_minutes": minutes,
        "learning_target_minutes": 14 * 1440,
        "alerts_24h": alerts24,
        "last_alert": dict(la) if la else None,
        "wifi_floor": c.getint("detect", "wifi_rssi"),
        "bt_floor": c.getint("detect", "bt_rssi"),
    })


@app.get("/api/radar")
def api_radar():
    db, now = get_db(), int(time.time())
    window = max(30, min(int(request.args.get("window", 300)), 3600))
    rows = db.execute("SELECT mac,phy,rssi,ts,rand FROM sightings WHERE ts>=? ORDER BY ts",
                      (now - window,)).fetchall()
    agg = {}
    for r in rows:
        a = agg.setdefault(r["mac"], {"mac": r["mac"], "phy": r["phy"], "rand": r["rand"],
                                      "rs": [], "ts": 0})
        a["rs"].append(r["rssi"])
        a["ts"] = r["ts"]
    meta = {d["mac"]: d for d in db.execute(
        "SELECT mac,manuf,name,known,label,first_seen,seen_count FROM devices "
        "WHERE last_seen>=?", (now - window,))}
    out = []
    for a in agg.values():
        last3 = a["rs"][-3:]
        rssi = round(sum(last3) / len(last3))
        m = meta.get(a["mac"])
        out.append({
            "mac": a["mac"], "phy": a["phy"], "rand": bool(a["rand"]), "rssi": rssi,
            "age": now - a["ts"], "floor": thr_for(a["phy"]),
            "known": bool(m and m["known"]),
            "label": (m["label"] if m else None),
            "manuf": (m["manuf"] if m else None),
            "name": (m["name"] if m else None),
            "first_seen": (m["first_seen"] if m else None),
            "seen_count": (m["seen_count"] if m else None),
        })
    out.sort(key=lambda d: -d["rssi"])
    return jsonify({"now": now, "devices": out[:250]})


@app.get("/api/signals")
def api_signals():
    db, now = get_db(), int(time.time())
    minutes = max(1, min(int(request.args.get("minutes", 10)), 60))
    since = now - minutes * 60
    rows = db.execute("SELECT mac,phy,rssi,ts,rand FROM sightings WHERE ts>=? ORDER BY ts",
                      (since,)).fetchall()
    meta = {d["mac"]: d for d in db.execute(
        "SELECT mac,manuf,name,known,label FROM devices WHERE last_seen>=?", (since,))}
    series = {}
    for r in rows:
        s = series.setdefault(r["mac"], {"mac": r["mac"], "phy": r["phy"],
                                         "rand": bool(r["rand"]), "pts": []})
        s["pts"].append([r["ts"], r["rssi"]])
    out = []
    for s in series.values():
        m = meta.get(s["mac"])
        s.update(known=bool(m and m["known"]), label=(m["label"] if m else None),
                 manuf=(m["manuf"] if m else None), name=(m["name"] if m else None),
                 floor=thr_for(s["phy"]), peak=max(p[1] for p in s["pts"]))
        out.append(s)
    # All static-address devices, plus the strongest rotating ones, to keep the payload small.
    static = [s for s in out if not s["rand"]]
    rand = sorted((s for s in out if s["rand"]), key=lambda s: -s["peak"])[:80]
    return jsonify({"now": now, "start": since, "series": static + rand})


@app.get("/api/activity")
def api_activity():
    db, now = get_db(), int(time.time())
    hours = max(1, min(int(request.args.get("hours", 24)), 168))
    bucket = 600 if hours <= 24 else 3600
    start = (now - hours * 3600) // bucket * bucket
    rows = db.execute(
        "SELECT (s.ts/?)*? AS b, "
        "COUNT(DISTINCT CASE WHEN s.rand=1 THEN s.mac END) AS r, "
        "COUNT(DISTINCT CASE WHEN s.rand=0 AND COALESCE(d.known,0)=0 THEN s.mac END) AS u, "
        "COUNT(DISTINCT CASE WHEN s.rand=0 AND d.known=1 THEN s.mac END) AS k, "
        "MAX(s.rssi) AS mx FROM sightings s LEFT JOIN devices d ON d.mac=s.mac "
        "WHERE s.ts>=? GROUP BY b ORDER BY b", (bucket, bucket, start)).fetchall()
    alerts = [r[0] for r in db.execute("SELECT ts FROM alerts WHERE ts>=? ORDER BY ts", (start,))]
    return jsonify({"bucket": bucket, "start": start, "end": now,
                    "rows": [dict(r) for r in rows], "alerts": alerts})


@app.get("/api/feed")
def api_feed():
    db = get_db()
    limit = max(1, min(int(request.args.get("limit", 40)), 200))
    items = []
    for r in db.execute("SELECT ts,title,message,priority FROM alerts "
                        "ORDER BY ts DESC LIMIT ?", (limit,)):
        items.append({"kind": "alert", "ts": r["ts"], "title": r["title"],
                      "text": r["message"], "priority": r["priority"]})
    for r in db.execute("SELECT mac,phy,manuf,name,first_seen,max_rssi,known FROM devices "
                        "WHERE rand=0 ORDER BY first_seen DESC LIMIT ?", (limit,)):
        items.append({"kind": "new", "ts": r["first_seen"], "mac": r["mac"],
                      "title": "New device " + r["mac"],
                      "text": " ".join(x for x in (r["phy"], r["manuf"], r["name"]) if x)
                              + f" peak {r['max_rssi']} dBm",
                      "known": bool(r["known"])})
    items.sort(key=lambda i: -i["ts"])
    return jsonify({"items": items[:limit]})


@app.get("/api/devices")
def api_devices():
    db = get_db()
    flt = request.args.get("filter", "unknown")
    q = request.args.get("q", "").strip().lower()
    where = {"unknown": "known=0 AND rand=0", "known": "known=1",
             "random": "rand=1", "all": "1=1"}.get(flt, "known=0 AND rand=0")
    sql = ("SELECT mac,phy,manuf,name,rand,known,label,first_seen,last_seen,max_rssi,"
           f"seen_count FROM devices WHERE {where}")
    args = []
    if q:
        sql += " AND (mac LIKE ? OR LOWER(COALESCE(manuf,'')) LIKE ? OR " \
               "LOWER(COALESCE(label,'')) LIKE ? OR LOWER(COALESCE(name,'')) LIKE ?)"
        args = [f"%{q}%"] * 4
    sql += " ORDER BY last_seen DESC LIMIT 300"
    return jsonify({"devices": [dict(r) for r in db.execute(sql, args)]})


@app.get("/api/history/<mac>")
def api_history(mac):
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify({"error": "bad mac"}), 400
    db, now = get_db(), int(time.time())
    minutes = max(5, min(int(request.args.get("minutes", 60)), 1440))
    rows = db.execute("SELECT ts,rssi FROM sightings WHERE mac=? AND ts>=? ORDER BY ts",
                      (mac, now - minutes * 60)).fetchall()
    return jsonify({"mac": mac, "points": [[r["ts"], r["rssi"]] for r in rows]})


# ---------- actions ----------

def body():
    return request.get_json(silent=True) or {}


@app.post("/api/mode")
def api_mode():
    mode = body().get("mode")
    if mode not in ("home", "away", "learning"):
        return jsonify({"error": "mode must be home, away or learning"}), 400
    db = get_db()
    watcher.meta_set(db, "mode", mode)
    if mode == "learning" and not watcher.meta_get(db, "learning_start"):
        watcher.meta_set(db, "learning_start", int(time.time()))
    return jsonify({"ok": True, "mode": mode})


@app.post("/api/arm")
def api_arm():
    peak, minutes = watcher.do_arm(get_db())
    return jsonify({"ok": True, "baseline_max": peak, "baseline_minutes": minutes})


@app.post("/api/guest")
def api_guest():
    hours = body().get("hours")
    db = get_db()
    if hours in (None, 0, "off"):
        watcher.meta_set(db, "quiet_until", 0)
        return jsonify({"ok": True, "quiet_until": 0})
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        return jsonify({"error": "hours must be a number or 'off'"}), 400
    hours = max(0.25, min(hours, 24 * 14))
    until = time.time() + hours * 3600
    watcher.meta_set(db, "quiet_until", until)
    return jsonify({"ok": True, "quiet_until": until})


@app.post("/api/known")
def api_known_add():
    b = body()
    mac = str(b.get("mac", "")).lower()
    label = (str(b.get("label", "")).strip()[:40]) or None
    if not MAC_RE.match(mac):
        return jsonify({"error": "bad mac"}), 400
    now = int(time.time())
    db = get_db()
    db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,label) "
               "VALUES(?,?,0,?,?,0,1,?) ON CONFLICT(mac) DO UPDATE SET known=1, "
               "label=COALESCE(?, label), src=NULL", (mac, "", now, now, label, label))
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/known/delete")
def api_known_del():
    mac = str(body().get("mac", "")).lower()
    if not MAC_RE.match(mac):
        return jsonify({"error": "bad mac"}), 400
    db = get_db()
    db.execute("UPDATE devices SET known=0, label=NULL, src='unmarked' WHERE mac=?", (mac,))
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/known/bulk")
def api_known_bulk():
    macs = [str(m).lower() for m in (body().get("macs") or [])][:500]
    macs = [m for m in macs if MAC_RE.match(m)]
    db = get_db()
    db.executemany("UPDATE devices SET known=1, src=NULL WHERE mac=? AND rand=0", [(m,) for m in macs])
    db.commit()
    return jsonify({"ok": True, "count": len(macs)})


def main():
    c = cfg()
    bind = c.get("web", "bind", fallback="127.0.0.1")
    port = c.getint("web", "port", fallback=8080)
    if bind not in ("127.0.0.1", "localhost", "::1") and not c.get("web", "password", fallback=""):
        sys.exit("Refusing to bind to a non-loopback address without [web] password set.")
    app.run(host=bind, port=port, threaded=True)


if __name__ == "__main__":
    main()
