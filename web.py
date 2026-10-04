#!/usr/bin/env python3
"""Tripline web UI: live dashboard plus device management.

Reads and writes the same SQLite database as watcher.py. Binds to localhost by
default. To expose it on a LAN interface, set [web] bind and [web] password in
config.ini; the app refuses to start on a non-loopback address without a password.
"""
import hmac
import json
import os
import re
import sqlite3
import sys
import time

from flask import Flask, Response, g, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import identity  # noqa: E402
import insight  # noqa: E402
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
    """One connection per request, closed afterwards."""
    if "db" not in g:
        g.db = watcher.db_connect(cfg())
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


_cache = {}


def cached(key, ttl, fn):
    """Small in-process cache for expensive read endpoints. Any POST clears it."""
    hit = _cache.get(key)
    now = time.time()
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _cache[key] = (now, val)
    return val


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
    if request.method == "POST":
        _cache.clear()
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
    hours = max(1, min(int(request.args.get("hours", 24)), 168))
    return jsonify(cached(("activity", hours), 25, lambda: _activity(hours)))


def _activity(hours):
    db, now = get_db(), int(time.time())
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
    return {"bucket": bucket, "start": start, "end": now,
            "rows": [dict(r) for r in rows], "alerts": alerts}


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
    now = int(time.time())
    c = cfg()
    where = {"unknown": "known=0 AND rand=0", "known": "known=1",
             "random": "rand=1", "all": "1=1",
             # the lists behind the dashboard tiles use the same rules as the tile counts
             "unknown_now": "known=0 AND mac IN (SELECT mac FROM sightings WHERE ts>=%d AND rand=0)" % (now - 60),
             "rotating_now": "mac IN (SELECT mac FROM sightings WHERE ts>=%d AND rand=1 AND "
                             "((phy LIKE '%%luetooth%%' AND rssi>=%d) OR (phy NOT LIKE '%%luetooth%%' AND rssi>=%d)))"
                             % (now - c.getint("detect", "random_window_seconds"),
                                c.getint("detect", "bt_rssi"), c.getint("detect", "wifi_rssi")),
             }.get(flt, "known=0 AND rand=0")
    sql = ("SELECT mac,phy,manuf,name,rand,known,label,first_seen,last_seen,max_rssi,"
           "seen_count,(SELECT COUNT(*) FROM probes p WHERE p.mac=devices.mac) AS probe_count,"
           "(SELECT group_concat(ssid, char(10)) FROM (SELECT ssid FROM probes p WHERE p.mac=devices.mac "
           "ORDER BY last_seen DESC LIMIT 6)) AS probe_list,"
           "(SELECT entity_id FROM entity_members m WHERE m.kind='device' AND m.ref=devices.mac) AS entity_id,"
           "EXISTS(SELECT 1 FROM networks n WHERE n.bssid=devices.mac) AS is_network "
           f"FROM devices WHERE {where}")
    args = []
    radio = request.args.get("radio", "")
    if radio == "wifi":
        sql += " AND phy LIKE '%802.11%'"
    elif radio == "bt":
        sql += " AND (LOWER(phy) LIKE '%bluetooth%' OR LOWER(phy) LIKE '%btle%')"
    if q:
        sql += " AND (mac LIKE ? OR LOWER(COALESCE(manuf,'')) LIKE ? OR " \
               "LOWER(COALESCE(label,'')) LIKE ? OR LOWER(COALESCE(name,'')) LIKE ?)"
        args = [f"%{q}%"] * 4
    col = {"last_seen": "last_seen", "first_seen": "first_seen", "rssi": "max_rssi", "seen": "seen_count",
           "name": "LOWER(COALESCE(NULLIF(label,''), NULLIF(name,''), manuf, ''))",
           "mac": "mac"}.get(request.args.get("sort", ""), "last_seen")
    direction = "ASC" if request.args.get("dir") == "asc" else "DESC"
    sql += f" ORDER BY {col} {direction}, mac LIMIT 300"
    return jsonify({"devices": [dict(r) for r in db.execute(sql, args)]})


@app.get("/api/alerts")
def api_alerts():
    hours = max(1, min(int(request.args.get("hours", 24)), 720))
    rows = get_db().execute("SELECT ts,title,message,priority FROM alerts WHERE ts>=? ORDER BY ts DESC LIMIT 200",
                            (int(time.time()) - hours * 3600,)).fetchall()
    return jsonify({"alerts": [dict(r) for r in rows]})


@app.get("/api/device/<mac>")
def api_device(mac):
    """Everything known about one device, for the detail panel."""
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify({"error": "bad mac"}), 400
    db, now = get_db(), int(time.time())
    d = db.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
    if d is None:
        return jsonify({"error": "unknown device"}), 404
    out = {k: d[k] for k in d.keys()}
    out["probes"] = [dict(r) for r in db.execute(
        "SELECT ssid,first_seen,last_seen FROM probes WHERE mac=? ORDER BY last_seen DESC LIMIT 100", (mac,))]
    ap = None
    if d["bssid"]:
        net = db.execute("SELECT label FROM networks WHERE bssid=?", (d["bssid"],)).fetchone()
        apd = db.execute("SELECT manuf,name,label FROM devices WHERE mac=?", (d["bssid"],)).fetchone()
        home = watcher.home_set(cfg(), db)
        ap = {"bssid": d["bssid"], "mine": watcher.in_home(d["bssid"], home),
              "listed": bool(net), "label": (net[0] if net else None) or (apd["label"] if apd else None),
              "manuf": apd["manuf"] if apd else None, "name": apd["name"] if apd else None}
    out["ap"] = ap
    ex = insight.load_extra(d["extra"])
    out["extra"] = ex
    if watcher.is_bt(d["phy"]):
        out["address_kind"] = insight.address_kind(mac, bool(d["manuf"]) and d["manuf"].lower() != "unknown")
    if ex.get("clients"):
        names = {}
        for c in ex["clients"]:
            r = db.execute("SELECT label,name,manuf,known FROM devices WHERE mac=?", (c,)).fetchone()
            names[c] = {"title": (r["label"] or r["name"] or r["manuf"]) if r else None, "known": bool(r["known"]) if r else None}
        out["client_names"] = names
    ent = db.execute("SELECT e.id,e.name,e.kind,e.known FROM entity_members m JOIN entities e ON e.id=m.entity_id "
                     "WHERE m.kind='device' AND m.ref=?", (mac,)).fetchone()
    out["entity"] = dict(ent) if ent else None
    hrs = [0] * 24
    for b, n in db.execute("SELECT CAST((?-ts)/3600 AS INTEGER), COUNT(*) FROM sightings "
                           "WHERE mac=? AND ts>=? GROUP BY 1", (now, mac, now - 86400)):
        if 0 <= b < 24:
            hrs[b] = n
    out["hourly"] = hrs[::-1]   # oldest first
    r = db.execute("SELECT COUNT(*), AVG(rssi), MAX(rssi), MIN(rssi) FROM sightings WHERE mac=? AND ts>=?",
                   (mac, now - 3600)).fetchone()
    out["hour"] = {"sightings": r[0], "avg_rssi": round(r[1]) if r[1] is not None else None,
                   "max_rssi": r[2], "min_rssi": r[3]}
    out["alerts"] = [dict(a) for a in db.execute(
        "SELECT ts,title,message FROM alerts WHERE message LIKE ? OR title LIKE ? ORDER BY ts DESC LIMIT 5",
        (f"%{mac}%", f"%{mac}%"))]
    out["now"] = now
    if d["fp"]:
        n_addr, first, last = db.execute("SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM devices WHERE fp=?",
                                         (d["fp"],)).fetchone()
        fpv = insight.fingerprint(ex)
        member = db.execute("SELECT e.name FROM entity_members m JOIN entities e ON e.id=m.entity_id "
                            "WHERE m.kind='fingerprint' AND m.ref=?", (d["fp"],)).fetchone()
        out["fingerprint"] = {"id": d["fp"], "addresses": n_addr, "first_seen": first, "last_seen": last,
                              "describe": insight.describe_fingerprint(fpv[2]) if fpv else None,
                              "entity": member[0] if member else None}
    out.update(_device_extras(db, mac, now))
    return jsonify(out)


def _device_extras(db, mac, now):
    """Derived facts about one device: address analysis, sessions, days seen, who it is seen with."""
    try:
        first = int(mac.split(":")[0], 16)
    except ValueError:
        first = 0
    addr = {"locally_administered": bool(first & 2), "multicast": bool(first & 1),
            "oui": mac[:8].upper()}
    # Sessions: runs of sightings with no gap over 5 minutes, last 24 h.
    sessions, cur = [], None
    for ts, rssi in db.execute("SELECT ts,rssi FROM sightings WHERE mac=? AND ts>=? ORDER BY ts", (mac, now - 86400)):
        if cur and ts - cur["end"] <= 300:
            cur["end"] = ts
            cur["n"] += 1
            cur["sum"] += rssi
            cur["peak"] = max(cur["peak"], rssi)
        else:
            if cur:
                sessions.append(cur)
            cur = {"start": ts, "end": ts, "n": 1, "sum": rssi, "peak": rssi}
    if cur:
        sessions.append(cur)
    off0 = time.localtime().tm_gmtoff
    pts = [[r[0], r[1]] for r in db.execute("SELECT ts,rssi FROM sightings WHERE mac=? AND ts>=? ORDER BY ts",
                                            (mac, now - 600))]
    recent = pts[-1][1] if pts else None
    phy = (db.execute("SELECT phy FROM devices WHERE mac=?", (mac,)).fetchone() or [""])[0]
    out = {"address": addr, "typical": insight.typical_hours(db, mac, now, off0),
           "trend": insight.trend(pts), "distance": insight.distance(recent, phy),
           "sessions": [{"start": x["start"], "end": x["end"], "sightings": x["n"],
                         "avg_rssi": round(x["sum"] / x["n"]), "peak_rssi": x["peak"]}
                        for x in sessions[-12:][::-1]]}
    off = time.localtime().tm_gmtoff
    days = {(ts + off) // 86400 for (ts,) in db.execute(
        "SELECT ts FROM sightings WHERE mac=? AND ts>=? GROUP BY ts/600", (mac, now - 14 * 86400))}
    today = (now + off) // 86400
    out["days_seen"] = [today - d for d in sorted(days, reverse=True) if today - d < 14]
    # Seen together: other devices that share its 5-minute windows, ranked by overlap (Jaccard).
    ref = "device:" + mac
    mine = db.execute("SELECT COUNT(*) FROM presence WHERE ref=?", (ref,)).fetchone()[0]
    together = []
    if mine:
        cand = db.execute(
            "SELECT p2.ref, COUNT(*) FROM presence p1 JOIN presence p2 ON p2.bucket=p1.bucket AND p2.ref!=p1.ref "
            "WHERE p1.ref=? GROUP BY p2.ref HAVING COUNT(*)>=2 ORDER BY COUNT(*) DESC LIMIT 40", (ref,)).fetchall()
        for r, n in cand:
            theirs = db.execute("SELECT COUNT(*) FROM presence WHERE ref=?", (r,)).fetchone()[0]
            together.append((n / float(mine + theirs - n), r, n, theirs))
        together.sort(reverse=True)
    rows = []
    for score, r, n, theirs in together[:8]:
        item = {"ref": r, "together": n, "of_theirs": theirs, "of_mine": mine}
        if r.startswith("device:"):
            d = db.execute("SELECT mac,phy,manuf,name,label,known,rand FROM devices WHERE mac=?", (r[7:],)).fetchone()
            if d:
                item.update(mac=d["mac"], title=d["label"] or d["name"] or d["manuf"] or d["mac"],
                            known=bool(d["known"]), rand=bool(d["rand"]), phy=d["phy"])
        else:
            item["title"] = r
        rows.append(item)
    out["seen_with"] = rows
    return out


def _pick(d, *path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


@app.get("/api/device/<mac>/live")
def api_device_live(mac):
    """The raw record Kismet holds right now, plus a few commonly useful fields pulled out of it."""
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify({"error": "bad mac"}), 400
    try:
        data = watcher.kismet_get(cfg(), "/devices/by-mac/%s/devices.json" % mac)
    except Exception as exc:
        return jsonify({"error": "Kismet did not answer: %s" % exc}), 502
    rec = data[0] if isinstance(data, list) and data else data if isinstance(data, dict) else None
    if not rec:
        return jsonify({"error": "Kismet has no record of this address"}), 404
    b, dot = "kismet.device.base.", rec.get("dot11.device") or {}
    adv = _pick(dot, "dot11.device.last_beaconed_ssid_record") or {}
    summary = {
        "Kismet type": rec.get(b + "type"), "Common name": rec.get(b + "commonname"),
        "Channel": rec.get(b + "channel"), "Frequency (kHz)": rec.get(b + "frequency"),
        "Packets": _pick(rec, b + "packets.total"), "Data bytes": rec.get(b + "datasize"),
        "Advertised SSID": adv.get("dot11.advertisedssid.ssid") if isinstance(adv, dict) else None,
        "Encryption": adv.get("dot11.advertisedssid.crypt_string") if isinstance(adv, dict) else None,
        "Clients associated": len(dot["dot11.device.associated_client_map"])
        if isinstance(dot.get("dot11.device.associated_client_map"), dict) else None,
        "Last BSSID": dot.get("dot11.device.last_bssid"),
        "Probed names": len(dot["dot11.device.probed_ssid_map"])
        if isinstance(dot.get("dot11.device.probed_ssid_map"), (dict, list)) else None,
        "First seen (Kismet)": rec.get(b + "first_time"), "Last seen (Kismet)": rec.get(b + "last_time"),
    }
    summary = {k: v for k, v in summary.items() if v not in (None, "", 0)}
    raw = json.dumps(rec, indent=1, default=str)
    return jsonify({"summary": summary, "groups": insight.interesting(rec),
                    "raw": raw[:200000], "truncated": len(raw) > 200000})


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


@app.get("/api/networks")
def api_networks():
    db = get_db()
    rows = db.execute("SELECT n.bssid, n.label, n.added, d.last_seen, d.manuf FROM networks n "
                      "LEFT JOIN devices d ON d.mac = n.bssid ORDER BY n.added DESC").fetchall()
    cfg_list = sorted(m.strip().lower() for m in cfg().get("detect", "home_bssids", fallback="").split(",")
                      if m.strip())
    return jsonify({"networks": [dict(r) for r in rows], "from_config": cfg_list})


@app.post("/api/networks")
def api_networks_add():
    b = body()
    bssid = str(b.get("bssid", "")).strip().lower().replace("-", ":")
    label = (str(b.get("label", "")).strip()[:40]) or None
    if not MAC_RE.match(bssid):
        return jsonify({"error": "bad bssid"}), 400
    now = int(time.time())
    db = get_db()
    db.execute("INSERT INTO networks(bssid,label,added) VALUES(?,?,?) "
               "ON CONFLICT(bssid) DO UPDATE SET label=COALESCE(excluded.label, label)", (bssid, label, now))
    # The beaconing device itself is yours too.
    db.execute("INSERT INTO devices(mac,phy,rand,first_seen,last_seen,max_rssi,known,label) "
               "VALUES(?,?,0,?,?,0,1,?) ON CONFLICT(mac) DO UPDATE SET known=1, src=NULL, "
               "label=COALESCE(label, ?)", (bssid, "IEEE802.11", now, now, label, label))
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/networks/delete")
def api_networks_del():
    bssid = str(body().get("bssid", "")).strip().lower()
    if not MAC_RE.match(bssid):
        return jsonify({"error": "bad bssid"}), 400
    db = get_db()
    db.execute("DELETE FROM networks WHERE bssid=?", (bssid,))
    # Adding it as a network is what made the device known, so removing it undoes that.
    db.execute("UPDATE devices SET known=0, src='unmarked' WHERE mac=?", (bssid,))
    db.commit()
    return jsonify({"ok": True})


def _entity_args(b):
    return dict(name=b.get("name"), kind=b.get("kind") or "household",
                expires_days=b.get("expires_days") or None)


@app.get("/api/entities")
def api_entities():
    db, now = get_db(), int(time.time())
    ents = identity.entity_view(db)
    off = time.localtime().tm_gmtoff
    for e in ents:
        mem = []
        for m in e["members"]:
            if m["kind"] == "fingerprint":   # every address that carried this fingerprint
                mem += [("device", r[0]) for r in db.execute("SELECT mac FROM devices WHERE fp=?", (m["ref"],))]
            else:
                mem.append((m["kind"], m["ref"]))
        e["pattern"] = insight.entity_pattern(db, mem, now, off)
    return jsonify({"entities": ents, "kinds": list(identity.ENTITY_KINDS)})


@app.post("/api/entities")
def api_entities_create():
    b = body()
    try:
        eid = identity.create_entity(get_db(), known=bool(b.get("known", True)), **_entity_args(b))
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "id": eid})


@app.post("/api/entities/member")
def api_entities_member():
    b = body()
    db = get_db()
    try:
        eid = b.get("entity_id")
        if eid in (None, "", "new"):
            new = b.get("new") or {}
            eid = identity.create_entity(db, known=bool(new.get("known", True)), **_entity_args(new))
        identity.add_member(db, int(eid), str(b.get("kind")), str(b.get("ref")))
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except KeyError as exc:
        return jsonify({"error": str(exc.args[0])}), 404
    return jsonify({"ok": True, "id": int(eid)})


@app.post("/api/entities/member/delete")
def api_entities_member_del():
    b = body()
    identity.remove_member(get_db(), str(b.get("kind")), str(b.get("ref")))
    return jsonify({"ok": True})


@app.post("/api/entities/delete")
def api_entities_delete():
    try:
        identity.delete_entity(get_db(), int(body().get("id")))
    except (TypeError, ValueError):
        return jsonify({"error": "bad id"}), 400
    return jsonify({"ok": True})


@app.get("/api/suggestions")
def api_suggestions():
    return jsonify(cached("suggestions", 120, _suggestions))


def _suggestions():
    db = get_db()
    out = identity.suggestions(db, cfg())
    for s in out:
        for m in s["members"]:
            if m["kind"] == "fingerprint":
                continue
            if m["kind"] == "device":
                r = db.execute("SELECT label,manuf,name,phy,last_seen FROM devices WHERE mac=?", (m["ref"],)).fetchone()
                m["title"] = (r[0] or r[2] or r[1] or m["ref"]) if r else m["ref"]
                m["phy"], m["last_seen"] = (r[3], r[4]) if r else ("", None)
            else:
                r = db.execute("SELECT label,model,last_seen FROM vehicles WHERE vid=?", (m["ref"],)).fetchone()
                m["title"] = (r[0] or r[1] or m["ref"]) if r else m["ref"]
                m["phy"], m["last_seen"] = "TPMS", (r[2] if r else None)
    return {"suggestions": out}


def _members(b, minimum=2):
    members = b.get("members") or [b.get("a"), b.get("b")]
    if (not isinstance(members, list) or len(members) < minimum or len(members) > 20
            or not all(isinstance(m, dict) and "kind" in m and "ref" in m for m in members)):
        raise ValueError("members must be objects with kind and ref")
    return [{"kind": str(m["kind"]), "ref": str(m["ref"])} for m in members]


@app.post("/api/suggestions/accept")
def api_suggestions_accept():
    b = body()
    try:
        fps = [m for m in (b.get("members") or []) if isinstance(m, dict) and m.get("kind") == "fingerprint"]
        if len(fps) == 1 and len(b["members"]) == 1:
            eid = identity.link_fingerprint(get_db(), str(fps[0].get("ref")), b.get("entity_id"), **_entity_args(b))
        elif b.get("entity_id") is not None:
            eid = identity.add_to_entity(get_db(), int(b["entity_id"]), _members(b, 1))
        else:
            eid = identity.link_group(get_db(), _members(b), **_entity_args(b))
    except KeyError as exc:
        return jsonify({"error": str(exc.args[0])}), 404
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "id": eid})


@app.post("/api/suggestions/dismiss")
def api_suggestions_dismiss():
    b = body()
    try:
        if b.get("entity_id") is not None:
            identity.dismiss_from_entity(get_db(), int(b["entity_id"]), _members(b, 1))
        else:
            identity.dismiss_group(get_db(), _members(b))
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.post("/api/reset")
def api_reset():
    b = body()
    if b.get("confirm") != "RESET":
        return jsonify({"error": 'send {"confirm": "RESET"}'}), 400
    n = watcher.reset_db(get_db(), bool(b.get("everything")))
    return jsonify({"ok": True, "removed": n})


@app.get("/api/ssids")
def api_ssids():
    db = get_db()
    rows = [r[0] for r in db.execute("SELECT ssid FROM home_ssids ORDER BY added DESC")]
    cfg_list = [s.strip() for s in cfg().get("detect", "home_ssids", fallback="").split(",") if s.strip()]
    return jsonify({"ssids": rows, "from_config": cfg_list})


@app.post("/api/ssids")
def api_ssids_add():
    ssid = identity.clean_ssid(str(body().get("ssid", "")))
    if not ssid:
        return jsonify({"error": "bad ssid"}), 400
    db = get_db()
    db.execute("INSERT OR IGNORE INTO home_ssids(ssid,added) VALUES(?,?)", (ssid, int(time.time())))
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/ssids/delete")
def api_ssids_del():
    db = get_db()
    db.execute("DELETE FROM home_ssids WHERE ssid=?", (str(body().get("ssid", "")),))
    db.commit()
    return jsonify({"ok": True})


@app.get("/api/vehicles")
def api_vehicles():
    db = get_db()
    rows = db.execute("SELECT vid,model,sensor_id,first_seen,last_seen,seen_count,known,label,last_rssi,"
                      "last_freq FROM vehicles ORDER BY last_seen DESC LIMIT 200").fetchall()
    return jsonify({"enabled": cfg().getboolean("vehicles", "enabled", fallback=False),
                    "vehicles": [dict(r) for r in rows]})


@app.post("/api/vehicles/known")
def api_vehicles_known():
    b = body()
    vid = str(b.get("vid", ""))[:100]
    known = 1 if b.get("known", True) else 0
    label = (str(b.get("label", "")).strip()[:40]) or None
    db = get_db()
    cur = db.execute("UPDATE vehicles SET known=?, label=? WHERE vid=?",
                     (known, label if known else None, vid))
    db.commit()
    if not cur.rowcount:
        return jsonify({"error": "unknown vehicle"}), 404
    return jsonify({"ok": True})


def main():
    c = cfg()
    bind = c.get("web", "bind", fallback="127.0.0.1")
    port = c.getint("web", "port", fallback=8080)
    if bind not in ("127.0.0.1", "localhost", "::1") and not c.get("web", "password", fallback=""):
        sys.exit("Refusing to bind to a non-loopback address without [web] password set.")
    app.run(host=bind, port=port, threaded=True)


if __name__ == "__main__":
    main()
