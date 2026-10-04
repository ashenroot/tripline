"""Derived facts about devices and entities, and tolerant readers for Kismet records.

Nothing here talks to the network. Kismet field names differ between versions, so the readers search
a record for keys by name fragment instead of assuming one fixed layout.
"""
import json
import math
import time

# Extra fields polled from Kismet [path, alias]. Unknown paths come back empty, which is harmless.
EXTRA_FIELDS = [
    ["kismet.device.base.type", "type"],
    ["kismet.device.base.channel", "channel"],
    ["kismet.device.base.frequency", "freq"],
    ["dot11.device/dot11.device.probe_fingerprint", "fp_probe"],
    ["dot11.device/dot11.device.beacon_fingerprint", "fp_beacon"],
    ["dot11.device/dot11.device.response_fingerprint", "fp_resp"],
    ["dot11.device/dot11.device.advertised_ssid_map", "ap_ssids"],
    ["dot11.device/dot11.device.associated_client_map", "clients"],
    ["dot11.device/dot11.device.bss_timestamp", "bss_ts"],
]

_SSID_KEYS = {"ssid": "dot11.advertisedssid.ssid", "crypt": "dot11.advertisedssid.crypt_string",
              "channel": "dot11.advertisedssid.channel", "beacon_rate": "dot11.advertisedssid.beaconrate",
              "wps_manuf": "dot11.advertisedssid.wps_manuf", "wps_model": "dot11.advertisedssid.wps_model_name",
              "country": "dot11.advertisedssid.dot11d_country"}


def harvest(d):
    """Stable facts from one polled Kismet record, as a small JSON-able dict (counters are not kept)."""
    out = {}
    for k in ("type", "freq"):
        v = d.get(k)
        if v not in (None, "", 0):
            out[k] = v
    ch = d.get("channel")
    if ch not in (None, "", 0):
        out["channels"] = [str(ch)]
    for k in ("fp_probe", "fp_beacon", "fp_resp"):
        v = d.get(k)
        if v not in (None, "", 0):
            out[k] = v
    ap = d.get("ap_ssids")
    if isinstance(ap, dict) and ap:
        rows = []
        for rec in list(ap.values())[:12]:
            if isinstance(rec, dict):
                row = {n: rec.get(p) for n, p in _SSID_KEYS.items() if rec.get(p) not in (None, "")}
                if row:
                    rows.append(row)
        if rows:
            out["ssids"] = rows
    cl = d.get("clients")
    if isinstance(cl, dict) and cl:
        out["clients"] = sorted(str(m).lower() for m in cl)[:80]
    ts = d.get("bss_ts")
    if isinstance(ts, (int, float)) and ts > 0:
        out["uptime_s"] = int(ts / 1e6)
    return out


def merge_extra(old, new):
    """Fold a fresh harvest into what is stored: channels accumulate, everything else is replaced."""
    merged = dict(old)
    for k, v in new.items():
        if k == "channels":
            merged[k] = sorted(set(old.get(k, [])) | set(v))
        elif k == "uptime_s":
            merged[k] = v if v < old.get(k, 0) else max(v, old.get(k, 0))  # keep latest reading
        else:
            merged[k] = v
    return merged


def load_extra(raw):
    try:
        v = json.loads(raw) if raw else {}
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


# ---------------------------------------------------------------- computed facts

def typical_hours(db, mac, now, tz_offset):
    """Sightings by local hour of day over everything kept, and whether this hour is unusual."""
    hist = [0] * 24
    days = set()
    for ts, n in db.execute("SELECT ts/600*600, COUNT(*) FROM sightings WHERE mac=? GROUP BY 1", (mac,)):
        local = ts + tz_offset
        hist[(local // 3600) % 24] += 1
        days.add(local // 86400)
    total = sum(hist)
    here = ((now + tz_offset) // 3600) % 24
    unusual = None
    if total >= 30 and len(days) >= 3:
        unusual = hist[here] / float(total) < 0.03
    return {"hours": hist, "days": len(days), "now_hour": here, "unusual_now": unusual}


def trend(points):
    """Signal trend over recent [ts, rssi] points: slope in dB per minute and a plain label."""
    pts = [p for p in points if p[1]]
    if len(pts) < 4 or pts[-1][0] - pts[0][0] < 60:
        return {"slope": None, "label": "not enough recent data"}
    t0 = pts[0][0]
    xs = [(p[0] - t0) / 60.0 for p in pts]
    ys = [p[1] for p in pts]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else 0.0
    label = "getting closer" if slope >= 1.0 else "moving away" if slope <= -1.0 else "steady"
    return {"slope": round(slope, 1), "label": label}


def distance(rssi, phy):
    """Very rough range from signal strength (log-distance model). Walls and antennas change it a lot."""
    if not rssi:
        return None
    ref = -59 if "luetooth" in (phy or "") else -40      # expected dBm at 1 m
    d = 10 ** ((ref - rssi) / (10 * 2.7))
    for hi, label in ((3, "under 3 m"), (10, "about 3 to 10 m"), (30, "about 10 to 30 m"),
                      (100, "about 30 to 100 m")):
        if d < hi:
            return label
    return "over 100 m"


def entity_pattern(db, members, now, tz_offset, bucket=300, days=14):
    """Arrivals and dwell for an entity: windows where any member was heard, joined into visits."""
    refs = [("device:" if k == "device" else "vehicle:") + r for k, r in members]
    if not refs:
        return None
    since = (now - days * 86400) // bucket
    marks = ",".join("?" * len(refs))
    buckets = [r[0] for r in db.execute(
        "SELECT DISTINCT bucket FROM presence WHERE ref IN (%s) AND bucket>=? ORDER BY bucket" % marks,
        refs + [since])]
    visits, cur = [], None
    for b in buckets:
        if cur and b - cur[1] <= 3:      # a gap of up to 15 minutes stays one visit
            cur[1] = b
        else:
            if cur:
                visits.append(cur)
            cur = [b, b]
    if cur:
        visits.append(cur)
    hours = [0] * 24
    for s, _ in visits:
        hours[((s * bucket + tz_offset) // 3600) % 24] += 1
    dur = [(e - s + 1) * bucket / 60.0 for s, e in visits]
    return {"visits": len(visits), "hours": hours,
            "avg_minutes": round(sum(dur) / len(dur)) if dur else None,
            "last_arrival": visits[-1][0] * bucket if visits else None,
            "last_departure": (visits[-1][1] + 1) * bucket if visits else None,
            "days": days}


# ---------------------------------------------------------------- tolerant record reader

def _flatten(node, path="", out=None, depth=0):
    out = {} if out is None else out
    if depth > 6:
        return out
    if isinstance(node, dict):
        for k, v in node.items():
            _flatten(v, path + "/" + str(k) if path else str(k), out, depth + 1)
    elif isinstance(node, list):
        if node and all(not isinstance(x, (dict, list)) for x in node):
            out[path] = node
        else:
            for i, v in enumerate(node[:20]):
                _flatten(v, "%s[%d]" % (path, i), out, depth + 1)
    else:
        out[path] = node
    return out


GROUPS = [
    ("Capabilities", ("ht_mode", "ht_capab", "vht_capab", "he_capab", "maxrate", "max_rate", "supported_rate",
                      "dot11d_country", "chanwidth", "channel_width", "mcs", "streams")),
    ("WPS", ("wps_manuf", "wps_model", "wps_device_name", "wps_serial")),
    ("Traffic", ("packets.total", "packets.data", "packets.error", "packets.llc", "datasize", "num_retries",
                 "num_fragments")),
    ("Bluetooth", ("uuid", "address_type", "addr_type", "txpower", "tx_power", "company", "manufacturer",
                   "device_class", "appearance", "service_data", "connectable", "bt_device", "bdaddr")),
]


def interesting(rec, limit=60):
    """Pick the fields of a raw Kismet record that help identify a device, grouped by purpose."""
    flat = _flatten(rec)
    out = {}
    for group, frags in GROUPS:
        rows = []
        for path, v in flat.items():
            low = path.lower()
            if any(f in low for f in frags) and v not in (None, "", [], 0, "0"):
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v[:10])
                leaf = path.split("/")[-1].replace("dot11.device.", "").replace("kismet.device.base.", "")
                rows.append((leaf[:80], str(v)[:160]))
        if rows:
            out[group] = rows[:limit]
    seen = flat.get("kismet.device.base.seenby")
    n_sources = sum(1 for p in flat if p.startswith("kismet.device.base.seenby[") and p.endswith(".kismet.common.seenby.uuid"))
    if n_sources:
        out.setdefault("Capture", []).append(("Heard by capture sources", str(n_sources)))
    return out
