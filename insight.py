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
    ["bluetooth.device/bluetooth.device.major_class", "bt_major"],
    ["bluetooth.device/bluetooth.device.minor_class", "bt_minor"],
    ["bluetooth.device/bluetooth.device.txpower", "bt_tx"],
    ["bluetooth.device/bluetooth.device.type", "bt_type"],
    ["bluetooth.device/bluetooth.device.service_uuid_vec", "bt_uuids"],
    ["bluetooth.device/bluetooth.device.scan_data_bytes", "bt_adv"],
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
    bt = bt_facts(d.get("bt_major"), d.get("bt_minor"), d.get("bt_tx"), d.get("bt_type"),
                  d.get("bt_uuids"), d.get("bt_adv"))
    if bt:
        out["bt"] = bt
    ts = d.get("bss_ts")
    if isinstance(ts, (int, float)) and ts > 0:
        out["uptime_s"] = int(ts / 1e6)
    return out


# ---------------------------------------------------------------- Bluetooth

MAJOR_CLASS = {1: "computer", 2: "phone", 3: "network access point", 4: "audio or video", 5: "peripheral",
               6: "imaging", 7: "wearable", 8: "toy", 9: "health device", 31: "uncategorized"}
SERVICES = {"1800": "Generic Access", "1801": "Generic Attribute", "1802": "Immediate Alert", "1803": "Link Loss",
            "1804": "TX Power", "1805": "Current Time", "1809": "Health Thermometer", "180a": "Device Information",
            "180d": "Heart Rate", "180f": "Battery", "1810": "Blood Pressure", "1812": "Human Interface (keyboard, mouse)",
            "1814": "Running Speed", "1816": "Cycling Speed", "1818": "Cycling Power", "181a": "Environmental Sensing",
            "181c": "User Data", "181d": "Weight Scale", "1822": "Pulse Oximeter", "fd6f": "Exposure Notification",
            "feaa": "Eddystone beacon", "fe9f": "Google", "fe2c": "Google Fast Pair", "fd5a": "Samsung SmartTag",
            "feec": "Tile tracker", "feed": "Tile tracker", "fe07": "Sonos", "fe03": "Amazon"}
COMPANIES = {0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google", 0x0087: "Garmin",
             0x0059: "Nordic Semiconductor", 0x0171: "Amazon", 0x012D: "Sony", 0x009E: "Bose", 0x038F: "Xiaomi"}
APPLE_TYPES = {0x02: "iBeacon", 0x05: "AirDrop", 0x07: "AirPods or Beats pairing", 0x09: "AirPlay target",
               0x0A: "AirPlay source", 0x0C: "Handoff", 0x0D: "Tethering target", 0x0E: "Tethering source",
               0x0F: "Nearby action", 0x10: "Nearby info (iPhone, iPad, Mac or Watch)", 0x12: "Find My (AirTag or accessory)"}


def _to_bytes(v):
    """Raw advertisement bytes from a list of ints, a hex string or base64, whichever Kismet sent."""
    import base64
    import binascii
    try:
        if isinstance(v, list) and v and all(isinstance(x, int) and 0 <= x < 256 for x in v):
            return bytes(v)
        if isinstance(v, str) and v:
            t = v.replace(":", "").replace(" ", "")
            if len(t) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in t):
                return bytes.fromhex(t)
            return base64.b64decode(v, validate=True)
    except (ValueError, binascii.Error):
        return None
    return None


def parse_adv(raw):
    """Walk the advertisement's length/type/value records; None if the bytes do not parse."""
    b = _to_bytes(raw)
    if not b:
        return None
    out, i = {}, 0
    while i < len(b):
        n = b[i]
        if n == 0:
            break
        if i + 1 + n > len(b):
            return out or None
        t, val = b[i + 1], b[i + 2:i + 1 + n]
        if t in (0x08, 0x09):
            out["name"] = val.decode("utf-8", "replace")[:40]
        elif t == 0xFF and len(val) >= 2:
            cid = val[0] | (val[1] << 8)
            out["company_id"] = cid
            if cid == 0x004C and len(val) >= 3:
                out["apple_type"] = val[2]
        i += 1 + n
    return out or None


def bt_facts(major, minor, tx, btype, uuids, adv):
    """The Bluetooth identity facts worth keeping, from Kismet's bluetooth.device fields."""
    out = {}
    if isinstance(major, int) and major:
        out["class"] = MAJOR_CLASS.get(major, "class %d" % major)
    elif isinstance(major, str) and major and major.lower() not in ("0", "unknown", "miscellaneous"):
        out["class"] = major
    if isinstance(minor, str) and minor and minor.lower() not in ("0", "unknown"):
        out["subclass"] = minor
    if isinstance(tx, (int, float)) and tx not in (0, -127, 127):
        out["tx_dbm"] = tx
    if isinstance(btype, str) and btype:
        out["type"] = btype
    if isinstance(uuids, list) and uuids:
        names = []
        for u in uuids[:12]:
            u = str(u).lower()
            short = u[4:8] if len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb") else u[-4:] if len(u) <= 4 else u
            names.append(SERVICES.get(short, u))
        out["services"] = names
    a = parse_adv(adv)
    if a:
        if "name" in a:
            out["adv_name"] = a["name"]
        if "company_id" in a:
            out["company"] = COMPANIES.get(a["company_id"], "company id 0x%04x" % a["company_id"])
        if "apple_type" in a:
            out["apple_message"] = APPLE_TYPES.get(a["apple_type"], "type 0x%02x" % a["apple_type"])
    return out


def address_kind(mac, vendor_known):
    """Bluetooth address class from the top two bits (Core spec): only meaningful for random addresses."""
    try:
        top = int(mac.split(":")[0], 16) >> 6
    except ValueError:
        return None
    if vendor_known:
        return "public (assigned to a vendor)"
    return {3: "static random (stable until the device restarts)", 1: "resolvable private (rotates, typical of phones and wearables)",
            0: "non-resolvable private (rotates)", 2: "reserved or public with an unknown vendor"}[top]


def fingerprint(extra, phy=""):
    """A device-level fingerprint from stable advertisement facts, for recognising a rotating address.

    Returns (id, richness, parts) or None. Richness counts the distinguishing facts used: a name or a
    service list narrows it a lot, a bare manufacturer does not. Wi-Fi probe fingerprints identify a
    hardware and driver combination, so they score low.
    """
    import hashlib
    parts = {}
    bt = extra.get("bt") or {}
    for k in ("class", "subclass", "company", "apple_message", "adv_name", "type"):
        if bt.get(k):
            parts[k] = bt[k]
    if bt.get("services"):
        parts["services"] = sorted(bt["services"])
    if isinstance(bt.get("tx_dbm"), (int, float)):
        parts["tx_dbm"] = bt["tx_dbm"]
    if not parts and extra.get("fp_probe"):
        parts["wifi_probe"] = extra["fp_probe"]
    if not parts:
        return None
    richness = len(parts)
    digest = hashlib.sha1(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:12]
    return digest, richness, parts


def describe_fingerprint(parts):
    bits = []
    if parts.get("adv_name"):
        bits.append('named "%s"' % parts["adv_name"])
    if parts.get("class"):
        bits.append(parts["class"])
    if parts.get("company"):
        bits.append(parts["company"] + (" " + parts["apple_message"] if parts.get("apple_message") else ""))
    if parts.get("services"):
        bits.append("services " + ", ".join(parts["services"][:4]))
    if parts.get("wifi_probe"):
        bits.append("Wi-Fi probe fingerprint %s" % parts["wifi_probe"])
    return "; ".join(bits) or "unlabelled device"


def max_concurrency(intervals, tolerance=45):
    """Largest number of lifetimes that overlap. Each lifetime is trimmed at both ends first, so the
    seconds where an old and a new address of one device briefly coexist do not count."""
    events = []
    for a, b in intervals:
        a2, b2 = a + tolerance, b - tolerance
        if b2 < a2:
            a2 = b2 = (a + b) / 2.0
            events.append((a2, 1))
            events.append((b2 + 0.001, -1))
        else:
            events.append((a2, 1))
            events.append((b2 + 0.001, -1))
    best = cur = 0
    for _, d in sorted(events):
        cur += d
        best = max(best, cur)
    return best


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


# Kismet's own bookkeeping: server and capture-source identifiers say nothing about the device.
_NOISE = ("kismet.server", "seenby", "datasource", "kismet.device.base.key", "kismet.device.base.packets.rrd",
          "rrd", "location")

GROUPS = [
    ("Capabilities", ("ht_mode", "ht_capab", "vht_capab", "he_capab", "maxrate", "max_rate", "supported_rate",
                      "dot11d_country", "chanwidth", "channel_width", "mcs", "streams")),
    ("WPS", ("wps_manuf", "wps_model", "wps_device_name", "wps_serial")),
    ("Traffic", ("packets.total", "packets.data", "packets.error", "packets.llc", "datasize", "num_retries",
                 "num_fragments")),
    ("Bluetooth", ("uuid", "address_type", "addr_type", "txpower", "tx_power", "company", "manufacturer",
                   "device_class", "major_class", "minor_class", "pathloss", "bluetooth.device.type",
                   "scan_data", "appearance", "service_data", "connectable", "bdaddr")),
]


def interesting(rec, limit=60):
    """Pick the fields of a raw Kismet record that help identify a device, grouped by purpose."""
    flat = _flatten(rec)
    out = {}
    for group, frags in GROUPS:
        rows = []
        for path, v in flat.items():
            low = path.lower()
            if any(x in low for x in _NOISE):
                continue
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
