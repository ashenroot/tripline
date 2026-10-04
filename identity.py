"""Identity features: probed SSIDs, entities, and link suggestions.

Nothing here decides who someone is. It records weak evidence (probed network names,
sensors and devices that show up together), proposes links, and applies the ones you
confirm. A link is always a manual action.
"""
import math
import time

# SSIDs carried by huge numbers of devices. They say almost nothing about a specific owner.
COMMON_EXACT = {"xfinitywifi", "attwifi", "cablewifi", "optimumwifi", "default", "guest", "setup",
                "iphone", "androidap", "android", "hpsetup", "linksys", "netgear", "dlink",
                "belkin", "tmobile", "wifi", "free wifi", "starbucks", "google starbucks",
                "mcdonalds free wifi", "directv"}
COMMON_PREFIX = ("netgear", "linksys", "tp-link", "tplink", "xfinity", "att", "spectrum", "dlink",
                 "d-link", "asus", "belkin", "hp-print", "directv", "verizon", "mywifi", "cox")
COMMON_FACTOR = 0.1

MIN_SSID_POPULATION = 10     # below this many probing devices, rarity statistics are meaningless
MIN_SHARED_WEIGHT = 2.0      # rarity-weighted overlap needed to suggest a match
MIN_SHARED_FRACTION = 0.4
BUCKET = 300                 # co-occurrence bucket size, seconds
COOCCUR_DAYS = 14
MIN_SHARED_BUCKETS = 6
MIN_COOCCUR_RATIO = 0.8
ALWAYS_PRESENT = 0.4         # devices present in more of the buckets than this carry no signal
MIN_TPMS_PAIR = 4
TPMS_WINDOW = 30             # seconds: sensors heard this close together may share a car

ENTITY_KINDS = ("household", "regular", "visitor", "contractor", "other")


# ---------------------------------------------------------------- SSIDs

def clean_ssid(s):
    if not isinstance(s, str):
        return None
    s = "".join(c for c in s if c.isprintable()).strip()
    return s if 0 < len(s.encode("utf-8", "ignore")) <= 32 else None


def extract_ssids(obj, _depth=0):
    """Pull SSID strings out of whatever shape Kismet returns for the probed-SSID map.

    Handles a dict or list of records carrying "dot11.probedssid.ssid", or a plain list of strings.
    """
    out = []
    if _depth > 6 or obj is None:
        return out
    if isinstance(obj, str):
        c = clean_ssid(obj)
        return [c] if c else []
    if isinstance(obj, dict):
        if "dot11.probedssid.ssid" in obj:
            c = clean_ssid(obj["dot11.probedssid.ssid"])
            return [c] if c else []
        for v in obj.values():
            out += extract_ssids(v, _depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out += extract_ssids(v, _depth + 1)
    seen, res = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res[:64]


def is_common(ssid):
    s = ssid.casefold()
    return s in COMMON_EXACT or s.startswith(COMMON_PREFIX)


def record_probes(db, mac, ssids, now):
    for s in ssids:
        db.execute("INSERT INTO probes(mac,ssid,first_seen,last_seen) VALUES(?,?,?,?) "
                   "ON CONFLICT(mac,ssid) DO UPDATE SET last_seen=excluded.last_seen", (mac, s, now, now))


def home_ssid_set(cfg, db):
    """Your own network names (config home_ssids plus the ones added in the web UI), case-folded."""
    out = {s.strip().casefold() for s in cfg.get("detect", "home_ssids", fallback="").split(",") if s.strip()}
    out.update(r[0].casefold() for r in db.execute("SELECT ssid FROM home_ssids"))
    return frozenset(out)


def weights(db):
    """Rarity weight per SSID, from how many distinct devices have probed it."""
    n_dev = db.execute("SELECT COUNT(DISTINCT mac) FROM probes").fetchone()[0]
    w = {}
    for ssid, n in db.execute("SELECT ssid, COUNT(DISTINCT mac) FROM probes GROUP BY ssid"):
        base = 2.0 if n_dev < MIN_SSID_POPULATION else max(0.05, min(6.0, math.log2((n_dev + 1) / (n + 0.5))))
        w[ssid] = base * (COMMON_FACTOR if is_common(ssid) else 1.0)
    return w


# ---------------------------------------------------------------- entities

def _members_of(db, entity_id):
    return [(r[0], r[1]) for r in db.execute(
        "SELECT kind, ref FROM entity_members WHERE entity_id=?", (entity_id,))]


def apply_known(db, kind, ref, known, label=None):
    """Mark one member known/unknown. Adds the entity name as a label if it has none."""
    if kind == "device":
        db.execute("UPDATE devices SET known=?, src=NULL, label=COALESCE(label, ?) WHERE mac=?",
                   (1 if known else 0, label if known else None, ref))
    elif kind == "vehicle":
        db.execute("UPDATE vehicles SET known=?, label=COALESCE(label, ?) WHERE vid=?",
                   (1 if known else 0, label if known else None, ref))


def create_entity(db, name, kind="household", expires_days=None, known=True, now=None):
    now = int(now or time.time())
    name = (name or "").strip()[:40]
    if not name:
        raise ValueError("name required")
    if kind not in ENTITY_KINDS:
        raise ValueError("bad kind")
    exp = int(now + float(expires_days) * 86400) if expires_days else None
    cur = db.execute("INSERT INTO entities(name,kind,created,expires,known) VALUES(?,?,?,?,?)",
                     (name, kind, now, exp, 1 if known else 0))
    db.commit()
    return cur.lastrowid


def add_member(db, entity_id, kind, ref, now=None):
    if kind not in ("device", "vehicle"):
        raise ValueError("bad member kind")
    row = db.execute("SELECT name, known FROM entities WHERE id=?", (entity_id,)).fetchone()
    if row is None:
        raise KeyError("no such entity")
    table, col = ("devices", "mac") if kind == "device" else ("vehicles", "vid")
    if not db.execute(f"SELECT 1 FROM {table} WHERE {col}=?", (ref,)).fetchone():
        raise KeyError("no such " + kind)
    db.execute("INSERT INTO entity_members(kind,ref,entity_id,added) VALUES(?,?,?,?) "
               "ON CONFLICT(kind,ref) DO UPDATE SET entity_id=excluded.entity_id",
               (kind, ref, entity_id, int(now or time.time())))
    if row[1]:
        apply_known(db, kind, ref, True, row[0])
    db.commit()


def entity_of(db, kind, ref):
    row = db.execute("SELECT entity_id FROM entity_members WHERE kind=? AND ref=?", (kind, ref)).fetchone()
    return row[0] if row else None


def link_group(db, members, name=None, kind="household", expires_days=None):
    """Put members (dicts with kind/ref) in one entity, creating or merging entities as needed."""
    if len(members) < 2:
        raise ValueError("need at least two members")
    existing = [e for e in (entity_of(db, m["kind"], m["ref"]) for m in members) if e]
    eid = existing[0] if existing else create_entity(db, name, kind, expires_days)
    for other in set(existing[1:]) - {eid}:
        db.execute("UPDATE entity_members SET entity_id=? WHERE entity_id=?", (eid, other))
        db.execute("DELETE FROM entities WHERE id=?", (other,))
    for m in members:
        add_member(db, eid, m["kind"], m["ref"])
    return eid


def link_pair(db, a, b, name=None, kind="household", expires_days=None):
    return link_group(db, [a, b], name, kind, expires_days)


def remove_member(db, kind, ref):
    db.execute("DELETE FROM entity_members WHERE kind=? AND ref=?", (kind, ref))
    db.commit()


def delete_entity(db, entity_id):
    db.execute("DELETE FROM entity_members WHERE entity_id=?", (entity_id,))
    db.execute("DELETE FROM entities WHERE id=?", (entity_id,))
    db.commit()


def expire_entities(db, now=None):
    """Visitors and contractors lapse: their members go back to unknown. Returns names expired."""
    now = int(now or time.time())
    done = []
    for eid, name in db.execute("SELECT id, name FROM entities WHERE known=1 AND expires IS NOT NULL "
                                "AND expires<?", (now,)).fetchall():
        for kind, ref in _members_of(db, eid):
            apply_known(db, kind, ref, False)
        db.execute("UPDATE entities SET known=0 WHERE id=?", (eid,))
        done.append(name)
    if done:
        db.commit()
    return done


def entity_view(db):
    """All entities with members and a last-seen time taken across every member."""
    out = []
    for e in db.execute("SELECT id,name,kind,created,expires,known FROM entities ORDER BY created DESC"):
        mem = []
        for kind, ref in _members_of(db, e[0]):
            if kind == "device":
                r = db.execute("SELECT label,manuf,name,phy,last_seen,rand FROM devices WHERE mac=?", (ref,)).fetchone()
                if r:
                    mem.append({"kind": "device", "ref": ref, "label": r[0] or r[2] or r[1] or "",
                                "phy": r[3], "last_seen": r[4], "rand": r[5]})
            else:
                r = db.execute("SELECT label,model,last_seen FROM vehicles WHERE vid=?", (ref,)).fetchone()
                if r:
                    mem.append({"kind": "vehicle", "ref": ref, "label": r[0] or r[1] or "",
                                "phy": "TPMS", "last_seen": r[2], "rand": 0})
        seen = max((m["last_seen"] or 0 for m in mem), default=0)
        sig = {}
        for m in mem:
            label = ("Tyre sensors" if m["kind"] == "vehicle" else
                     "Bluetooth" if "luetooth" in (m["phy"] or "") else
                     "Wi-Fi" if "802.11" in (m["phy"] or "") else (m["phy"] or "Device"))
            s = sig.setdefault(label, {"signal": label, "count": 0, "last_seen": None})
            s["count"] += 1
            s["last_seen"] = max(s["last_seen"] or 0, m["last_seen"] or 0) or None
        names = {r[0] for r in db.execute(
            "SELECT DISTINCT ssid FROM probes WHERE mac IN (SELECT ref FROM entity_members "
            "WHERE kind='device' AND entity_id=?)", (e[0],))}
        if names:
            sig["Network names"] = {"signal": "Network names", "count": len(names), "last_seen": None}
        out.append({"id": e[0], "name": e[1], "kind": e[2], "created": e[3], "expires": e[4],
                    "known": e[5], "last_seen": seen or None, "members": mem, "signals": list(sig.values())})
    return out


# ---------------------------------------------------------------- suggestions

def _key(kind, ref):
    return f"{kind}:{ref}"


def _linked(db):
    return {_key(k, r): e for k, r, e in db.execute("SELECT kind, ref, entity_id FROM entity_members")}


def _dismissed(db):
    return {(a, b) for a, b in db.execute("SELECT a, b FROM dismissed")}


def _pair(a, b):
    return (a, b) if a <= b else (b, a)


def ssid_evidence(db, cfg, now=None):
    """{(keyA,keyB): {"weight","fraction","ssids"}} for devices whose probed SSIDs overlap."""
    home = home_ssid_set(cfg, db)
    w = weights(db)
    per = {}
    for mac, ssid in db.execute("SELECT mac, ssid FROM probes"):
        if ssid.casefold() in home:
            continue
        per.setdefault(mac, set()).add(ssid)
    total = {m: sum(w.get(s, 0) for s in ss) for m, ss in per.items()}
    index = {}
    for mac, ss in per.items():
        for s in ss:
            index.setdefault(s, []).append(mac)
    n_dev = max(1, len(per))
    shared = {}
    for s, macs in index.items():
        if len(macs) < 2 or len(macs) > max(6, 0.25 * n_dev):
            continue  # nearly everyone probes it: no signal
        for i in range(len(macs)):
            for j in range(i + 1, len(macs)):
                shared.setdefault(_pair(macs[i], macs[j]), []).append(s)
    out = {}
    for (a, b), ss in shared.items():
        inter = sum(w.get(s, 0) for s in ss)
        denom = min(total[a], total[b]) or 1
        frac = inter / denom
        if inter >= MIN_SHARED_WEIGHT and frac >= MIN_SHARED_FRACTION:
            out[(_key("device", a), _key("device", b))] = {"weight": round(inter, 2), "fraction": round(frac, 2),
                                                           "ssids": sorted(ss)[:6]}
    return out


def _overlap_minutes(db, a, b, since):
    """Minutes in which both addresses were heard. Two addresses of one device barely overlap."""
    row = db.execute(
        "SELECT COUNT(*) FROM (SELECT ts/60 m FROM sightings WHERE mac=? AND ts>=? INTERSECT "
        "SELECT ts/60 FROM sightings WHERE mac=? AND ts>=?)", (a, since, b, since)).fetchone()
    return row[0]


def cooccurrence_evidence(db, now=None):
    """{(keyA,keyB): {"shared","ratio"}} for devices/vehicles that appear in the same 5-minute buckets."""
    now = int(now or time.time())
    since = now - COOCCUR_DAYS * 86400
    buckets = {}
    for mac, b in db.execute("SELECT mac, ts/? FROM sightings WHERE ts>=? GROUP BY mac, ts/?", (BUCKET, since, BUCKET)):
        buckets.setdefault(_key("device", mac), set()).add(b)
    for vid, b in db.execute("SELECT vid, ts/? FROM vehicle_sightings WHERE ts>=? GROUP BY vid, ts/?", (BUCKET, since, BUCKET)):
        buckets.setdefault(_key("vehicle", vid), set()).add(b)
    span = max(1, (now - since) // BUCKET)
    cand = {k: s for k, s in buckets.items() if MIN_SHARED_BUCKETS <= len(s) <= ALWAYS_PRESENT * span}
    by_bucket = {}
    for k, s in cand.items():
        for b in s:
            by_bucket.setdefault(b, []).append(k)
    counts = {}
    for b, ks in by_bucket.items():
        if len(ks) > 15:
            continue
        for i in range(len(ks)):
            for j in range(i + 1, len(ks)):
                p = _pair(ks[i], ks[j])
                counts[p] = counts.get(p, 0) + 1
    out = {}
    for (a, b), n in counts.items():
        ratio = n / min(len(cand[a]), len(cand[b]))
        if n >= MIN_SHARED_BUCKETS and ratio >= MIN_COOCCUR_RATIO:
            out[(a, b)] = {"shared": n, "ratio": round(ratio, 2)}
    return out


def entity_suggestions(db, cfg, now=None):
    """Records that match what an entity has shown across ALL its members, not one member.

    The entity's network names are the union of its devices' probes, so a record that shares a
    few names with each of several members still matches. Entities do not need every member
    to transmit on every trip: any member's evidence counts.
    """
    now = int(now or time.time())
    since = now - COOCCUR_DAYS * 86400
    home = home_ssid_set(cfg, db)
    w = weights(db)
    per = {}
    for mac, ssid in db.execute("SELECT mac, ssid FROM probes"):
        if ssid.casefold() not in home:
            per.setdefault(mac, set()).add(ssid)
    n_dev = max(1, len(per))
    freq = {}
    for ss in per.values():
        for s in ss:
            freq[s] = freq.get(s, 0) + 1
    usable = lambda s: freq.get(s, 0) <= max(6, 0.25 * n_dev)
    linked = _linked(db)
    dismissed = _dismissed(db)
    members = {}
    for kind, ref, eid in db.execute("SELECT kind, ref, entity_id FROM entity_members"):
        members.setdefault(eid, []).append((kind, ref))
    names = {r[0]: r[1] for r in db.execute("SELECT id, name FROM entities")}
    out = []
    for eid, mem in members.items():
        macs = [r for k, r in mem if k == "device"]
        eset = set().union(*(per.get(m, set()) for m in macs)) if macs else set()
        eset = {s for s in eset if usable(s)}
        if not eset:
            continue
        etot = sum(w.get(s, 0) for s in eset)
        sharing = {}
        for cand, ss in per.items():
            key = _key("device", cand)
            if cand in macs or key in linked:
                continue
            if _pair(_key("entity", str(eid)), key) in dismissed:
                continue
            inter = {s for s in ss if s in eset}
            iw = sum(w.get(s, 0) for s in inter)
            ctot = sum(w.get(s, 0) for s in ss if usable(s)) or 1
            if iw < MIN_SHARED_WEIGHT or iw / min(etot, ctot) < MIN_SHARED_FRACTION:
                continue
            donors = [m for m in macs if per.get(m, set()) & inter]
            if any(_overlap_minutes(db, cand, m, since) >= 3 for m in donors):
                continue  # heard at the same time as a member: a different device
            sharing[cand] = (iw, sorted(inter)[:6], len(donors))
        for cand, (iw, inter, donors) in sharing.items():
            pts = 3 if iw >= 5 else 2 if iw >= 3 else 1
            out.append({"members": [{"kind": "device", "ref": cand}], "entity_id": eid, "entity_name": names.get(eid),
                        "evidence": {"ssid": {"weight": round(iw, 2), "ssids": inter, "from_members": donors}},
                        "level": "high" if pts >= 4 else "medium" if pts >= 2 else "low", "points": pts})
    return out


def tpms_evidence(db):
    return {(_key("vehicle", a), _key("vehicle", b)): {"count": n}
            for a, b, n in db.execute("SELECT a, b, n FROM vehicle_pairs WHERE n>=?", (MIN_TPMS_PAIR,))}


def _points(ev):
    pts = 0
    s = ev.get("ssid")
    if s:
        pts += 3 if s["weight"] >= 5 else 2 if s["weight"] >= 3 else 1
    c = ev.get("cooccur")
    if c:
        pts += 2 if c["shared"] >= 12 else 1
    t = ev.get("tpms")
    if t:
        pts += 3 if t["count"] >= 8 else 2
    return pts


def suggestions(db, cfg, now=None):
    """Pairs that look like the same entity, with evidence and a low/medium/high level."""
    now = int(now or time.time())
    pairs = {}
    for p, e in ssid_evidence(db, cfg, now).items():
        pairs.setdefault(p, {})["ssid"] = e
    for p, e in cooccurrence_evidence(db, now).items():
        pairs.setdefault(p, {})["cooccur"] = e
    for p, e in tpms_evidence(db).items():
        pairs.setdefault(p, {})["tpms"] = e
    linked, dismissed = _linked(db), _dismissed(db)
    out = []
    for (a, b), ev in pairs.items():
        if (a, b) in dismissed or (linked.get(a) is not None and linked.get(a) == linked.get(b)):
            continue
        ka, ra = a.split(":", 1)
        kb, rb = b.split(":", 1)
        if ev.get("ssid") and ka == kb == "device" and _overlap_minutes(db, ra, rb, now - COOCCUR_DAYS * 86400) >= 3:
            ev.pop("ssid")  # heard at the same time: two devices, not one device's two addresses
            if not ev:
                continue
        pts = _points(ev)
        if pts == 0:
            continue
        if ev.get("tpms"):
            ev.pop("cooccur", None)  # the same bursts, counted twice
            pts = _points(ev)
        out.append({"a": {"kind": ka, "ref": ra}, "b": {"kind": kb, "ref": rb}, "evidence": ev,
                    "level": "high" if pts >= 4 else "medium" if pts >= 2 else "low", "points": pts,
                    "entity_a": linked.get(a), "entity_b": linked.get(b)})
    out = _group_tpms(out)
    ent_sugs = entity_suggestions(db, cfg, now)
    covered = {(s["entity_id"], s["members"][0]["ref"]) for s in ent_sugs}
    keep = []
    for s in out:
        ents = [e for e in (s.get("entity_a"), s.get("entity_b")) if e]
        refs = [m["ref"] for m in (s.get("members") or [s["a"], s["b"]])]
        if any((e, r) in covered for e in ents for r in refs):
            continue  # the entity-level suggestion already says this, with more evidence
        keep.append(s)
    out = keep
    for s in out:
        s["members"] = s.get("members") or [s["a"], s["b"]]
        s["entities"] = sorted({e for e in (s.get("entity_a"), s.get("entity_b"), *s.get("entities", [])) if e})
    out += ent_sugs
    for s in ent_sugs:
        s.setdefault("entities", [s["entity_id"]])
    out.sort(key=lambda s: -s["points"])
    return out[:50]


def _group_tpms(items):
    """Four tyre sensors of one car give six pairs. Fold them into one suggestion per car."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    tp = [s for s in items if s["evidence"].get("tpms") and s["a"]["kind"] == s["b"]["kind"] == "vehicle"]
    for s in tp:
        parent[find(s["a"]["ref"])] = find(s["b"]["ref"])
    groups = {}
    for s in tp:
        groups.setdefault(find(s["a"]["ref"]), []).append(s)
    rest = [s for s in items if s not in tp]
    for g in groups.values():
        refs = sorted({m["ref"] for s in g for m in (s["a"], s["b"])})
        pts = max(s["points"] for s in g)
        ents = sorted({e for s in g for e in (s.get("entity_a"), s.get("entity_b")) if e})
        rest.append({"members": [{"kind": "vehicle", "ref": r} for r in refs], "entities": ents,
                     "evidence": {"tpms": {"count": min(s["evidence"]["tpms"]["count"] for s in g)}},
                     "level": "high" if pts >= 4 else "medium" if pts >= 2 else "low", "points": pts})
    return rest


def add_to_entity(db, entity_id, members):
    for m in members:
        add_member(db, entity_id, m["kind"], m["ref"])
    return entity_id


def dismiss_from_entity(db, entity_id, members):
    for m in members:
        a, b = _pair(_key("entity", str(entity_id)), _key(m["kind"], m["ref"]))
        db.execute("INSERT OR IGNORE INTO dismissed(a,b) VALUES(?,?)", (a, b))
    db.commit()


def dismiss(db, a, b):
    a, b = _pair(a, b)
    db.execute("INSERT OR IGNORE INTO dismissed(a,b) VALUES(?,?)", (a, b))
    db.commit()


def dismiss_group(db, members):
    keys = [_key(m["kind"], m["ref"]) for m in members]
    for x in range(len(keys)):
        for y in range(x + 1, len(keys)):
            a, b = _pair(keys[x], keys[y])
            db.execute("INSERT OR IGNORE INTO dismissed(a,b) VALUES(?,?)", (a, b))
    db.commit()


def note_tpms(db, recent, vid, now):
    """Count sensors heard within TPMS_WINDOW of each other (a car's wheels). `recent` is a dict vid->ts."""
    for other, ts in list(recent.items()):
        if now - ts > TPMS_WINDOW:
            del recent[other]
        elif other != vid:
            a, b = _pair(other, vid)
            row = db.execute("SELECT last_seen FROM vehicle_pairs WHERE a=? AND b=?", (a, b)).fetchone()
            if row is None:
                db.execute("INSERT INTO vehicle_pairs(a,b,n,last_seen) VALUES(?,?,1,?)", (a, b, now))
            elif now - row[0] > 60:  # one count per burst, not per message
                db.execute("UPDATE vehicle_pairs SET n=n+1, last_seen=? WHERE a=? AND b=?", (now, a, b))
    recent[vid] = now
