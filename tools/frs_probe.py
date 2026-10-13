#!/usr/bin/env python3
"""Log FRS/GMRS handheld-radio transmissions heard by the RTL-SDR.

A person carrying a walkie-talkie is a person on the property. This tool watches the 22 FRS
channels and the 8 GMRS repeater-input channels for carriers, and logs when each channel was
keyed, for how long and how strong. It measures signal energy only. It does not demodulate,
record audio or read channel tones.

    python3 tools/frs_probe.py [--log frs-probe.log] [--hours 24] [--threshold 10] [--gain 40]

The SDR can serve one program at a time, so stop the TPMS decoder first and start it again after:

    sudo systemctl stop tripline-tpms
    sudo systemd-run --unit=frs-probe --uid=tripline python3 /opt/tripline/tools/frs_probe.py \\
        --log /var/lib/tripline/frs-probe.log
    tail -f /var/lib/tripline/frs-probe.log
    sudo systemctl stop frs-probe; sudo systemctl start tripline-tpms     # when finished

Each transmission is one line, written when the carrier ends. Levels are rtl_power dB, which are
relative to the receiver and not calibrated, so compare them with each other, not with other gear.
A line "peak +23 dB" means 23 dB above that channel's own recent quiet level.

Channel classes follow 47 CFR Part 95 (check the current text): FRS channels 1-7 and 15-22 allow
2 W ERP, channels 8-14 allow 0.5 W ERP, and 467.550-467.725 MHz are GMRS repeater inputs. Weaker
FRS radios make strength a better distance guide; radios sold as FRS often exceed the limits.

Needs rtl_power from the rtl-sdr package (installed by install.sh).
"""
import argparse
import math
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter, deque

# One rtl_power range covers both channel blocks; rtl_power splits it into tunings by itself.
RANGE = "462.4M:467.8M:6.25k"
HALF_CHANNEL_HZ = 6250


def build_channels():
    """(label, Hz, class) for every FRS channel and GMRS repeater input."""
    chans = []
    for n in range(1, 8):
        chans.append((str(n), round((462.5625 + 0.025 * (n - 1)) * 1e6), "FRS 2W"))
    for n in range(8, 15):
        chans.append((str(n), round((467.5625 + 0.025 * (n - 8)) * 1e6), "FRS 0.5W"))
    for n in range(15, 23):
        chans.append((str(n), round((462.55 + 0.025 * (n - 15)) * 1e6), "FRS 2W"))
    for n in range(15, 23):
        chans.append(("R%d" % n, round((467.55 + 0.025 * (n - 15)) * 1e6), "GMRS rpt"))
    return chans


CHANNELS = build_channels()


def parse_row(line):
    """One rtl_power CSV line -> (epoch, hz_low, hz_high, hz_step, [dB...]) or None."""
    parts = [p.strip() for p in line.strip().split(",")]
    if len(parts) < 8:
        return None
    try:
        ts = time.mktime(time.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S"))
        low, high, step = float(parts[2]), float(parts[3]), float(parts[4])
        dbs = [float(x) for x in parts[6:]]
    except ValueError:
        return None
    if step <= 0 or not dbs:
        return None
    return ts, low, high, step, dbs


def level_at(hz, low, step, dbs):
    """Strongest bin within half a channel of hz, or None when hz is outside this row."""
    if hz < low or hz > low + step * len(dbs):
        return None
    first = math.ceil((hz - HALF_CHANNEL_HZ - low) / step - 0.5)
    last = math.floor((hz + HALF_CHANNEL_HZ - low) / step - 0.5)
    if first > last:
        first = last = round((hz - low) / step - 0.5)
    vals = [dbs[i] for i in range(max(first, 0), min(last, len(dbs) - 1) + 1) if math.isfinite(dbs[i])]
    return max(vals) if vals else None


class _Chan:
    def __init__(self, label, hz, kind, history):
        self.label, self.hz, self.kind = label, hz, kind
        self.hist = deque(maxlen=history)
        self.active = None


class Detector:
    """Per-channel carrier detection against that channel's own quiet level."""

    def __init__(self, threshold=10.0, end_gap=2.0, warmup=30, max_active=120.0, history=300, interval=1.0):
        self.threshold, self.end_gap, self.warmup = threshold, end_gap, warmup
        self.max_active, self.interval = max_active, interval
        self.chans = [_Chan(l, hz, k, history) for l, hz, k in CHANNELS]

    def warmed(self):
        return sum(1 for c in self.chans if len(c.hist) >= self.warmup)

    def floors(self):
        v = [statistics.median(c.hist) for c in self.chans if len(c.hist) >= self.warmup]
        return (min(v), max(v)) if v else None

    def feed(self, ts, low, step, dbs):
        """Process one spectrum row; returns the transmissions that ended with it."""
        done = []
        for c in self.chans:
            lvl = level_at(c.hz, low, step, dbs)
            if lvl is None:
                continue
            if c.active is None:
                base = statistics.median(c.hist) if len(c.hist) >= self.warmup else None
                if base is not None and lvl - base >= self.threshold:
                    c.active = {"start": ts, "last": ts, "floor": base, "peak": lvl, "n": 1}
                else:
                    c.hist.append(lvl)
                continue
            a = c.active
            if lvl - a["floor"] >= self.threshold - 3.0:
                a["last"] = ts
                a["n"] += 1
                a["peak"] = max(a["peak"], lvl)
            if ts - a["last"] >= self.end_gap:
                done.append(self._finish(c, False))
            elif ts - a["start"] >= self.max_active:
                done.append(self._finish(c, True))
                c.hist.clear()
                c.hist.extend([lvl] * self.warmup)   # a stuck carrier becomes the new normal
        return done

    def _finish(self, c, long):
        a, c.active = c.active, None
        return {"label": c.label, "hz": c.hz, "kind": c.kind, "start": a["start"],
                "dur": a["last"] - a["start"] + self.interval, "peak": a["peak"],
                "excess": a["peak"] - a["floor"], "floor": a["floor"], "long": long}


def format_event(e):
    return "%s  ch %-3s %9.4f MHz  %-8s  %4.0fs  peak +%.1f dB (level %.1f, floor %.1f)%s" % (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["start"])), e["label"], e["hz"] / 1e6, e["kind"],
        e["dur"], e["excess"], e["peak"], e["floor"], "  [carrier held; treated as interference]" if e["long"] else "")


def summary(events, started, ended):
    out = ["", "Summary: %s to %s (%.1f h)" % (time.strftime("%Y-%m-%d %H:%M", time.localtime(started)),
                                                time.strftime("%Y-%m-%d %H:%M", time.localtime(ended)), (ended - started) / 3600)]
    if not events:
        out.append("No transmissions heard. If handhelds are known to be nearby, try --gain 49 or a lower --threshold.")
        return "\n".join(out)
    out.append("Transmissions: %d" % len(events))
    by = {}
    for e in events:
        s = by.setdefault(e["label"], {"n": 0, "secs": 0.0, "best": -999.0, "kind": e["kind"], "hz": e["hz"]})
        s["n"] += 1
        s["secs"] += e["dur"]
        s["best"] = max(s["best"], e["excess"])
    out.append("By channel (strongest first):")
    for label, s in sorted(by.items(), key=lambda kv: -kv[1]["best"]):
        out.append("  ch %-3s %9.4f MHz  %-8s %3d transmissions  %5.0f s keyed  strongest +%.1f dB" % (
            label, s["hz"] / 1e6, s["kind"], s["n"], s["secs"], s["best"]))
    hours = Counter(time.localtime(e["start"]).tm_hour for e in events)
    out.append("By hour: " + "  ".join("%02d:00 %d" % (h, hours[h]) for h in sorted(hours)))
    kinds = Counter(e["kind"] for e in events)
    out.append("By class: " + ", ".join("%s %d" % kv for kv in kinds.most_common()))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="frs-probe.log", help="file to append to (default frs-probe.log)")
    ap.add_argument("--hours", type=float, default=0, help="stop after this long (default: run until stopped)")
    ap.add_argument("--threshold", type=float, default=10.0, help="dB over a channel's quiet level that counts as a transmission")
    ap.add_argument("--gain", default="40", help="tuner gain in dB (default 40)")
    ap.add_argument("--device", default="0", help="SDR index or serial (default 0)")
    ap.add_argument("--ppm", default=None, help="frequency correction in ppm")
    ap.add_argument("--rtl-power", default="rtl_power", help="path to rtl_power")
    ap.add_argument("--heartbeat", type=float, default=600, help="seconds between 'still running' lines (default 600)")
    args = ap.parse_args()

    exe = shutil.which(args.rtl_power) or (args.rtl_power if args.rtl_power != "rtl_power" else None)
    if not exe:
        sys.exit("rtl_power is missing. Install it with: sudo apt install rtl-sdr")
    cmd = [exe, "-f", RANGE, "-i", "1", "-g", str(args.gain), "-c", "20%", "-d", str(args.device)]
    if args.ppm:
        cmd += ["-p", str(args.ppm)]
    cmd.append("-")

    log = open(args.log, "a", buffering=1)

    def emit(line=""):
        print(line, flush=True)
        log.write(line + "\n")

    det = Detector(threshold=args.threshold)
    events = []
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    started = time.time()
    emit("# frs_probe started %s  threshold %g dB  gain %s  %d channels" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), args.threshold, args.gain, len(CHANNELS)))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        emit("# could not start rtl_power: %s" % exc)
        return 1
    errs = deque(maxlen=20)
    threading.Thread(target=lambda: [errs.append(l.rstrip()) for l in proc.stderr], daemon=True).start()

    def watchdog():
        while not stop.wait(1):
            if args.hours and time.time() - started >= args.hours * 3600:
                stop.set()
        try:
            proc.terminate()
        except OSError:
            pass
    threading.Thread(target=watchdog, daemon=True).start()

    rows, last_beat = 0, time.time()
    for line in proc.stdout:
        row = parse_row(line)
        if row is None:
            continue
        rows += 1
        for e in det.feed(row[0], row[1], row[3], row[4]):
            events.append(e)
            emit(format_event(e))
        if time.time() - last_beat >= args.heartbeat:
            last_beat = time.time()
            fl = det.floors()
            emit("# alive %s  rows %d  channels ready %d/%d  transmissions %d%s" % (
                time.strftime("%H:%M:%S"), rows, det.warmed(), len(CHANNELS), len(events),
                "  quiet level %.0f to %.0f dB" % fl if fl else ""))
    code = proc.wait()
    requested = stop.is_set()   # set by Ctrl-C, systemctl stop or --hours; otherwise rtl_power ended on its own
    stop.set()
    if rows == 0 or (code != 0 and not requested):
        emit("# rtl_power ended (exit %s) after %d rows. Last messages: %s" % (code, rows, " | ".join(errs) or "none"))
        if any("usb" in m.lower() or "open" in m.lower() for m in errs):
            emit("# The SDR is busy or not permitted. Stop tripline-tpms first, and run as the tripline user (see the top of this file).")
    emit(summary(events, started, time.time()))
    log.close()
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
