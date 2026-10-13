import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import frs_probe as F  # noqa: E402

LOW, STEP, NBINS = 462_400_000, 6250.0, 96     # 462.4 to 463.0 MHz
T0 = time.mktime((2026, 10, 13, 14, 0, 0, 0, 0, -1))


def row(hot=None, level=-50.0, spur=None):
    """A spectrum row; `hot` is {channel Hz: dB} and `spur` a constant {Hz: dB}."""
    dbs = [level] * NBINS
    for table in (hot or {}, spur or {}):
        for hz, db in table.items():
            dbs[round((hz - LOW) / STEP - 0.5)] = db
    return dbs


CH3 = 462_612_500
CH1 = 462_562_500


class Channels(unittest.TestCase):
    def test_table(self):
        by = {l: (hz, k) for l, hz, k in F.CHANNELS}
        self.assertEqual(len(by), 30)
        self.assertEqual(by["1"], (462_562_500, "FRS 2W"))
        self.assertEqual(by["7"][0], 462_712_500)
        self.assertEqual(by["8"], (467_562_500, "FRS 0.5W"))
        self.assertEqual(by["14"][0], 467_712_500)
        self.assertEqual(by["15"], (462_550_000, "FRS 2W"))
        self.assertEqual(by["22"][0], 462_725_000)
        self.assertEqual(by["R15"], (467_550_000, "GMRS rpt"))
        self.assertEqual(by["R22"][0], 467_725_000)

    def test_level_picks_channel_bins_and_ignores_outside(self):
        dbs = row({CH3: -20.0})
        self.assertEqual(F.level_at(CH3, LOW, STEP, dbs), -20.0)
        self.assertEqual(F.level_at(CH1, LOW, STEP, dbs), -50.0)
        self.assertIsNone(F.level_at(467_562_500, LOW, STEP, dbs))

    def test_parse_row(self):
        line = "2026-10-13, 14:00:01, 462400000, 463000000, 6250.00, 4096, " + ", ".join(["-50.00"] * 4)
        ts, low, high, step, dbs = F.parse_row(line)
        self.assertEqual((low, high, step, len(dbs)), (462400000, 463000000, 6250.0, 4))
        self.assertIsNone(F.parse_row("garbage"))
        self.assertIsNone(F.parse_row("2026-10-13, 14:00:01, a, b, c, 1, -50.0, -50.0"))


class Detection(unittest.TestCase):
    def quiet(self, d, n, start=0):
        for i in range(n):
            self.assertEqual(d.feed(T0 + start + i, LOW, STEP, row()), [])
        return start + n

    def test_transmission_is_logged_once_it_ends(self):
        d = F.Detector()
        t = self.quiet(d, 40)
        for i in range(3):
            self.assertEqual(d.feed(T0 + t + i, LOW, STEP, row({CH3: -25.0})), [])
        out = []
        for i in range(3, 8):
            out += d.feed(T0 + t + i, LOW, STEP, row())
        self.assertEqual(len(out), 1)
        e = out[0]
        self.assertEqual((e["label"], e["kind"]), ("3", "FRS 2W"))
        self.assertAlmostEqual(e["excess"], 25.0, places=1)
        self.assertGreaterEqual(e["dur"], 3)
        self.assertIn("ch 3", F.format_event(e))

    def test_nothing_reported_before_warmup(self):
        d = F.Detector()
        t = self.quiet(d, 5)
        out = []
        for i in range(3):
            out += d.feed(T0 + t + i, LOW, STEP, row({CH3: -25.0}))
        self.assertEqual(out, [])

    def test_constant_spur_never_alerts(self):
        d = F.Detector()
        out = []
        for i in range(120):
            out += d.feed(T0 + i, LOW, STEP, row(spur={CH3: -20.0}))
        self.assertEqual(out, [])

    def test_short_gap_does_not_split_a_transmission(self):
        d = F.Detector()
        t = self.quiet(d, 40)
        seq = [-25.0, -25.0, None, -25.0, -25.0]
        out = []
        for i, db in enumerate(seq):
            out += d.feed(T0 + t + i, LOW, STEP, row({CH3: db} if db else None))
        for i in range(len(seq), len(seq) + 5):
            out += d.feed(T0 + t + i, LOW, STEP, row())
        self.assertEqual(len(out), 1)

    def test_held_carrier_is_cut_off_and_rebaselined(self):
        d = F.Detector(max_active=30)
        t = self.quiet(d, 40)
        out = []
        for i in range(60):
            out += d.feed(T0 + t + i, LOW, STEP, row({CH3: -25.0}))
        self.assertTrue(out and out[0]["long"])
        self.assertEqual(len(out), 1)   # the new normal does not keep re-alerting

    def test_two_channels_are_independent(self):
        d = F.Detector()
        t = self.quiet(d, 40)
        out = []
        for i in range(2):
            out += d.feed(T0 + t + i, LOW, STEP, row({CH1: -30.0, CH3: -28.0}))
        for i in range(2, 7):
            out += d.feed(T0 + t + i, LOW, STEP, row())
        self.assertEqual(sorted(e["label"] for e in out), ["1", "3"])


class Summary(unittest.TestCase):
    def test_summary_and_empty(self):
        ev = [{"label": "3", "hz": CH3, "kind": "FRS 2W", "start": T0, "dur": 4, "peak": -25, "excess": 25, "floor": -50, "long": False},
              {"label": "3", "hz": CH3, "kind": "FRS 2W", "start": T0 + 3600, "dur": 2, "peak": -30, "excess": 20, "floor": -50, "long": False}]
        s = F.summary(ev, T0, T0 + 7200)
        self.assertIn("Transmissions: 2", s)
        self.assertIn("ch 3", s)
        self.assertIn("FRS 2W 2", s)
        self.assertIn("No transmissions heard", F.summary([], T0, T0 + 60))


class EndToEnd(unittest.TestCase):
    def test_log_file_from_a_fake_rtl_power(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "fake_rtl_power")
            with open(fake, "w") as f:
                f.write(textwrap.dedent("""\
                    #!%s
                    import sys, time
                    t0 = time.mktime((2026, 10, 13, 14, 0, 0, 0, 0, -1))
                    low, step, n = 462400000, 6250.0, 96
                    i3 = round((462612500 - low) / step - 0.5)
                    for s in range(60):
                        dbs = [-50.0] * n
                        if 40 <= s < 44:
                            dbs[i3] = -25.0
                        print("%%s, %%s, %%d, %%d, %%.2f, 1, %%s" %% (
                            time.strftime("%%Y-%%m-%%d", time.localtime(t0 + s)), time.strftime("%%H:%%M:%%S", time.localtime(t0 + s)),
                            low, low + 600000, step, ", ".join("%%.2f" %% x for x in dbs)))
                    """ % sys.executable))
            os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
            log = os.path.join(d, "out.log")
            r = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "frs_probe.py"),
                                "--rtl-power", fake, "--log", log], capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(log) as fh:
                text = fh.read()
            self.assertIn("ch 3", text)
            self.assertIn("Transmissions: 1", text)
            self.assertIn("# frs_probe started", text)


if __name__ == "__main__":
    unittest.main()
