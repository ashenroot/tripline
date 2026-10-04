import configparser
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import watcher  # noqa: E402


def make_cfg(tmp, **overrides):
    """Load config.example.ini with db_path in tmp; overrides is {"section": {"key": "val"}}."""
    cp = configparser.ConfigParser()
    cp.read(os.path.join(ROOT, "config.example.ini"))
    cp.set("detect", "db_path", os.path.join(tmp, "t.db"))
    for sec, kv in overrides.items():
        if not cp.has_section(sec):
            cp.add_section(sec)
        for k, v in kv.items():
            cp.set(sec, k, v)
    path = os.path.join(tmp, "config.ini")
    with open(path, "w") as fh:
        cp.write(fh)
    watcher.CFG_PATH = path
    watcher._last_sighting.clear()
    return cp


def tmpdir():
    return tempfile.TemporaryDirectory()


def rec(mac, bssid=None, rssi=-60, phy="IEEE802.11", manuf=""):
    d = {"kismet.device.base.macaddr": mac, "kismet.device.base.phyname": phy,
         "kismet.device.base.manuf": manuf, "kismet.device.base.name": "", "rssi": rssi}
    if bssid:
        d["bssid"] = bssid
    return d
