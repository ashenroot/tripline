"""Plain-text known-device list: one device per line, `MAC [label]`. `#` starts a comment.

    [source.file]
    path = /etc/wuds/known_devices.txt
"""
from . import clean_label, norm_mac


class Source:
    def __init__(self, cfg):
        self.path = cfg["path"]

    def devices(self):
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                mac, _, label = line.partition(" ")
                mac = norm_mac(mac)
                if mac:
                    out.append({"mac": mac, "label": clean_label(label)})
        return out
