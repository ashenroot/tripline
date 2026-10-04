"""Known-device sources.

A source answers one question: which devices on my network are mine? Each source
is a module in this package (or any importable module named in `module =`) that
defines a class `Source`:

    class Source:
        def __init__(self, cfg: dict): ...      # the [source.<name>] section
        def devices(self) -> list[dict]: ...    # [{"mac": "aa:bb:..", "label": "..."}]

`devices()` raises on failure; known_sync keeps the previous state in that case.
See sources/file.py for the smallest working example.
"""
import importlib
import re

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def norm_mac(value):
    """Normalise aa-bb-cc-dd-ee-ff / AABBCCDDEEFF / aa:bb:... to lower-case colon form, or None."""
    s = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(s) != 12:
        return None
    mac = ":".join(s[i:i + 2] for i in range(0, 12, 2)).lower()
    return mac if MAC_RE.match(mac) else None


def clean_label(text, limit=60):
    """Single-line, printable, length-limited label."""
    t = "".join(c for c in str(text or "") if c.isprintable()).strip()
    return t[:limit] or None


def load(name, section):
    """Instantiate source `name` from its config section (a dict)."""
    module = section.get("module") or f"sources.{name.replace('-', '_')}"
    return importlib.import_module(module).Source(section)
