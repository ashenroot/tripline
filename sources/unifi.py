"""UniFi Network source: every client your controller has a record of.

Works with a Cloud Key / UniFi OS console or a self-hosted controller. Field names
come from the community-documented internal API and are tolerated loosely; they have
not been verified against every Network version.

    [source.unifi]
    url = https://192.168.1.2          # console address (Cloud Key Gen2+/UniFi OS), or https://host:8443 for legacy
    site = default
    # Either an API key (Network 10.1+; create under Control Plane > Integrations) ...
    api_key =
    # ... or a LOCAL account (not SSO, no MFA). Read-only role is enough.
    username =
    password =
    verify_tls = false                 # Cloud Keys use self-signed certificates
    include = all                      # all | named  (named = only clients you gave a name)
    max_age_days = 30                  # skip clients the controller has not seen for this long; 0 = keep all
"""
import http.cookiejar
import json
import ssl
import time
import urllib.request

from . import clean_label, norm_mac


class Source:
    def __init__(self, cfg):
        self.base = cfg["url"].rstrip("/")
        self.site = cfg.get("site", "default")
        self.key = cfg.get("api_key", "").strip()
        self.user = cfg.get("username", "")
        self.pw = cfg.get("password", "")
        self.named_only = cfg.get("include", "all").lower() == "named"
        try:
            self.max_age_days = max(0, int(str(cfg.get("max_age_days", "30")).strip() or 30))
        except ValueError:
            raise RuntimeError("max_age_days must be a whole number of days (0 keeps every client)")
        self.skipped_idle = 0
        ctx = ssl.create_default_context()
        if str(cfg.get("verify_tls", "false")).lower() not in ("1", "true", "yes", "on"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar))
        self.prefix = None  # "/proxy/network" on UniFi OS, "" on legacy controllers

    def _req(self, path, data=None):
        headers = {"Accept": "application/json"}
        if self.key:
            headers["X-API-KEY"] = self.key
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        for c in self.jar:
            if c.name == "csrf_token":
                headers["X-CSRF-Token"] = c.value
        return self.opener.open(urllib.request.Request(self.base + path, data=body, headers=headers), timeout=15)

    def _login(self):
        if self.key:
            self.prefix = "/proxy/network"
            return
        creds = {"username": self.user, "password": self.pw}
        for login, prefix in (("/api/auth/login", "/proxy/network"), ("/api/login", "")):
            try:
                self._req(login, creds).read()
                self.prefix = prefix
                return
            except Exception:
                continue
        raise RuntimeError("UniFi login failed (use a local, non-SSO account without MFA, or an API key)")

    def devices(self):
        self._login()
        paths = [f"{self.prefix}/api/s/{self.site}/rest/user"]
        last = None
        for p in paths:
            try:
                rows = json.load(self._req(p)).get("data", [])
                break
            except Exception as exc:
                last = exc
        else:
            raise RuntimeError(f"UniFi client list failed: {last}")
        out = []
        self.skipped_idle = 0
        cutoff = time.time() - self.max_age_days * 86400 if self.max_age_days else None
        for r in rows:
            mac = norm_mac(r.get("mac"))
            if not mac:
                continue
            name = clean_label(r.get("name") or r.get("hostname"))
            if self.named_only and not r.get("name"):
                continue
            # UniFi remembers every client it has ever seen. A client with no usable
            # last_seen is kept, because we cannot tell that it is old.
            seen = r.get("last_seen")
            if cutoff and isinstance(seen, (int, float)) and 0 < seen < cutoff:
                self.skipped_idle += 1
                continue
            out.append({"mac": mac, "label": name})
        return out
