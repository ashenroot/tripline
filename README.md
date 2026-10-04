# Tripline

Passive wireless presence detection for one building, on a single Raspberry Pi.
Kismet captures Wi-Fi and Bluetooth; Tripline logs sightings to SQLite, alerts when an
unknown device stays above a signal-strength floor, and serves a web dashboard.

Inspired by the old WUDS project (wireless MAC-based intruder alerts), rebuilt for a world of randomized addresses.

It detects "something new is nearby." It does not identify people.

## Status

Early. The logic is covered by automated tests that run against mock Kismet, UniFi and
webhook servers. It has **not** been run against a real Kismet instance or a real UniFi
console yet. These items are unverified and are the first places to look if something
does not work:

- Kismet field names, in particular `dot11.device.last_bssid` (used by `home_bssids`).
- The `linuxbluetooth` Kismet data source type (`kismet --list-datasources`).
- UniFi client-list field names across Network versions.
- The "rotating Bluetooth address" heuristic (no vendor resolved).

Reports and fixes from real hardware are the most useful contribution right now.

## How it works

- **Static-address devices** (anything with a stable MAC) alert when above the RSSI floor
  for `dwell_seconds`, unless they are on the known list.
- **Rotating-address devices** (modern phones) cannot be told apart, so the watcher counts
  distinct strong rotating addresses in a sliding window. In `home` mode it alerts above the
  learned household peak plus a margin; in `away` mode, above the away margin.
- **Your own network** is excluded from the noise. Clients associated with your access
  points (`home_bssids`) and devices from a known-device source (UniFi, a text file, or your
  own plugin) are marked known automatically. Hand edits in the UI always win.
- **Modes:** `learning` (log only), `home`, `away`, plus a timed guest window that
  suppresses alerts.
- **Dashboard:** signal-over-time timeline and radar (direction on the radar is
  arbitrary; one sensor cannot determine bearing), 24-hour activity strip, live feed, and a
  device manager.

## Install (Raspberry Pi OS)

1. **Kismet.** Install from the official Kismet apt repository (kismetwireless.net, docs,
   installing), choose the suid-root install, and add your user to the `kismet` group.
2. **Kismet login.** Create `~/.kismet/kismet_httpd.conf` with `httpd_username` and
   `httpd_password`.
3. **Data sources.** `sudo cp examples/kismet_site.conf /etc/kismet/` and set your Wi-Fi
   interface name (`iw dev`).
4. **Tripline.**
   ```
   sudo mkdir -p /opt/tripline/sources /etc/tripline /var/lib/tripline
   sudo chown $USER /var/lib/tripline
   sudo apt install python3-flask
   sudo cp watcher.py web.py known_sync.py dashboard.html /opt/tripline/
   sudo cp sources/*.py /opt/tripline/sources/
   sudo cp config.example.ini /etc/tripline/config.ini
   sudo chmod 600 /etc/tripline/config.ini
   sudo nano /etc/tripline/config.ini
   ```
5. **Services.** Copy `systemd/*.service` to `/etc/systemd/system/`, change `User=`, then
   `sudo systemctl enable --now kismet tripline-watcher tripline-web` (add `tripline-sync` if you use a
   known-device source).
6. **Learn, then arm.** Leave it in `learning` mode for 1-2 weeks, then press Arm in the UI
   or run `python3 /opt/tripline/watcher.py arm`.

`config.ini` holds secrets and is git-ignored. Never commit it.

## Known-device sources

Set `[sync] sources = unifi,file` and fill in the matching `[source.*]` sections, then run
`known_sync.py once` to test. Rules: a source can mark devices known and label them, never
overrides a device you marked or removed by hand, and revokes only devices it added itself
when it stops listing them. A failed or empty answer changes nothing.

| Source | Config | Notes |
|---|---|---|
| `unifi` | `[source.unifi]` | Cloud Key, UniFi OS console or self-hosted controller. API key (Network 10.1+) or a local non-SSO, no-MFA read-only account. Self-signed certificates are accepted unless `verify_tls = true`. |
| `file` | `[source.file]` | One `MAC label` per line. See `examples/known_devices.txt`. |

**Writing a source:** add a module with a `Source` class whose `devices()` returns
`[{"mac": "aa:bb:cc:dd:ee:ff", "label": "TV"}]`, then reference it with
`module = your.module` in a `[source.<name>]` section. `sources/file.py` is the smallest
example. Open a PR if it is useful to others (Home Assistant, OpenWrt, pfSense and router
DHCP leases are obvious candidates).

## Alerts

Every alert is logged and shown in the UI. Push delivery is optional and off by default:
set `[ntfy] topic` (use a long random name, or run your own ntfy server) and/or
`[webhook] url` to receive each alert as JSON.

## Web interface

Served at `http://127.0.0.1:8080` by default. For other machines use an SSH tunnel or
Tailscale. To bind to a LAN address set `[web] bind` and `[web] password`; the app refuses
to start on a non-loopback address without a password. Basic auth over plain HTTP is
unencrypted, so keep it on a network you trust. Write requests need an `X-Requested-With`
header (CSRF guard), and device strings are rendered as text only.

## CLI

`python3 watcher.py <command>` with `TRIPLINE_CONFIG` set: `status`, `report [--hours N]`,
`arm`, `home`, `away`, `guest HOURS|off`, `known add|del|list`.

## Tests

```
pip install flask
python -m unittest discover -s tests -t . -v
```

## Privacy and legal

This records the presence of nearby wireless devices, including your neighbors' and
passersby's. It is passive: it transmits nothing and does not read traffic contents.
Laws on collecting device identifiers differ by country and state. Run it only on property
you control, keep `retention_days` short, and check your local rules.

## License

GPL-3.0-or-later. See `LICENSE`. Modified versions that you distribute must be released under the same license with source.

## Not yet done

Vehicle detection via `rtl_433` (TPMS sensors), additional notification channels, and
verification on real hardware.
