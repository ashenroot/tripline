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
  points (`home_bssids` in the config, or the My networks box in the Devices tab) and devices from a known-device source (UniFi, a text file, or your
  own plugin) are marked known automatically. Hand edits in the UI always win.
- **Modes:** `learning` (log only), `home`, `away`, plus a timed guest window that
  suppresses alerts.
- **Dashboard:** signal-over-time timeline and radar (direction on the radar is
  arbitrary; one sensor cannot determine bearing), 24-hour activity strip, live feed, and a
  device manager.

## Install (Raspberry Pi OS, Debian, Ubuntu)

```
git clone https://github.com/ashenroot/tripline.git
cd tripline
sudo ./install.sh
```

The script installs Kismet from the official apt repository, installs Tripline to
`/opt/tripline`, creates a `tripline` service user, writes `/etc/tripline/config.ini` with
generated Kismet credentials, points Kismet at your monitor-mode Wi-Fi adapter and the
built-in Bluetooth, and enables the `kismet`, `tripline-watcher` and `tripline-web`
services. Re-running it upgrades the code and keeps your config and database.

| Option | Effect |
|---|---|
| `--wifi-iface wlan1` | Choose the monitor adapter (default: the one adapter that is not carrying your default route, else it asks) |
| `--web-bind ADDR` / `--web-port N` | Move the web UI; a non-loopback address gets a generated password, shown once |
| `--ntfy-topic auto` | Turn on ntfy alerts with a generated random topic |
| `--no-kismet` | Use your own Kismet install |
| `--no-packages` | Skip apt (other distros: install Kismet and Flask yourself first) |
| `--no-services` | Copy files only |
| `--uninstall [--purge]` | Remove services and code; `--purge` also removes config, data and the user |

Packaged Kismet builds exist for Debian bookworm/trixie (amd64, arm64) and several Ubuntu
releases; 32-bit Raspberry Pi OS is not on Kismet's list. The script's handling of Kismet's
suid-root prompt (a debconf answer) has not been verified on a real device.

Afterwards leave it in `learning` mode for 1-2 weeks, then press Arm in the web UI or run
`python3 /opt/tripline/watcher.py arm`.

`config.ini` holds secrets and is git-ignored. Never commit it.

### Manual install

1. Install Kismet from the official apt repository (kismetwireless.net, packages), choose
   suid-root helpers, and put the user that runs it in the `kismet` group.
2. Create `~/.kismet/kismet_httpd.conf` for that user with `httpd_username` and `httpd_password`.
3. `sudo cp examples/kismet_site.conf /etc/kismet/` and set your Wi-Fi interface (`iw dev`).
4. Copy `watcher.py web.py known_sync.py dashboard.html` and `sources/` to `/opt/tripline`,
   copy `config.example.ini` to `/etc/tripline/config.ini` and edit it.
5. Copy `systemd/*.service` to `/etc/systemd/system/`, set `User=`, then
   `sudo systemctl enable --now kismet tripline-watcher tripline-web`.

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
