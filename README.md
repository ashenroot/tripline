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
- The probed-SSID field (`dot11.device.probed_ssid_map`) and its JSON shape.

Run `watcher.py doctor` first on real hardware; it checks most of these.

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
- **Entities:** you can group a person's devices, wearables and vehicle sensors into one
  entity, with suggestions from probed network names and shared appearances.
- **Vehicles:** with an RTL-SDR dongle, tyre-pressure sensor IDs identify cars arriving at the
  property (see Vehicle detection below).
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
| `--bt-iface hci1` | Choose the Bluetooth adapter (default: a USB adapter if present, else the built-in) |
| `--sdr` / `--no-sdr` | Force or skip vehicle detection (default: enabled when an RTL-SDR or Nooelec dongle is plugged in) |
| `--sdr-freq LIST` | TPMS frequencies (default `315M,433.92M`: both bands) |
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
4. Copy `watcher.py web.py known_sync.py identity.py tpms.py dashboard.html` and `sources/` to `/opt/tripline`,
   copy `config.example.ini` to `/etc/tripline/config.ini` and edit it.
5. Copy `systemd/*.service` to `/etc/systemd/system/`, set `User=`, then
   `sudo systemctl enable --now kismet tripline-watcher tripline-web` (add `tripline-tpms` if you use an SDR, and copy `tpms.py` too).

## Vehicle detection (RTL-SDR)

With an RTL-SDR or Nooelec dongle, `tpms.py` runs `rtl_433` and records tyre-pressure
sensor IDs. Each sensor ID is a fixed identifier, so it works despite randomized MACs. A car
has up to four. Sensors transmit while the wheels turn, so this reports vehicles arriving
and leaving, and does not see parked ones.

- Unknown sensors raise an alert in `home` and `away` mode (respecting the guest window and
  the alert cooldown). In `learning` mode they are only logged.
- Sensors are never marked known automatically. Mark your own vehicles in the Vehicles
  section of the Devices tab and give them a label.
- The installer enables this when it finds a dongle, installs `rtl-433`, and blacklists the
  kernel TV-tuner driver that otherwise claims the device (a reboot or re-plug may be needed).
  Re-run `install.sh` after plugging a dongle in later.
- A sensor's band is not known in advance, so the default watches 315 MHz and 433.92 MHz.
  One dongle hops between them every `hop_seconds` (default 10), so each band is covered about
  half the time and a short drive past can be missed. Two dongles, one per band, give full
  coverage.
- `[vehicles] command` replaces the whole decoder command, and `tpms.py run --stdin` reads
  `rtl_433` JSON from a pipe.
- Range is short. A road several hundred feet away is unlikely to register, which is the
  point; a sensor on your own driveway should.

Unverified on real hardware: the `rtl_433` JSON fields (`type: TPMS`, `pressure_*`), the
behavior of dual-band hopping on a single dongle, and the Bluetooth and USB detection in the
installer.

## Entities and link suggestions

Randomized addresses mean one person shows up as many unrelated records. Tripline keeps
weak evidence and lets you join the pieces by hand into an **entity** (a person, household,
vehicle, regular visitor or contractor).

- **Probed network names.** Some devices ask for networks they have joined before. Add your
  own SSIDs under "My network names" (or `home_ssids` in the config): a device that probes
  for one is treated as yours. Names are weighted by rarity, so `xfinitywifi` counts for
  almost nothing and `Smith_Cabin_5G` for a lot. Two records that share rare names are
  suggested as one device. Most current phones send no named probes, so this helps on some
  devices only. Past guests who joined your Wi-Fi also probe for it; set
  `ssid_marks_known = false` to use your SSIDs for suggestions only.
- **Tyre sensors.** Sensors heard together repeatedly are folded into one suggestion per car.
- **Shared time windows.** Devices and vehicles that keep appearing in the same 5-minute
  windows are suggested as a pair. Always-present devices are ignored.
- **Confidence** is low, medium or high, from how many independent signals agree. It is a
  rule of thumb, not a probability.
- **Nothing links automatically.** Accept or dismiss each suggestion in the Entities tab, or
  use Link on any device or vehicle row. Linking marks every member known (or leave an
  entity untrusted to keep alerting on it). Visitors and contractors can be known for a set
  number of days, after which their members become unknown again.
- Rotating addresses can be linked, but a rotated address stops appearing, so the link only
  covers the records you have already seen.
- Probed network names reveal where a person has been. They are deleted with the device
  record after `retention_days` unless the device belongs to an entity. They are never sent
  anywhere.

## Checking a new install

`python3 /opt/tripline/watcher.py doctor` (with `TRIPLINE_CONFIG` set) connects to Kismet and
reports whether the data sources are running and whether signal strength, associated BSSIDs
and probed SSIDs are actually present. `doctor --dump out.json` also saves five raw device
records, which is what to send when a field name turns out to differ on your Kismet version.

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

Additional notification channels, arrival and departure events per entity, and verification
on real hardware.
