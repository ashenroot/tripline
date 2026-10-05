# Tripline

Passive wireless presence detection for one building, on a single Raspberry Pi.
Kismet captures Wi-Fi and Bluetooth; Tripline logs sightings to SQLite, alerts when an
unknown device stays above a signal-strength floor, and serves a web dashboard.

Inspired by the old WUDS project (wireless MAC-based intruder alerts), rebuilt for a world of randomized addresses.

It detects "something new is nearby." It does not identify people.

**Contents:** [Status](#status) · [How it works](#how-it-works) · [Install](#install-raspberry-pi-os-debian-ubuntu) · [Updating](#updating) · [First days](#first-days-a-checklist) · [Using the web interface](#using-the-web-interface) · [Reading a device](#reading-a-device) · [Modes and alerts](#modes-and-alerts) · [Configuration reference](#configuration-reference) · [Vehicle detection](#vehicle-detection-rtl-sdr) · [Entities](#entities-and-link-suggestions) · [Known-device sources](#known-device-sources) · [Troubleshooting](#troubleshooting) · [CLI](#cli) · [Privacy](#privacy-and-legal)

## Status

Early. The logic is covered by automated tests that run against mock Kismet, UniFi and
webhook servers. A pilot install on a Raspberry Pi has confirmed the following against a real
Kismet: the connection and both data sources (Wi-Fi monitor adapter and Bluetooth), signal
strength, associated BSSIDs (`dot11.device.last_bssid`), probed SSIDs, and the Bluetooth
fields listed under [Reading a device](#reading-a-device).

Still unverified on real hardware:

- UniFi client-list field names across Network versions (the `unifi` known-device source).
- The `rtl_433` JSON fields and dual-band hopping (vehicle detection).
- The advertisement bytes format (`scan_data_bytes`) behind the Bluetooth manufacturer lines.
- The installer's suid-root debconf answer for Kismet.

Run `watcher.py doctor` first on real hardware. Reports and fixes from real hardware are
the most useful contribution right now.

## How it works

Kismet listens passively and Tripline polls it every `poll_seconds`. Every device Kismet
reports is stored, and what happens next depends on what kind of device it is.

- **Static-address devices** (a stable MAC: most IoT gear, laptops on their home network,
  many wearables) alert when above the RSSI floor for `dwell_seconds`, unless they are known.
- **Rotating-address devices** (modern phones, many Bluetooth devices) cannot be told apart,
  so the watcher counts distinct strong rotating addresses in a sliding window. In `home`
  mode it alerts above the learned household peak plus a margin; in `away` mode, above the
  away margin.
- **Your own network** is excluded from the noise. Clients associated with your access
  points (`home_bssids` in the config, or the My networks list in the Devices tab) and devices
  from a known-device source (UniFi, a text file, or your own plugin) are marked known
  automatically. Hand edits in the UI always win.
- **Entities** group a person's devices, wearables and vehicle sensors into one record, with
  suggestions from probed network names and shared appearances.
- **Vehicles:** with an RTL-SDR dongle, tyre-pressure sensor IDs identify cars arriving at the
  property.
- **Modes:** `learning` (log only), `home`, `away`, plus a timed guest window that
  suppresses alerts.

Terms used throughout:

| Term | Meaning |
|---|---|
| **MAC** | The hardware address a device broadcasts. Phones and many Bluetooth devices randomize it. |
| **BSSID** | The MAC of one access-point radio. One router usually has several, one per SSID and band. |
| **SSID** | A Wi-Fi network name. |
| **RSSI** | Received signal strength in dBm. Closer to 0 is stronger: -40 is close, -80 is faint. |
| **Probe** | A device asking for a named network it has joined before. Most current phones no longer send named probes. |
| **Known** | A device you have told Tripline to ignore (by hand, by network, or by a sync source). |
| **Rotating** | An address that changes over time. It shows up as a stream of unrelated devices. |
| **Entity** | A person, household, vehicle or visitor you have grouped from several devices. |

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
releases; 32-bit Raspberry Pi OS is not on Kismet's list.

`config.ini` holds secrets and is git-ignored. Never commit it.

### Reaching the web interface from another computer

By default the UI listens on `127.0.0.1:8080` of the Pi only. To open it from another machine:

1. In `/etc/tripline/config.ini` set `[web] bind = 0.0.0.0`, `port = 8080` and a `password`
   (the app refuses to start on a non-loopback address without one).
2. `sudo systemctl restart tripline-web`
3. Browse to `http://<pi-address>:8080` and sign in as `admin` with that password.

Alternatives that keep the port closed: an SSH tunnel
(`ssh -L 8080:127.0.0.1:8080 you@<pi>`, then browse to `http://127.0.0.1:8080`) or Tailscale.
Basic auth over plain HTTP is unencrypted, so keep a LAN-facing UI on a network you trust.

### Manual install

1. Install Kismet from the official apt repository (kismetwireless.net, packages), choose
   suid-root helpers, and put the user that runs it in the `kismet` group.
2. Create `~/.kismet/kismet_httpd.conf` for that user with `httpd_username` and `httpd_password`.
3. `sudo cp examples/kismet_site.conf /etc/kismet/` and set your Wi-Fi interface (`iw dev`).
4. Copy `watcher.py web.py known_sync.py identity.py insight.py tpms.py dashboard.html` and `sources/` to `/opt/tripline`,
   copy `config.example.ini` to `/etc/tripline/config.ini` and edit it.
5. Copy `systemd/*.service` to `/etc/systemd/system/`, set `User=`, then
   `sudo systemctl enable --now kismet tripline-watcher tripline-web` (add `tripline-tpms` if you use an SDR).

## Updating

```
cd tripline        # your clone
git pull
sudo ./install.sh
```

The installer keeps your config and database, copies the new code, and restarts the
Tripline services (Kismet keeps running, so capture is not interrupted). Afterwards
hard-refresh the browser (Ctrl+Shift+R) so it loads the new dashboard page. Database changes
(new columns, merged duplicate rows) run automatically the first time the new code starts.

If the clone lives in `/opt/tripline` itself, the installer detects that and updates in place.

## First days: a checklist

1. **Run the check.** `python3 /opt/tripline/watcher.py doctor` (with `TRIPLINE_CONFIG`
   set, for example `sudo -u tripline env TRIPLINE_CONFIG=/etc/tripline/config.ini python3 /opt/tripline/watcher.py doctor`).
   See [Troubleshooting](#troubleshooting) for how to read it.
2. **Tell Tripline which networks are yours.** Devices tab, My networks: add one BSSID for each
   of your access points (the rest of an AP's BSSIDs are matched automatically, see below).
   Add your SSIDs under My network names.
3. **Mark your own devices.** Use the Devices tab (Mark known) or a known-device source such
   as UniFi. Mark your vehicles under Vehicles if you use the SDR.
4. **Leave it in `learning` mode for one to two weeks.** Nothing alerts during learning. This
   builds the household peak of rotating devices that `home` mode compares against.
5. **Arm it.** Press Arm now on the dashboard, or `python3 /opt/tripline/watcher.py arm`. This
   ends learning and switches to `home`. Use `away` when the house is empty.

## Using the web interface

Three tabs: Dashboard, Devices, Entities. The header shows whether the sensor is live ("sensor
live" turns to "no sightings in 2 min" when Kismet stops reporting).

### Dashboard tab

**Tiles.** Each tile opens the list behind its number.

| Tile | Shows | Click |
|---|---|---|
| Mode | `LEARNING`, `HOME` or `AWAY`, and in learning a progress bar toward 14 days | Display only |
| Unknown nearby | Distinct non-rotating, unknown devices heard in the last 60 seconds, with a count of known static devices nearby | Devices tab, "Unknown nearby now" |
| Rotating devices | Distinct rotating addresses above the signal floor in the last `random_window_seconds`, with the alert limit and the household peak | Devices tab, "Rotating nearby now" |
| Alerts 24h | Alerts raised in the last day and the most recent one | A list of those alerts |

**Signal timeline and radar.** The timeline draws one trace per device for the last 10
minutes. A rising trace is approaching; a trace that peaks below the dashed line is passing by.
The radar plots devices heard in the last 5 minutes by signal strength only. Direction is
arbitrary because one sensor cannot determine bearing, and the dashed rings mark the alert
floors. Colors: red is an unknown device past the alert floor, amber is unknown, green is
known, blue is a rotating address. Tap a trace or a blip to see the device under Selected device.

**Show chips.** Known and Rotating are off by default, so only unknown static devices are
drawn. Turn them on to see everything. The setting is saved in that browser only, so two
computers can look different until their chips match.

**Choose devices.** When the timeline is crowded, the Choose devices button opens a panel listing every
device heard in the last 10 minutes, with its color, name, MAC, radio and latest signal. Tick the
ones to draw. Search by name, vendor or MAC; filter by Wi-Fi or Bluetooth and by unknown, known or
rotating. The shortcuts are Show all listed, Hide all listed, Only unknown and Strongest 10. Once
you choose, exactly those devices are drawn on both the timeline and the radar, and the Known and
Rotating chips dim. Back to automatic returns to the chips. The selection is saved in that browser.
On the timeline, labels at the right edge are skipped where they would overlap, with unknown
devices labeled first.

**Selected device.** MAC, type, vendor, live signal, last and first seen, sighting count, a
one-hour signal graph, and Mark known / Update label / Unmark for static devices.

**Controls.** Home and Away set the mode. Arm now appears during learning. Guest suppresses
alerts for 2, 8 or 24 hours; Off ends it early.

**Live feed.** Alerts and newly seen devices, newest first.

**Last 24 hours.** One bar per time slot, split into rotating, unknown static and known static
devices, with red marks where alerts fired. Hover for the counts.

### Devices tab

Top to bottom:

- **My network names.** Your own SSIDs. A device that probes for one of them is treated as
  yours. See [Entities](#entities-and-link-suggestions) for how names are also used for
  suggestions.
- **My networks.** Access points that are yours. See [My network and Mark known](#my-network-and-mark-known).
  The list shows each one's vendor and last seen time; Add network takes a BSSID and an optional name.
- **Vehicles** (only with the SDR on). Tyre-pressure sensors. Mark your own vehicles known and label them.
- **Devices table.** Everything Kismet has reported.
  - *Filter dropdown:* Unknown static (the default), Known, Rotating address, All, Unknown
    nearby now, Rotating nearby now.
  - *Radio dropdown:* Wi-Fi and Bluetooth, Wi-Fi only, or Bluetooth only.
  - *Search* matches MAC, vendor, label and broadcast name.
  - *Sorting:* click the Device, Last seen or Peak headers; click again to reverse. Sorting runs
    on the server, so it applies to the whole list (the table shows up to 300 rows).
  - *Columns:* Device (label, name or vendor over the MAC); Type (Wi-Fi or Bluetooth, plus
    "rotating", "linked" for entity members, and the number of probed SSIDs); Last seen; Peak
    (strongest signal ever recorded); Seen (number of times recorded); Label (editable).
  - *Buttons:* **Mark known** / **Unmark**; **My network** / **Not my network** (Wi-Fi
    devices); **Link** (adds the device to an entity). The bulk button marks every device
    currently listed as known.
  - *Click anywhere else on a row* to open the device detail panel.
- **Reset.** Removes everything discovered (devices, sightings, probes, vehicles, entities,
  alerts) and restarts learning. My networks and My network names are kept unless you tick the
  box. You must type RESET to confirm.

### Entities tab

Suggested links lists records that may belong together, with the evidence and a confidence of
low, medium or high. Accept links them, Add to entity joins an existing entity, Not the same
dismisses the suggestion. Entity cards list the signals seen (Wi-Fi, Bluetooth, tyre sensors,
network names), each member, and visit patterns: how many visits in the last 14 days, the
average length, the last arrival, and arrivals by hour of day. See
[Entities and link suggestions](#entities-and-link-suggestions).

## Reading a device

Click a row in the Devices table to open the detail panel. Fields appear when the data exists.

**Identity**

| Field | Meaning |
|---|---|
| MAC, Radio, Vendor | The address, Wi-Fi or Bluetooth, and the manufacturer Kismet resolved from the address prefix |
| Broadcast name | The name the device advertises (Bluetooth names, access-point names) |
| Fingerprint | The advertisement facts that identify this device across address rotations, how many addresses carry them, and the entity they are linked to |
| Address type | Locally administered means a private or random address; globally unique means assigned to the vendor |
| Vendor prefix | The first three bytes of the address, which identify the manufacturer |
| Kismet type | What Kismet thinks it is (for example Wi-Fi client or access point) |

**Presence**

| Field | Meaning |
|---|---|
| First seen, Last seen | Absolute times, and how long ago the last one was |
| Peak signal | The strongest reading ever recorded |
| Sightings | Times this device has been recorded |
| Last hour | Sightings in the last hour with average, weakest and strongest signal |
| Rough range now | An estimate from signal strength (under 3 m up to over 100 m). It is crude: walls, antennas and body position change signal strength a lot |
| Signal trend | Over the last 10 minutes: getting closer, steady or moving away, with the slope in dB per minute |
| Usual hours of day | When the device is normally heard (all history). The current hour is amber, and a warning appears if the device is rarely heard at this hour |
| Days seen | Which of the last 14 days it was heard on |
| Visits in the last 24 h | Runs of sightings; a gap over 5 minutes starts a new visit |
| Most often heard at the same time | Other devices that share its 5-minute windows, ranked by overlap. Click one to open it. Useful for working out what an unknown device belongs to |

**Network (Wi-Fi)**

| Field | Meaning |
|---|---|
| Connected to | The access point it is associated with, whether that AP is in My networks, and its vendor or label |
| Channels heard on, Frequency | Where it transmits |
| Probe, Beacon, Response fingerprint | Numbers Kismet computes from how the device builds its frames. The same hardware model gives the same value, so two different MACs with the same fingerprint are likely the same model of device |
| Networks it broadcasts | For an access point: each SSID with encryption, channel, WPS and country details |
| Clients seen on it | For an access point: the clients Kismet has seen associated with it, each resolved to a name where known. Click one to open it |
| AP uptime | Estimated from the access point's beacon timestamp |
| Network names it has asked for | The SSIDs this client has probed, with the last time for each |

**Bluetooth**

| Field | Meaning |
|---|---|
| Bluetooth address | Public, static random (stable until the device restarts), resolvable private (rotates; typical of phones and wearables) or non-resolvable private (rotates). Worked out from the top two bits of the address, as the Bluetooth specification defines |
| Device class, Bluetooth type | What kind of device it declares itself to be (phone, wearable, audio, health) |
| Manufacturer data | The company in the advertisement and, for Apple devices, the message type (Nearby info, AirPods pairing, Find My, iBeacon and so on) |
| Advertised name | A name carried in the advertisement |
| Services | The advertised services, decoded where known (Battery, Heart Rate, Human Interface, Exposure Notification, Tile and so on) |
| Transmit power | The advertised transmit power, if any |

**Live from Kismet.** This section loads a moment after the panel opens, because Kismet can be
slow to answer. It shows Kismet's current counters (packets, data bytes) and any identifying fields found in
the record, and ends with a collapsible **Raw Kismet record**, which contains everything Kismet
holds about the device. If a field you expected is missing from the panel, look for it there.

Other buttons in the panel: a label box, Mark known / Unmark, and Link.

## My network and Mark known

These two buttons do different jobs.

- **My network** is for access points and other infrastructure. It adds the device's BSSID to
  your list. The access point itself is treated as yours, and so is every Wi-Fi client that
  Kismet reports as associated with that BSSID, so one click covers the clients on that AP.
  **Not my network** reverses it and marks the device unknown again.
- **Mark known** applies to a single device's MAC. Use it for a phone, a camera or any one
  thing you want to stop alerting on.

**Sibling BSSIDs.** An access point usually has a separate BSSID for each SSID and band, and a
client attaches to one of them. Tripline treats a BSSID as a sibling of one you added when bytes
2 and 3 and the last two bytes match, and the top four bits of the first byte agree. That covers
the way UniFi and similar gear derive virtual APs (`74:83:c2:27:02:3d` and `7a:83:c2:27:02:3d`,
or `...:24:fe:57` and `...:25:fe:57`). Adding one BSSID is enough. A device behind a BSSID that
differs in the last byte needs its own entry.

## Modes and alerts

The mode decides what raises an alert.

| Mode | What it does |
|---|---|
| `learning` | Logs everything and sends no alerts. Builds the household peak of rotating devices. Target: 14 days. |
| `home` | Alerts on an unknown static device that stays above the signal floor for `dwell_seconds`, and on more rotating devices at once than the household peak plus `random_margin_home`. |
| `away` | Same, with the rotating-device limit set to `random_margin_away` (0 by default): any strong rotating device counts. |
| Guest window | Suppresses alerts for 2, 8 or 24 hours (dashboard buttons, or `guest HOURS` on the CLI). |

More rules:

- A repeat alert for the same device or burst waits for `alert_cooldown_minutes`.
- Unknown vehicle sensors (SDR) alert in `home` and `away` mode, and are only logged in `learning`.
- A device is alertable only when Kismet reports a signal strength for it. Devices without a
  reading (common with Bluetooth) are still recorded and listed, but cannot alert.
- Alerts are always logged and shown in the UI. Push delivery is optional: set `[ntfy] topic`
  (use a long random name, or run your own ntfy server) and/or `[webhook] url` to receive each alert as JSON.

## Configuration reference

All settings live in `/etc/tripline/config.ini` (`config.example.ini` is the annotated template).
Restart with `sudo systemctl restart tripline-watcher tripline-web` after editing.

**`[kismet]`**

| Key | Meaning |
|---|---|
| `url`, `user`, `password` | Where Tripline reaches Kismet's REST API. The installer generates the credentials. |

**`[ntfy]` and `[webhook]`**

| Key | Meaning |
|---|---|
| `ntfy.url`, `ntfy.topic` | ntfy server and topic. Leave `topic` blank to disable. |
| `webhook.url` | Each alert is POSTed as JSON: `{"title","message","priority","ts"}`. |

**`[detect]`**

| Key | Default | Meaning |
|---|---|---|
| `poll_seconds` | 5 | How often Kismet is polled. |
| `wifi_rssi`, `bt_rssi` | -80, -85 | Signal floors in dBm. More negative detects farther out. Start permissive and tighten using the learning data. |
| `dwell_seconds` | 20 | How long an unknown static device must stay above the floor before alerting. |
| `gap_seconds` | 15 | Dropouts up to this long do not restart the dwell timer. |
| `alert_cooldown_minutes` | 30 | Minimum time between repeat alerts for the same device or burst. |
| `random_window_seconds` | 60 | Window for counting distinct strong rotating addresses. |
| `random_margin_home` | 2 | Rotating devices allowed above the household peak in `home` mode. |
| `random_margin_away` | 0 | Rotating devices allowed in `away` mode. |
| `burst_confirm_seconds` | 30 | How long a rotating-device burst must persist before it alerts. |
| `home_bssids` | blank | Your access-point BSSIDs, comma-separated. Also editable under My networks. Siblings are matched automatically. |
| `home_ssids` | blank | Your network names, comma-separated. Also editable under My network names. |
| `ssid_marks_known` | true | Whether probing for one of your SSIDs marks a device known. Past guests who joined your Wi-Fi also probe for it; set `false` to use the names for suggestions only. |
| `sighting_interval_seconds` | 10 | At most one sighting per device per interval. Keeps the database small and the dashboard fast. |
| `retention_days` | 30 | Sightings, unknown devices and probes older than this are deleted. Devices that belong to an entity are kept. |
| `db_path` | `/var/lib/tripline/tripline.db` | The SQLite database. |

**`[web]`**

| Key | Default | Meaning |
|---|---|---|
| `bind`, `port` | `127.0.0.1`, 8080 | Address and port. A non-loopback address requires a password. |
| `user`, `password` | `admin`, blank | Basic-auth login. |

**`[vehicles]`** (see [Vehicle detection](#vehicle-detection-rtl-sdr))

| Key | Default | Meaning |
|---|---|---|
| `enabled` | false | Turned on by the installer when it finds a dongle. |
| `frequencies` | `315M, 433.92M` | Bands to watch. |
| `hop_seconds` | 10 | How long the dongle stays on each band. |
| `device` | 0 | Which dongle, by index or serial. |
| `command` | blank | Replaces the whole decoder command. `{device}` and `{freqs}` are filled in. Must print `rtl_433` JSON. |

**`[sync]` and `[source.*]`** (see [Known-device sources](#known-device-sources))

| Key | Meaning |
|---|---|
| `sync.sources` | Comma-separated sources to run (`unifi`, `file`). Blank means manage known devices by hand. |
| `sync.interval_minutes` | How often `known_sync.py` runs (default 15). |
| `source.file.path` | A text file with one `MAC label` per line. |
| `source.unifi.url`, `site` | The controller address and site (default `default`). |
| `source.unifi.api_key` or `username` / `password` | An API key (Network 10.1+) or a local non-SSO, no-MFA read-only account. |
| `source.unifi.verify_tls` | `false` accepts a self-signed certificate. |
| `source.unifi.include` | `all` for every client the controller knows, `named` for clients you gave a name. |
| `source.unifi.max_age_days` | Skip clients UniFi has not seen for this many days (default 30, `0` keeps everything). UniFi remembers every client it has ever seen, so without this old gear stays known forever. Clients skipped this way stop being known on the next sync, and Tripline deletes them once they have also been unheard for `retention_days`. A client with no last-seen time in UniFi is kept. |

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
behavior of dual-band hopping on a single dongle, and the USB detection in the installer.

## Entities and link suggestions

Randomized addresses mean one person shows up as many unrelated records. Tripline keeps
weak evidence and lets you join the pieces by hand into an **entity** (a person, household,
vehicle, regular visitor or contractor).

- **Probed network names.** Some devices ask for networks they have joined before. Add your
  own SSIDs under "My network names" (or `home_ssids` in the config): a device that probes
  for one is treated as yours. Names are weighted by rarity, so `xfinitywifi` counts for
  almost nothing and `Smith_Cabin_5G` for a lot. Two records that share rare names are
  suggested as one device. Most current phones send no named probes, so this helps on some
  devices only.
- **Whole-entity matching.** Once an entity exists, new records are compared against everything
  it has shown across all its members. A record that shares a few probed names with each of
  an entity's phones is suggested as "part of Bob" even if no single phone overlaps enough.
  Members never need to appear on the same trip: a watch one day, tyre sensors another, and a
  phone's network names a third all count toward the same entity, and each entity card lists
  which signals have been seen and when. (Shared time windows are still pairwise.)
- **Device fingerprints (rotating Bluetooth and Wi-Fi addresses).** A device that rotates its
  address keeps its advertisement facts: device class, advertised services, manufacturer data,
  advertised name and transmit power. Addresses that share those facts, never overlap in time and
  follow one another within a few minutes are suggested as one device ("One device rotating its
  address"). Accepting links the fingerprint to an entity: every future rotating address with
  that fingerprint is treated as the entity's device, marked known and not counted as rotating,
  for as long as the entity is trusted and not lapsed. Several phones of one model share a
  fingerprint, but their addresses overlap, so those are never suggested. Use it for a
  distinctive device (a named watch, an unusual service list). A visitor with the same model and
  settings would match too, and the suggestion's confidence rises with how many distinguishing
  facts the fingerprint has. Wi-Fi probe fingerprints identify a hardware and driver
  combination, so they score low.
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
  covers the records you have already seen. Link the stable signals (a wearable, tyre
  sensors) for lasting results.
- Probed network names reveal where a person has been. They are deleted with the device
  record after `retention_days` unless the device belongs to an entity. They are never sent
  anywhere.

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

## Troubleshooting

**`watcher.py doctor`** connects to Kismet and reports what it finds. Run it as the service
user so it reads the same config:
`sudo -u tripline env TRIPLINE_CONFIG=/etc/tripline/config.ini python3 /opt/tripline/watcher.py doctor`

| Line | What it means |
|---|---|
| `reachable at ...` | Tripline can talk to Kismet. If not, check that `kismet` is running and the `[kismet]` URL and credentials. |
| Data sources | Each Kismet source with `running` or `NOT running`. A source that is not running needs fixing in `/etc/kismet/kismet_site.conf`. |
| `N devices` by radio | What Kismet heard in the last hour. |
| `signal strength present on ...` | Devices with a signal reading, overall and per radio. Devices without one are listed in the Devices tab but cannot alert. |
| `associated BSSID present on ...` | Whether Kismet reports which access point a client is attached to. My network and `home_bssids` depend on it. |
| `probed SSIDs present on ...` | Devices sending named probes. A low number is normal. |
| `Bluetooth identifying fields` | Which fields in Kismet's Bluetooth records identify devices. |

`doctor --dump out.json` saves three raw Bluetooth and three raw Wi-Fi device records. They
contain MAC addresses and names of nearby devices, so review the file before sharing it. To share
only the field names, print the keys instead of the values.

Common problems:

| Symptom | Likely cause and fix |
|---|---|
| A button seems to do nothing after an update | The browser is holding the old page. Hard-refresh (Ctrl+Shift+R). The installer restarts the services itself, but a manually copied install needs `sudo systemctl restart tripline-web tripline-watcher`. |
| Bluetooth devices are missing | They may be hidden by the default filters. On the Devices tab choose Filter: All and Radio: Bluetooth only, then sort by Last seen. A phone stops advertising when idle and locked. Opening its Bluetooth settings makes it advertise. |
| Two computers show different dashboards | The Known and Rotating chips are saved per browser. |
| Devices stay unknown after My network | Add each BSSID of the access point (siblings are matched when they differ in the middle bytes or the first byte's low bits). A client is attached to a particular BSSID, and Kismet only reports the association when it hears the client's data traffic on its channel. |
| The dashboard feels slow | Raise `sighting_interval_seconds`, or lower `retention_days`. |
| No hostnames | A passive sensor cannot read them: they travel inside encrypted traffic. Bluetooth names and access-point names are shown when advertised. A known-device source such as UniFi can supply names. |

## Web interface and security

Served at `http://127.0.0.1:8080` by default (see
[Reaching the web interface](#reaching-the-web-interface-from-another-computer)). The app
refuses to start on a non-loopback address without a password. Write requests need an
`X-Requested-With` header (CSRF guard), and device strings are rendered as text only. The raw
Kismet record and probed names are shown to anyone who can sign in.

## CLI

`python3 watcher.py <command>` with `TRIPLINE_CONFIG` set.

| Command | Does |
|---|---|
| `run [--once]` | The main loop (the service runs this). `--once` does one poll cycle for testing. |
| `status` | Mode and counts. |
| `doctor [--dump FILE]` | Checks Kismet and the fields Tripline relies on. |
| `report [--hours N]` | Unknown static devices, for tagging. |
| `arm` | Ends learning, records the household peak, switches to `home`. |
| `home`, `away` | Switch mode. |
| `guest HOURS` / `guest off` | Start or end the guest window. |
| `known add MAC [label]`, `known del MAC`, `known list` | Manage known devices. |
| `reset [--everything] [--yes]` | Wipes discovered data and restarts learning. `--everything` also clears My networks and names. |

`known_sync.py once` runs the known-device sources once; `tpms.py run` runs the vehicle decoder.

## Contributing

Issues and pull requests are welcome. See `CONTRIBUTING.md` for the workflow and the test setup.

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

Additional notification channels, matching of the Wi-Fi capability fingerprints against known
device models, and verification of the SDR and UniFi paths on real hardware.
