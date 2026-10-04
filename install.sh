#!/usr/bin/env bash
# Tripline installer for Debian-family Linux (Raspberry Pi OS, Debian, Ubuntu).
#
#   sudo ./install.sh [options]
#
# Installs Kismet from the official apt repository, the Tripline code, a config with
# generated credentials, and systemd services. Safe to re-run: it upgrades the code and
# keeps your existing config and database.
#
# Options:
#   --wifi-iface IFACE     monitor-mode Wi-Fi adapter (default: auto-detect, else ask)
#   --web-bind ADDR        web UI address (default 127.0.0.1; anything else gets a generated password)
#   --web-port PORT        web UI port (default 8080)
#   --ntfy-topic NAME|auto enable ntfy alerts ("auto" generates a long random topic)
#   --no-kismet            skip the Kismet install and its config (use your own Kismet)
#   --no-packages          skip apt entirely (you installed the dependencies yourself)
#   --no-services          do not install or start systemd units
#   --uninstall            stop and remove services and code (keeps config and data)
#   --purge                with --uninstall: also remove config, data and the service user
#   -y, --yes              never prompt
#   -h, --help             show this help
#
# Environment overrides (for packaging and tests): PREFIX, ETC_DIR, DATA_DIR, UNIT_DIR.
set -euo pipefail

PREFIX="${PREFIX:-/opt/tripline}"
ETC_DIR="${ETC_DIR:-/etc/tripline}"
DATA_DIR="${DATA_DIR:-/var/lib/tripline}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
KISMET_ETC="${KISMET_ETC:-/etc/kismet}"
SVC_USER="tripline"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WIFI_IFACE="" WEB_BIND="127.0.0.1" WEB_PORT="8080" NTFY_TOPIC=""
DO_KISMET=1 DO_PACKAGES=1 DO_SERVICES=1 UNINSTALL=0 PURGE=0 YES=0

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}" || true; }
ask()  { # ask "question" -> sets REPLY; empty when non-interactive
  REPLY=""; if [ "$YES" = 0 ] && [ -t 0 ]; then read -r -p "$1 " REPLY || true; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --wifi-iface) WIFI_IFACE="${2:?}"; shift 2 ;;
    --web-bind)   WEB_BIND="${2:?}"; shift 2 ;;
    --web-port)   WEB_PORT="${2:?}"; shift 2 ;;
    --ntfy-topic) NTFY_TOPIC="${2:?}"; shift 2 ;;
    --no-kismet)  DO_KISMET=0; shift ;;
    --no-packages) DO_PACKAGES=0; shift ;;
    --no-services) DO_SERVICES=0; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    --purge)      PURGE=1; shift ;;
    -y|--yes)     YES=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root: sudo ./install.sh"
[[ "$WEB_PORT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT" -ge 1 ] && [ "$WEB_PORT" -le 65535 ] || die "bad --web-port"
[[ "$WIFI_IFACE" =~ ^[A-Za-z0-9_.-]*$ ]] || die "bad --wifi-iface"
[[ "$NTFY_TOPIC" =~ ^[A-Za-z0-9_-]*$ ]] || die "--ntfy-topic may contain only letters, digits, - and _"

have_systemd() { [ "$DO_SERVICES" = 1 ] && command -v systemctl >/dev/null && [ -d /run/systemd/system ]; }

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  say "Stopping services"
  if have_systemd; then
    for u in tripline-sync tripline-web tripline-watcher; do
      systemctl disable --now "$u" 2>/dev/null || true
    done
    systemctl disable --now kismet 2>/dev/null || true
  fi
  rm -f "$UNIT_DIR"/tripline-{watcher,web,sync}.service "$UNIT_DIR"/kismet.service
  have_systemd && systemctl daemon-reload
  rm -rf "$PREFIX"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$ETC_DIR" "$DATA_DIR"
    id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
    say "Removed code, config, data and the $SVC_USER user. Kismet itself was left installed (apt remove kismet)."
  else
    say "Removed services and code. Kept $ETC_DIR and $DATA_DIR (use --purge to delete them)."
  fi
  exit 0
fi

# ---------------------------------------------------------------- checks
[ -f "$SRC/watcher.py" ] && [ -d "$SRC/sources" ] || die "run this from a Tripline checkout"
command -v python3 >/dev/null || [ "$DO_PACKAGES" = 1 ] || die "python3 is required"

APT=0
if [ "$DO_PACKAGES" = 1 ]; then
  command -v apt-get >/dev/null || die "apt-get not found. This installer targets Debian-family systems. On other distros install Kismet and Flask yourself, then re-run with --no-packages --no-kismet."
  APT=1
fi

# ---------------------------------------------------------------- packages
if [ "$APT" = 1 ]; then
  say "Installing dependencies"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-flask iw wget gnupg ca-certificates >/dev/null
fi

if [ "$DO_KISMET" = 1 ]; then
  if [ "$APT" = 1 ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    CODENAME="${VERSION_CODENAME:-}"
    ARCH="$(dpkg --print-architecture)"
    [ -n "$CODENAME" ] || die "cannot determine the distribution codename"
    if ! command -v kismet >/dev/null; then
      say "Adding the official Kismet repository ($CODENAME, $ARCH)"
      case "$CODENAME/$ARCH" in
        bookworm/amd64|bookworm/arm64|trixie/amd64|trixie/arm64|jammy/*|focal/*|noble/amd64|noble/arm64) ;;
        *) warn "$CODENAME/$ARCH is not on Kismet's published package list; the install may fail." ;;
      esac
      wget -qO- https://www.kismetwireless.net/repos/kismet-release.gpg.key \
        | gpg --dearmor >/usr/share/keyrings/kismet-archive-keyring.gpg
      echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/$CODENAME $CODENAME main" \
        >/etc/apt/sources.list.d/kismet.list
      apt-get update -qq
      # Answer the "install suid-root helpers" question non-interactively.
      echo "kismet-capture-common kismet-capture-common/install-setuid boolean true" | debconf-set-selections || true
      say "Installing Kismet (this can take a few minutes)"
      apt-get install -y -qq kismet >/dev/null
    else
      say "Kismet already installed: $(kismet --version 2>/dev/null | head -1)"
    fi
  else
    command -v kismet >/dev/null || warn "kismet not found and --no-packages was given; install it before starting the services."
  fi
fi

# ---------------------------------------------------------------- service user
if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "Creating system user $SVC_USER"
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || adduser --system --home "$DATA_DIR" --shell /usr/sbin/nologin --group "$SVC_USER"
fi
if [ "$DO_KISMET" = 1 ]; then
  getent group kismet >/dev/null || groupadd --system kismet
  usermod -aG kismet "$SVC_USER"
  getent group bluetooth >/dev/null && usermod -aG bluetooth "$SVC_USER" || true
fi

# ---------------------------------------------------------------- code
say "Installing code to $PREFIX"
install -d "$PREFIX" "$PREFIX/sources"
install -m 0644 "$SRC"/watcher.py "$SRC"/web.py "$SRC"/known_sync.py "$SRC"/dashboard.html "$PREFIX"/
install -m 0644 "$SRC"/sources/*.py "$PREFIX/sources/"

install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"
install -d -m 0750 "$ETC_DIR"
chgrp "$SVC_USER" "$ETC_DIR"

# ---------------------------------------------------------------- config
CFG="$ETC_DIR/config.ini"
KISMET_PW=""
setkey() { # setkey SECTION KEY VALUE  (edits the first matching key inside the section)
  local sec="$1" key="$2" val="$3"
  sed -i "/^\[$sec\]/,/^\[/ s|^$key *=.*|$key = $val|" "$CFG"
}
if [ -f "$CFG" ]; then
  say "Keeping existing config $CFG"
  KISMET_PW="$(sed -n '/^\[kismet\]/,/^\[/ s/^password *= *//p' "$CFG" | head -1)"
else
  say "Writing $CFG"
  install -m 0640 -g "$SVC_USER" "$SRC/config.example.ini" "$CFG"
  KISMET_PW="$(rand 28)"
  setkey kismet password "$KISMET_PW"
  setkey detect db_path "$DATA_DIR/tripline.db"
  setkey web port "$WEB_PORT"
  setkey web bind "$WEB_BIND"
  sed -i "s|/etc/tripline/known_devices.txt|$ETC_DIR/known_devices.txt|" "$CFG"
  case "$WEB_BIND" in
    127.0.0.1|localhost|::1) ;;
    *) WEB_PW="$(rand 20)"; setkey web password "$WEB_PW"
       say "Web UI is on $WEB_BIND:$WEB_PORT. Login: admin / $WEB_PW" ;;
  esac
  if [ -n "$NTFY_TOPIC" ]; then
    [ "$NTFY_TOPIC" = auto ] && NTFY_TOPIC="tripline-$(rand 24)"
    setkey ntfy topic "$NTFY_TOPIC"
    say "ntfy alerts on. Subscribe to topic: $NTFY_TOPIC (app, or https://ntfy.sh/$NTFY_TOPIC)"
  fi
fi
[ -f "$ETC_DIR/known_devices.txt" ] || install -m 0640 -g "$SVC_USER" "$SRC/examples/known_devices.txt" "$ETC_DIR/known_devices.txt"

# ---------------------------------------------------------------- Kismet config
if [ "$DO_KISMET" = 1 ]; then
  detect_iface() {
    command -v iw >/dev/null || return 0
    local def; def="$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
    iw dev 2>/dev/null | awk '$1=="Interface"{print $2}' | grep -vx "${def:-__none__}" || true
  }
  if [ -z "$WIFI_IFACE" ]; then
    mapfile -t CAND < <(detect_iface)
    if [ "${#CAND[@]}" = 1 ]; then
      WIFI_IFACE="${CAND[0]}"; say "Using Wi-Fi adapter $WIFI_IFACE (the only one not carrying your default route)"
    else
      ask "Wi-Fi interface for monitoring [${CAND[*]:-none found}]:"
      WIFI_IFACE="${REPLY:-${CAND[0]:-}}"
    fi
  fi
  if [ -z "$WIFI_IFACE" ]; then
    warn "No monitor Wi-Fi adapter chosen. Plug one in, then re-run with --wifi-iface IFACE. Kismet will start with Bluetooth only."
  fi

  say "Writing $KISMET_ETC/kismet_site.conf"
  install -d "$KISMET_ETC"
  {
    echo "# Generated by Tripline install.sh. Edit freely; re-running replaces this file."
    if [ -n "$WIFI_IFACE" ]; then
      sed -e "s|^source=wlan1:|source=$WIFI_IFACE:|" "$SRC/examples/kismet_site.conf"
    else
      sed -e '/^source=wlan1:/d' "$SRC/examples/kismet_site.conf"
    fi
  } >"$KISMET_ETC/kismet_site.conf"
  install -d -o "$SVC_USER" -g "$SVC_USER" /var/log/kismet

  say "Setting Kismet web credentials"
  install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR/.kismet"
  printf 'httpd_username=kismet\nhttpd_password=%s\n' "$KISMET_PW" >"$DATA_DIR/.kismet/kismet_httpd.conf"
  chown "$SVC_USER:$SVC_USER" "$DATA_DIR/.kismet/kismet_httpd.conf"
  chmod 0600 "$DATA_DIR/.kismet/kismet_httpd.conf"

  [ -d /sys/class/bluetooth ] && ls /sys/class/bluetooth 2>/dev/null | grep -q . \
    || warn "No Bluetooth adapter found; Bluetooth detection will not work until one is present."
fi

# ---------------------------------------------------------------- services
if have_systemd; then
  say "Installing systemd services"
  for u in tripline-watcher tripline-web tripline-sync; do
    sed -e "s|^User=.*|User=$SVC_USER|" \
        -e "s|/etc/tripline/config.ini|$CFG|g" \
        -e "s|/opt/tripline|$PREFIX|g" "$SRC/systemd/$u.service" >"$UNIT_DIR/$u.service"
  done
  if [ "$DO_KISMET" = 1 ]; then
    sed -e "s|^User=.*|User=$SVC_USER|" -e "s|^Group=.*||" "$SRC/systemd/kismet.service" >"$UNIT_DIR/kismet.service"
    # Kismet reads ~/.kismet; give the service the data dir as its home.
    GROUPS_LIST="kismet"; getent group bluetooth >/dev/null && GROUPS_LIST="kismet bluetooth"
    sed -i "/^User=/a Environment=HOME=$DATA_DIR\nSupplementaryGroups=$GROUPS_LIST\nWorkingDirectory=$DATA_DIR" "$UNIT_DIR/kismet.service"
  fi
  systemctl daemon-reload
  UNITS="tripline-watcher tripline-web"
  [ "$DO_KISMET" = 1 ] && UNITS="kismet $UNITS"
  # shellcheck disable=SC2086
  systemctl enable --now $UNITS
  sleep 2
  for u in $UNITS; do
    systemctl is-active --quiet "$u" && say "$u: running" || warn "$u is not running: journalctl -u $u -n 30"
  done
  if grep -Eq '^sources *= *[^ ]' "$CFG"; then
    systemctl enable --now tripline-sync && say "tripline-sync: running"
  else
    say "Known-device sync (UniFi, file) is off. Set [sync] sources in $CFG, then: sudo systemctl enable --now tripline-sync"
  fi
else
  say "Skipping services. Run by hand with: TRIPLINE_CONFIG=$CFG python3 $PREFIX/watcher.py run"
fi

# ---------------------------------------------------------------- summary
cat <<EOF

Tripline is installed.
  Web UI:    http://$WEB_BIND:$WEB_PORT   (reach it remotely with: ssh -L $WEB_PORT:127.0.0.1:$WEB_PORT <pi>)
  Config:    $CFG
  Data:      $DATA_DIR
  CLI:       sudo -u $SVC_USER env TRIPLINE_CONFIG=$CFG python3 $PREFIX/watcher.py status

Next: leave it in learning mode for 1-2 weeks, then press Arm in the web UI.
Uninstall: sudo ./install.sh --uninstall [--purge]
EOF
