#!/bin/sh
# Easy manager install. Run as root from the repo (or a folder that has the binary).
#
# Method A — one box that also has the access log:
#   sudo ./deploy/install-manager.sh --all-in-one --tail /var/log/nginx/access.log --journal
#
# Method A — dedicated monitor (agents will ship logs later):
#   sudo ./deploy/install-manager.sh
#
# Then: ssh -L 8787:127.0.0.1:8787 user@THISBOX
#       open http://127.0.0.1:8787/login  and create the first admin.
#
# Nothing here is an inventory. Paths are the product defaults. Override with flags.

set -eu

NAME=gpewebdefender
PREFIX=/usr/local
LISTEN=127.0.0.1:8787
HOME_PIN=US
HOMES=""
TAIL=""
JOURNAL=0
ALL_IN_ONE=0
GEOIP=""
RETAIN=168h
BIN_SRC=""

usage() {
  cat <<'EOF'
install-manager.sh — put the web-attack monitor on THIS Linux box.

  --all-in-one          also tail a local access log (one-box setup)
  --tail PATH           access log (repeat or comma-separate). implies --all-in-one
  --journal             follow systemd journal for sshd/sudo
  --listen ADDR         default 127.0.0.1:8787  (keep localhost)
  --home PIN            ISO country or lat,lon  (map landing pin)
  --homes SPEC          name=lat,lon;name=ISO   (must match agent --name)
  --geoip FILE          optional GeoLite2 / DB-IP .mmdb
  --retain DUR          default 168h
  --bin FILE            path to the Linux binary if we cannot find it
  -h, --help

You must be root. The script will:
  1. create user gpewebdefender and /var/lib/gpewebdefender
  2. make a token in /etc/gpewebdefender/env if one is not already there
  3. install the binary, rules, docs, optional packs
  4. enable systemd and start the manager
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --all-in-one) ALL_IN_ONE=1 ;;
    --tail) TAIL="${2:-}"; ALL_IN_ONE=1; shift ;;
    --journal) JOURNAL=1 ;;
    --listen) LISTEN="${2:-}"; shift ;;
    --home) HOME_PIN="${2:-}"; shift ;;
    --homes) HOMES="${2:-}"; shift ;;
    --geoip) GEOIP="${2:-}"; shift ;;
    --retain) RETAIN="${2:-}"; shift ;;
    --bin) BIN_SRC="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "run this as root (sudo)." >&2
  exit 1
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

find_bin() {
  if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then echo "$BIN_SRC"; return; fi
  for c in \
    "$here/gpewebdefender-linux-amd64" "$here/gpewebdefender" \
    "$here/gpewebdefender-linux-amd64" "$here/gpewebdefender" \
    "./gpewebdefender-linux-amd64" "./gpewebdefender"
  do
    if [ -f "$c" ]; then echo "$c"; return; fi
  done
  return 1
}

if ! bin=$(find_bin); then
  echo "cannot find the Linux binary next to the repo." >&2
  echo "build it first:" >&2
  echo "  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gpewebdefender-linux-amd64 ./cmd/gpewebdefender" >&2
  exit 1
fi

ETC=/etc/$NAME
VAR=/var/lib/$NAME
BIN=$PREFIX/bin/$NAME

id -u "$NAME" >/dev/null 2>&1 || useradd --system --home "$VAR" --shell /usr/sbin/nologin "$NAME"
mkdir -p "$VAR" "$ETC" "$VAR/rules" "$VAR/dochub" "$VAR/packs"
if [ ! -f "$ETC/env" ]; then
  tok=$(openssl rand -base64 32 2>/dev/null || dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)
  umask 077
  {
    echo "GWD_TOKEN=$tok"
    [ -n "$HOMES" ] && echo "GWD_HOMES=$HOMES"
  } > "$ETC/env"
  chmod 640 "$ETC/env"
  echo "wrote a new token to $ETC/env  (mode 640)"
else
  echo "keeping existing $ETC/env"
  if [ -n "$HOMES" ] && ! grep -q '^GWD_HOMES=' "$ETC/env"; then
    echo "GWD_HOMES=$HOMES" >> "$ETC/env"
  fi
fi
chown root:"$NAME" "$ETC/env" 2>/dev/null || chown root:root "$ETC/env"

install -o root -g root -m 755 "$bin" "$BIN"
if [ -d "$here/rules" ]; then
  cp -a "$here/rules/." "$VAR/rules/"
fi
if [ -d "$here/dochub" ]; then
  cp -a "$here/dochub/." "$VAR/dochub/"
fi
if [ -d "$here/packs" ]; then
  cp -a "$here/packs/." "$VAR/packs/"
fi
if [ -n "$GEOIP" ]; then
  if [ ! -f "$GEOIP" ]; then echo "geoip file not found: $GEOIP" >&2; exit 1; fi
  install -o "$NAME" -g "$NAME" -m 644 "$GEOIP" "$VAR/geoip.mmdb"
fi
if [ -f "$here/deploy/siem.example" ]; then
  install -o root -g root -m 755 "$here/deploy/siem.example" "$PREFIX/bin/siem"
fi
chown -R "$NAME:$NAME" "$VAR"

exec_extra=""
if [ "$ALL_IN_ONE" -eq 1 ] && [ -n "$TAIL" ]; then
  exec_extra="$exec_extra --tail $TAIL"
fi
if [ "$JOURNAL" -eq 1 ]; then
  exec_extra="$exec_extra --journal"
fi
if [ -f "$VAR/geoip.mmdb" ]; then
  exec_extra="$exec_extra --geoip $VAR/geoip.mmdb"
fi

cat > /etc/systemd/system/${NAME}.service <<EOF
[Unit]
Description=$NAME web-attack monitor
After=network.target

[Service]
Type=simple
User=$NAME
Group=$NAME
WorkingDirectory=$VAR
EnvironmentFile=$ETC/env
ExecStart=$BIN serve --listen $LISTEN --db $VAR/gpewebdefender.db --home $HOME_PIN --homes \${GWD_HOMES} --token \${GWD_TOKEN} --retain $RETAIN --docs $VAR/dochub$exec_extra
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$NAME"

echo
echo "manager is running."
echo "  status:   systemctl status $NAME"
echo "  logs:     journalctl -u $NAME -f"
echo "  token:    $ETC/env   (do not commit this file)"
echo
echo "open the UI from your laptop (do not expose $LISTEN to the internet yet):"
echo "  ssh -L 8787:127.0.0.1:8787 USER@$(hostname -f 2>/dev/null || hostname)"
echo "  then http://127.0.0.1:8787/login"
echo "  create the first admin. that is a dashboard user, not the ingest token."
echo
echo "docs on the box: http://127.0.0.1:8787/docs/"
echo "add another host:  sudo ./deploy/install-agent.sh --url http://THISBOX:8787 --name web-1 --tail /var/log/nginx/access.log"
echo
