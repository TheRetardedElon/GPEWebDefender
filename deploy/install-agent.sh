#!/bin/sh
# Easy agent install. Run as root on a box that has an access log (or sshd).
#
#   sudo ./deploy/install-agent.sh \
#     --url http://MONITOR:8787 \
#     --name web-1 \
#     --tail /var/log/nginx/access.log \
#     --journal
#
# Optional pairing (block orders from the dashboard):
#   --code ABCD-2341 --block fail2ban
# You will be asked for the enrollment phrase (the one you set in Settings).
#
# The token is read from /etc/gpewebdefender/env on this box, or from --token,
# or you can copy the manager's env file first:
#   scp root@MONITOR:/etc/gpewebdefender/env /etc/gpewebdefender/env

set -eu

NAME=gpewebdefender
PREFIX=/usr/local
URL=""
AGENT_NAME=""
TAIL=""
JOURNAL=0
TOKEN=""
BIN_SRC=""
PAIR_CODE=""
BLOCK=""

usage() {
  cat <<'EOF'
install-agent.sh — ship access logs (and optional sshd) to the manager.

  --url URL         manager base URL, e.g. http://10.0.0.8:8787   (required)
  --name NAME       stable label in the UI, e.g. web-1             (required)
  --tail PATH       access log (comma-separate more than one)
  --journal         follow systemd journal for sshd/sudo
  --token SECRET    ingest token (otherwise use /etc/gpewebdefender/env)
  --code CODE       one-time pair code from Settings (optional)
  --block BACKEND   fail2ban | ufw | off  (only with --code)
  --bin FILE        Linux binary if we cannot find it
  -h, --help

Need at least --tail or --journal.
Log shipping still uses the shared ingest token.
Pairing is extra: a phrase you invent + this code + Approve in the UI.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift ;;
    --name) AGENT_NAME="${2:-}"; shift ;;
    --tail) TAIL="${2:-}"; shift ;;
    --journal) JOURNAL=1 ;;
    --token) TOKEN="${2:-}"; shift ;;
    --code) PAIR_CODE="${2:-}"; shift ;;
    --block) BLOCK="${2:-}"; shift ;;
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
if [ -z "$URL" ] || [ -z "$AGENT_NAME" ]; then
  echo "--url and --name are required." >&2
  usage >&2
  exit 2
fi
if [ -z "$TAIL" ] && [ "$JOURNAL" -eq 0 ]; then
  echo "give --tail /path/to/access.log and/or --journal." >&2
  exit 2
fi

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
find_bin() {
  if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then echo "$BIN_SRC"; return; fi
  for c in \
    /usr/local/bin/$NAME \
    "$here/gpewebdefender-linux-amd64" "$here/gpewebdefender" \
    "$here/gpewebdefender-linux-amd64" "$here/gpewebdefender"
  do
    if [ -f "$c" ]; then echo "$c"; return; fi
  done
  return 1
}
if ! bin=$(find_bin); then
  echo "cannot find the binary. copy it from the manager:" >&2
  echo "  scp root@MONITOR:/usr/local/bin/$NAME /usr/local/bin/$NAME" >&2
  exit 1
fi

ETC=/etc/$NAME
BIN=$PREFIX/bin/$NAME
mkdir -p "$ETC"
if [ -n "$TOKEN" ]; then
  umask 077
  echo "GWD_TOKEN=$TOKEN" > "$ETC/env"
  chmod 640 "$ETC/env"
elif [ ! -f "$ETC/env" ]; then
  if [ -z "$PAIR_CODE" ]; then
    echo "no token. copy the manager env file or pass --token." >&2
    echo "  scp root@MONITOR:$ETC/env $ETC/env" >&2
    echo "or pair this host: pass --code from Settings." >&2
    exit 1
  fi
  umask 077
  echo "# pair this host; add GWD_TOKEN=... if you also want the shared ingest secret" > "$ETC/env"
  chmod 640 "$ETC/env"
fi

install -o root -g root -m 755 "$bin" "$BIN"

extra=""
[ -n "$TAIL" ] && extra="$extra --tail $TAIL"
[ "$JOURNAL" -eq 1 ] && extra="$extra --journal"

cat > /etc/systemd/system/${NAME}-agent.service <<EOF
[Unit]
Description=$NAME log shipper ($AGENT_NAME)
After=network.target

[Service]
Type=simple
EnvironmentFile=-$ETC/env
ExecStart=$BIN agent --url $URL --name $AGENT_NAME --cred $ETC/agent.json --token \${GWD_TOKEN}$extra
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

if [ -n "$PAIR_CODE" ]; then
  extra_pair="--cred $ETC/agent.json"
  [ -n "$BLOCK" ] && extra_pair="$extra_pair --block $BLOCK"
  echo "pairing $AGENT_NAME — type the enrollment phrase when asked."
  "$BIN" pair --url "$URL" --name "$AGENT_NAME" --code "$PAIR_CODE" $extra_pair
fi

systemctl daemon-reload
systemctl enable --now "${NAME}-agent"

echo
echo "agent $AGENT_NAME is shipping to $URL"
echo "  status: systemctl status ${NAME}-agent"
echo "  logs:   journalctl -u ${NAME}-agent -f"
echo
echo "on the manager firewall, allow THIS box's IP to the ingest port."
echo "in the UI, the Hosts dropdown should show \"$AGENT_NAME\" after the first line."
echo "optional: Settings → add a map row with the same name and a lat,lon or ISO country."
echo "optional: after Approve, Status → Check now pulls load / memory / disk from this box (0.9.25+ binary)."
echo
