#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIREWALL_HOST=''
FIREWALL_PORT=22
FIREWALL_USER=root
SERVER_IP=''
BACKEND=auto
INSTALL_FIREWALL=0
COPY_FIREWALL=1
ACCEPT_HOST_KEY=0
INSTALL_DEPS=1
CHECK_ONLY=0
ENABLE_PACKET_RING=1

usage() {
    cat <<'EOF'
Usage:
  sudo ./install.sh --firewall-host HOST [options]

Options:
  --firewall-port PORT       SSH port on OpenWrt, default 22
  --firewall-user USER       SSH user used for setup and restricted channel
  --server-ip IP             Source address seen by OpenWrt
  --backend auto|banip|standalone
  --install-firewall         Copy and execute the OpenWrt installer
  --no-copy-firewall         Install only the server side
  --accept-host-key          Accept ssh-keyscan output non-interactively
  --no-install-deps          Fail instead of installing missing packages
  --no-packet-ring           Do not enable the circular tcpdump recorder
  --check-only               Check server prerequisites and exit
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --firewall-host) FIREWALL_HOST="$2"; shift 2 ;;
        --firewall-port) FIREWALL_PORT="$2"; shift 2 ;;
        --firewall-user) FIREWALL_USER="$2"; shift 2 ;;
        --server-ip) SERVER_IP="$2"; shift 2 ;;
        --backend) BACKEND="$2"; shift 2 ;;
        --install-firewall) INSTALL_FIREWALL=1; shift ;;
        --no-copy-firewall) COPY_FIREWALL=0; shift ;;
        --accept-host-key) ACCEPT_HOST_KEY=1; shift ;;
        --no-install-deps) INSTALL_DEPS=0; shift ;;
        --no-packet-ring) ENABLE_PACKET_RING=0; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ "$BACKEND" =~ ^(auto|banip|standalone)$ ]] || { echo 'Invalid backend' >&2; exit 1; }
[[ "$FIREWALL_PORT" =~ ^[0-9]+$ ]] && (( FIREWALL_PORT >= 1 && FIREWALL_PORT <= 65535 )) || { echo 'Invalid firewall port' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'systemd is required' >&2; exit 1; }

source /etc/os-release
case "${ID:-}" in
    debian|ubuntu) : ;;
    *) echo "Supported server systems: Debian and Ubuntu. Detected: ${ID:-unknown}" >&2; exit 1 ;;
esac

install_packages() {
    ((${#@} > 0)) || return 0
    [[ $INSTALL_DEPS -eq 1 ]] || { echo "Missing packages: $*" >&2; exit 1; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y "$@"
}

packages=(apache2 perl nftables iproute2 openssh-client tcpdump coreutils gawk grep sed util-linux logrotate gzip)
missing=()
for pkg in "${packages[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' || missing+=("$pkg")
done
install_packages "${missing[@]}"

commands=(apache2 apache2ctl a2enconf perl nft ss ssh ssh-keygen ssh-keyscan scp tcpdump tail logger flock systemctl awk sed grep gzip)
for cmd in "${commands[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing command after package checks: $cmd" >&2; exit 1; }
    printf '[ OK ] %s\n' "$cmd"
done

apache_version="$(apache2 -v | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p' | head -n1)"
[[ -n "$apache_version" ]] || { echo 'Cannot determine Apache version' >&2; exit 1; }
dpkg --compare-versions "$apache_version" ge 2.4.19 || { echo 'Apache >= 2.4.19 is required for GlobalLog' >&2; exit 1; }
printf '[ OK ] Apache %s\n' "$apache_version"

perl -c "$BASE_DIR/server/usr/local/lib/reactive-web-firewall/detector.pm" >/dev/null
perl -c "$BASE_DIR/server/usr/local/sbin/reactive-web-ban.pl" >/dev/null
for f in \
    "$BASE_DIR/install.sh" "$BASE_DIR/finish-server.sh" "$BASE_DIR/uninstall-server.sh" \
    "$BASE_DIR/server/usr/local/sbin/reactive-web-fastban" \
    "$BASE_DIR/server/usr/local/sbin/reactive-web-ban-report" \
    "$BASE_DIR/server/usr/local/sbin/reactive-web-diagnose"; do
    bash -n "$f"
done
for f in "$BASE_DIR/firewall/install-firewall.sh" "$BASE_DIR/firewall/uninstall-firewall.sh" "$BASE_DIR/firewall/usr/local/sbin/"* "$BASE_DIR/firewall/etc/init.d/reactive-web-firewall"; do
    sh -n "$f"
done
printf '[ OK ] bundled syntax\n'

if grep -q '^CONFIG_INET_DIAG_DESTROY=y' "/boot/config-$(uname -r)" 2>/dev/null; then
    printf '[ OK ] CONFIG_INET_DIAG_DESTROY\n'
else
    printf '[WARN] CONFIG_INET_DIAG_DESTROY not confirmed; run the documented ss -K test\n'
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
    echo 'Server prerequisite check completed.'
    exit 0
fi

[[ -n "$FIREWALL_HOST" ]] || { echo '--firewall-host is required' >&2; exit 1; }
[[ "$FIREWALL_HOST" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'Invalid firewall host' >&2; exit 1; }
[[ "$FIREWALL_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || { echo 'Invalid firewall user' >&2; exit 1; }

if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(ip route get "$FIREWALL_HOST" 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
fi
[[ -n "$SERVER_IP" ]] || { echo 'Cannot determine the server address toward OpenWrt; use --server-ip' >&2; exit 1; }

if [[ "$FIREWALL_HOST" == *:* ]]; then
    FIREWALL_TARGET="$FIREWALL_USER@[$FIREWALL_HOST]"
else
    FIREWALL_TARGET="$FIREWALL_USER@$FIREWALL_HOST"
fi

echo "Server address seen by OpenWrt: $SERVER_IP"
echo "Restricted SSH target: $FIREWALL_TARGET:$FIREWALL_PORT"

install -d -m 0755 /etc/reactive-web-firewall /etc/reactive-web-firewall/keys /etc/nftables.d /usr/local/lib/reactive-web-firewall
install -d -m 0700 /var/lib/reactive-web-firewall
install -d -m 0750 /var/log/reactive-web-firewall/pcap

install -m 0755 "$BASE_DIR/server/usr/local/sbin/reactive-web-ban.pl" /usr/local/sbin/reactive-web-ban.pl
install -m 0755 "$BASE_DIR/server/usr/local/sbin/reactive-web-fastban" /usr/local/sbin/reactive-web-fastban
install -m 0755 "$BASE_DIR/server/usr/local/sbin/reactive-web-ban-report" /usr/local/sbin/reactive-web-ban-report
install -m 0755 "$BASE_DIR/server/usr/local/sbin/reactive-web-diagnose" /usr/local/sbin/reactive-web-diagnose
install -m 0644 "$BASE_DIR/server/usr/local/lib/reactive-web-firewall/detector.pm" /usr/local/lib/reactive-web-firewall/detector.pm
install -m 0644 "$BASE_DIR/server/etc/nftables.d/reactive-web-fastban.nft" /etc/nftables.d/reactive-web-fastban.nft
install -m 0644 "$BASE_DIR/server/etc/systemd/system/reactive-web-fastban.service" /etc/systemd/system/reactive-web-fastban.service
install -m 0644 "$BASE_DIR/server/etc/systemd/system/reactive-web-ban.service" /etc/systemd/system/reactive-web-ban.service
install -m 0644 "$BASE_DIR/server/etc/systemd/system/reactive-web-packet-ring.service" /etc/systemd/system/reactive-web-packet-ring.service
install -m 0644 "$BASE_DIR/server/etc/apache2/conf-available/reactive-web-firewall.conf" /etc/apache2/conf-available/reactive-web-firewall.conf
install -m 0644 "$BASE_DIR/server/etc/logrotate.d/reactive-web-firewall" /etc/logrotate.d/reactive-web-firewall

sed -i \
    -e "s|@@FIREWALL_TARGET@@|$FIREWALL_TARGET|" \
    -e "s|@@FIREWALL_PORT@@|$FIREWALL_PORT|" \
    /etc/systemd/system/reactive-web-ban.service

if [[ ! -f /etc/reactive-web-firewall/rules.conf ]]; then
    install -m 0644 "$BASE_DIR/server/etc/reactive-web-firewall/rules.conf.example" /etc/reactive-web-firewall/rules.conf
fi
if [[ ! -f /etc/reactive-web-firewall/allowlist ]]; then
    install -m 0640 "$BASE_DIR/server/etc/reactive-web-firewall/allowlist.example" /etc/reactive-web-firewall/allowlist
fi
cat > /etc/reactive-web-firewall/connection.conf <<EOF
FIREWALL_HOST=$FIREWALL_HOST
FIREWALL_PORT=$FIREWALL_PORT
FIREWALL_USER=$FIREWALL_USER
FIREWALL_TARGET=$FIREWALL_TARGET
SERVER_IP=$SERVER_IP
BACKEND=$BACKEND
EOF
chmod 0600 /etc/reactive-web-firewall/connection.conf

KEY=/etc/reactive-web-firewall/keys/firewall_ed25519
KNOWN=/etc/reactive-web-firewall/keys/known_hosts
if [[ ! -f "$KEY" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C reactive-web-firewall -f "$KEY"
fi
chmod 0600 "$KEY"; chmod 0644 "$KEY.pub"

scan_tmp="$(mktemp)"
trap 'rm -f "$scan_tmp"' EXIT
ssh-keyscan -T 5 -p "$FIREWALL_PORT" "$FIREWALL_HOST" > "$scan_tmp" 2>/dev/null || { echo 'Cannot read OpenWrt SSH host key' >&2; exit 1; }
echo 'OpenWrt SSH host-key fingerprint(s):'
ssh-keygen -lf "$scan_tmp"
if [[ $ACCEPT_HOST_KEY -ne 1 ]]; then
    if [[ -t 0 ]]; then
        read -r -p 'Accept these host keys? [y/N] ' answer
        [[ "$answer" =~ ^[Yy]$ ]] || { echo 'Aborted' >&2; exit 1; }
    else
        echo 'Non-interactive installation requires --accept-host-key' >&2
        exit 1
    fi
fi
install -m 0644 "$scan_tmp" "$KNOWN"

if ! id tcpdump >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin tcpdump
fi
chown tcpdump:tcpdump /var/log/reactive-web-firewall/pcap
chmod 0750 /var/log/reactive-web-firewall/pcap

touch /var/log/apache2/reactive_web_access.log
chown root:adm /var/log/apache2/reactive_web_access.log
chmod 0640 /var/log/apache2/reactive_web_access.log

a2enconf reactive-web-firewall >/dev/null
apache2ctl configtest
systemctl reload apache2

systemctl daemon-reload
systemctl enable --now reactive-web-fastban.service
if [[ $ENABLE_PACKET_RING -eq 1 ]]; then
    systemctl enable --now reactive-web-packet-ring.service
else
    systemctl disable --now reactive-web-packet-ring.service 2>/dev/null || true
fi

remote_dir=/tmp/reactive-web-firewall-install
ssh_base=(ssh -p "$FIREWALL_PORT" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN")
scp_base=(scp -P "$FIREWALL_PORT" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN")

if [[ $COPY_FIREWALL -eq 1 ]]; then
    stage="$(mktemp -d)"
    cp -a "$BASE_DIR/firewall/." "$stage/"
    cp "$KEY.pub" "$stage/server_key.pub"
    "${ssh_base[@]}" "$FIREWALL_TARGET" "rm -rf '$remote_dir' && mkdir -p '$remote_dir'"
    "${scp_base[@]}" -r "$stage/." "$FIREWALL_TARGET:$remote_dir/"
    rm -rf "$stage"
    echo "[ OK ] OpenWrt bundle copied to $remote_dir"
fi

remote_install="sh $remote_dir/install-firewall.sh --server-ip $SERVER_IP --public-key $remote_dir/server_key.pub --backend $BACKEND"
if [[ $INSTALL_DEPS -eq 0 ]]; then remote_install+=" --no-install-deps"; fi

if [[ $INSTALL_FIREWALL -eq 1 ]]; then
    "${ssh_base[@]}" "$FIREWALL_TARGET" "$remote_install"
fi

if ssh -p "$FIREWALL_PORT" -i "$KEY" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN" -o ConnectTimeout=3 \
    "$FIREWALL_TARGET" check >/dev/null 2>&1; then
    systemctl enable --now reactive-web-ban.service
    echo '[ OK ] restricted OpenWrt channel and watcher active'
else
    systemctl disable --now reactive-web-ban.service >/dev/null 2>&1 || true
    echo
    echo 'The server side is installed, but the watcher remains stopped until the restricted OpenWrt channel works.'
    if [[ $COPY_FIREWALL -eq 1 ]]; then
        echo 'Run on OpenWrt:'
        echo "  $remote_install"
        echo 'Then run on this server:'
        echo '  sudo ./finish-server.sh'
    fi
fi

echo
echo 'Installation stage completed.'
echo 'Diagnostic: sudo reactive-web-diagnose'
