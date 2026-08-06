#!/bin/sh
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu

BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SERVER_IP=''
PUBLIC_KEY=''
BACKEND=auto
INSTALL_DEPS=1

usage() {
    cat >&2 <<'EOF'
Usage:
  sh install-firewall.sh --server-ip IP --public-key FILE [--backend auto|banip|standalone] [--no-install-deps]
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --server-ip) SERVER_IP="$2"; shift 2 ;;
        --public-key) PUBLIC_KEY="$2"; shift 2 ;;
        --backend) BACKEND="$2"; shift 2 ;;
        --no-install-deps) INSTALL_DEPS=0; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
[ -f /etc/openwrt_release ] || { echo 'This installer requires OpenWrt' >&2; exit 1; }
[ -n "$SERVER_IP" ] && [ -f "$PUBLIC_KEY" ] || usage
case "$BACKEND" in auto|banip|standalone) : ;; *) usage ;; esac

pkg_install() {
    pkg="$1"
    [ "$INSTALL_DEPS" -eq 1 ] || return 1
    if command -v apk >/dev/null 2>&1; then
        apk update >/dev/null 2>&1 || true
        apk add "$pkg"
    elif command -v opkg >/dev/null 2>&1; then
        opkg update
        opkg install "$pkg"
    else
        return 1
    fi
}

ensure_cmd() {
    cmd="$1"; pkg="$2"
    command -v "$cmd" >/dev/null 2>&1 && return 0
    pkg_install "$pkg" || { echo "Missing command $cmd; install package $pkg" >&2; exit 1; }
    command -v "$cmd" >/dev/null 2>&1 || { echo "Package $pkg did not provide $cmd" >&2; exit 1; }
}

ensure_cmd nft nftables-json
ensure_cmd conntrack conntrack

if [ "$BACKEND" = banip ]; then
    [ -x /etc/init.d/banip ] || pkg_install banip || { echo 'banIP backend requested but banip is unavailable' >&2; exit 1; }
    /etc/init.d/banip enable
    /etc/init.d/banip restart
    tries=0
    until nft list set inet banIP blocklist.v4 >/dev/null 2>&1 && nft list set inet banIP blocklist.v6 >/dev/null 2>&1; do
        tries=$((tries+1)); [ "$tries" -lt 30 ] || { echo 'banIP nftables sets did not become ready' >&2; exit 1; }; sleep 1
    done
fi

mkdir -p /etc/reactive-web-firewall /usr/local/sbin /etc/init.d
cp "$BASE_DIR/etc/reactive-web-firewall/firewall.nft" /etc/reactive-web-firewall/firewall.nft
cp "$BASE_DIR/usr/local/sbin/reactive-fw-common" /usr/local/sbin/reactive-fw-common
cp "$BASE_DIR/usr/local/sbin/reactive-fw-load" /usr/local/sbin/reactive-fw-load
cp "$BASE_DIR/usr/local/sbin/reactive-fw-ban" /usr/local/sbin/reactive-fw-ban
cp "$BASE_DIR/usr/local/sbin/reactive-fw-dispatch" /usr/local/sbin/reactive-fw-dispatch
cp "$BASE_DIR/etc/init.d/reactive-web-firewall" /etc/init.d/reactive-web-firewall
chmod 0755 /usr/local/sbin/reactive-fw-* /etc/init.d/reactive-web-firewall
chmod 0644 /etc/reactive-web-firewall/firewall.nft

CONF=/etc/reactive-web-firewall/firewall.conf
if [ ! -f "$CONF" ]; then cp "$BASE_DIR/etc/reactive-web-firewall/firewall.conf.example" "$CONF"; fi
sed -i \
    -e "s/^PERSIST_BACKEND=.*/PERSIST_BACKEND=$BACKEND/" \
    -e "s/^ALLOWED_SERVER_IPS=.*/ALLOWED_SERVER_IPS=$SERVER_IP/" \
    "$CONF"
chmod 0600 "$CONF"
touch /etc/reactive-web-firewall/blocklist
chmod 0600 /etc/reactive-web-firewall/blocklist

if [ -x /etc/init.d/dropbear ]; then
    AUTH_FILE=/etc/dropbear/authorized_keys
    mkdir -p /etc/dropbear
else
    AUTH_FILE=/root/.ssh/authorized_keys
    mkdir -p /root/.ssh
    chmod 0700 /root/.ssh
fi

KEY_TMP="/tmp/reactive-web-key.$$"
awk 'NF>=2 && ($1 ~ /^ssh-ed25519$/ || $1 ~ /^ecdsa-sha2-/ || $1 ~ /^ssh-rsa$/) {print $1" "$2; exit}' "$PUBLIC_KEY" > "$KEY_TMP"
[ -s "$KEY_TMP" ] || { rm -f "$KEY_TMP"; echo 'Invalid SSH public key' >&2; exit 1; }
KEY_MATERIAL="$(cat "$KEY_TMP")"; rm -f "$KEY_TMP"

touch "$AUTH_FILE"
AUTH_TMP="${AUTH_FILE}.tmp.$$"
grep -v 'reactive-web-firewall$' "$AUTH_FILE" > "$AUTH_TMP" || true
printf 'command="/usr/local/sbin/reactive-fw-dispatch",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty %s reactive-web-firewall\n' "$KEY_MATERIAL" >> "$AUTH_TMP"
mv "$AUTH_TMP" "$AUTH_FILE"
chmod 0600 "$AUTH_FILE"

/etc/init.d/reactive-web-firewall enable
/etc/init.d/reactive-web-firewall restart
/usr/local/sbin/reactive-fw-ban check

logger -t reactive-fw "installed server_ip=$SERVER_IP backend=$BACKEND authorized_keys=$AUTH_FILE"
echo "Installed. Backend configured: $BACKEND"
echo "Restricted key file: $AUTH_FILE"
