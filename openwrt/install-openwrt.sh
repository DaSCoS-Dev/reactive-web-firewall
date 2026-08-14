#!/bin/sh
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

PATH='/usr/sbin:/usr/bin:/sbin:/bin'
API_VERSION='1'
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ALLOWED_SOURCE=''
RUNTIME_PUBKEY=''
INSTALL_TOOLS='yes'
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/rwf-backup/$STAMP"
AUTH_KEYS='/etc/dropbear/authorized_keys'
WRAPPER_CONF='/etc/f2b-banip-wrapper.conf'
BANIP_CONF='/etc/config/banip'
ROLLBACK_NEEDED=0
CREATED_MANIFEST="$BACKUP_DIR/.created"

say(){ printf '%s\n' "$*"; }
die(){ say "ERRORE: $*" >&2; exit 1; }

usage(){
        cat <<'EOF_USAGE'
Uso: install-openwrt.sh --allowed-source <IP_PROXY> --runtime-pubkey <FILE> [--install-tools yes|no]
EOF_USAGE
        exit 2
}

while [ "$#" -gt 0 ]; do
        case "$1" in
                --allowed-source) [ "$#" -ge 2 ] || usage; ALLOWED_SOURCE="$2"; shift 2 ;;
                --runtime-pubkey) [ "$#" -ge 2 ] || usage; RUNTIME_PUBKEY="$2"; shift 2 ;;
                --install-tools) [ "$#" -ge 2 ] || usage; INSTALL_TOOLS="$2"; shift 2 ;;
                *) usage ;;
        esac
done

[ "$(id -u)" -eq 0 ] || die "serve root"
[ -r /etc/openwrt_release ] || die "questa macchina non sembra OpenWrt"
[ -n "$ALLOWED_SOURCE" ] || die "--allowed-source mancante"
[ -r "$RUNTIME_PUBKEY" ] || die "chiave pubblica runtime non leggibile: $RUNTIME_PUBKEY"
case "$INSTALL_TOOLS" in yes|no) : ;; *) die "--install-tools deve essere yes o no" ;; esac

# Validazione conservativa. Il wrapper confronterà la stringa con SSH_CONNECTION.
printf '%s' "$ALLOWED_SOURCE" | grep -Eq '^[0-9A-Fa-f:.]+$' || die "IP proxy non valido: $ALLOWED_SOURCE"

mkdir -p "$BACKUP_DIR"
backup_one(){
        f="$1"
        if [ -e "$f" ]; then
                mkdir -p "$BACKUP_DIR$(dirname "$f")"
                cp -p "$f" "$BACKUP_DIR$f"
        else
                printf '%s\n' "$f" >> "$CREATED_MANIFEST"
        fi
}

rollback(){
        rc=$?
        [ "$ROLLBACK_NEEDED" -eq 1 ] || exit "$rc"
        say "Rollback dei file OpenWrt modificati..." >&2
        for f in \
                /usr/bin/f2b-banip \
                /usr/bin/f2b-banip-wrapper \
                /usr/sbin/fw-unban-all \
                /usr/sbin/check-fw-ban \
                /usr/bin/banip-aggregate-subnets.sh \
                "$WRAPPER_CONF" \
                "$BANIP_CONF" \
                "$AUTH_KEYS"
        do
                if [ -e "$BACKUP_DIR$f" ]; then
                        mkdir -p "$(dirname "$f")"
                        cp -p "$BACKUP_DIR$f" "$f"
                fi
        done
        if [ -r "$CREATED_MANIFEST" ]; then
                while IFS= read -r f; do
                        [ -n "$f" ] || continue
                        rm -f "$f"
                done < "$CREATED_MANIFEST"
        fi
        if [ -x /etc/init.d/banip ]; then
                if [ -e "$BACKUP_DIR/.banip-enabled" ]; then
                        /etc/init.d/banip enable >/dev/null 2>&1 || true
                else
                        /etc/init.d/banip disable >/dev/null 2>&1 || true
                fi
                if [ -e "$BACKUP_DIR/.banip-running" ]; then
                        /etc/init.d/banip restart >/dev/null 2>&1 || /etc/init.d/banip start >/dev/null 2>&1 || true
                else
                        /etc/init.d/banip stop >/dev/null 2>&1 || true
                fi
        fi
        exit "$rc"
}
trap rollback INT TERM HUP EXIT
ROLLBACK_NEEDED=1

for f in \
        /usr/bin/f2b-banip \
        /usr/bin/f2b-banip-wrapper \
        /usr/sbin/fw-unban-all \
        /usr/sbin/check-fw-ban \
        /usr/bin/banip-aggregate-subnets.sh \
        "$WRAPPER_CONF" \
        "$BANIP_CONF" \
        "$AUTH_KEYS"
do backup_one "$f"; done

# Preserve the pre-install banIP service state for rollback. These rc.common
# actions are best-effort because a fresh firewall may not have banIP yet.
if [ -x /etc/init.d/banip ]; then
        /etc/init.d/banip enabled >/dev/null 2>&1 && : > "$BACKUP_DIR/.banip-enabled" || true
        /etc/init.d/banip running >/dev/null 2>&1 && : > "$BACKUP_DIR/.banip-running" || true
fi

pkg_install(){
        if command -v apk >/dev/null 2>&1; then
                apk -U add "$@"
        elif command -v opkg >/dev/null 2>&1; then
                opkg update
                opkg install "$@"
        else
                die "nessun package manager OpenWrt supportato (apk/opkg)"
        fi
}

missing=''
[ -x /etc/init.d/banip ] || missing="$missing banip"
command -v conntrack >/dev/null 2>&1 || missing="$missing conntrack"
if [ -n "$missing" ]; then
        say "Installazione dipendenze:$missing"
        # shellcheck disable=SC2086
        pkg_install $missing
fi

command -v nft >/dev/null 2>&1 || die "nft non disponibile"
[ -x /etc/init.d/banip ] || die "banIP non installato correttamente"

# Non sostituiamo /etc/config/banip. Rendiamo soltanto espliciti i due
# requisiti del backend RwF e lasciamo intatte interfacce/feed/policy esistenti.
if command -v uci >/dev/null 2>&1; then
        uci -q set banip.global.ban_enabled='1'
        uci -q set banip.global.ban_autoblocklist='1'
        uci commit banip
fi
/etc/init.d/banip enable >/dev/null 2>&1 || true
/etc/init.d/banip restart >/dev/null 2>&1 || /etc/init.d/banip start >/dev/null 2>&1 || true

# banIP può impiegare qualche istante a creare la tabella nft.
i=0
while ! nft list table inet banIP >/dev/null 2>&1; do
        i=$((i+1)); [ "$i" -lt 20 ] || die "tabella nft inet banIP non disponibile dopo l'avvio"
        sleep 1
done
nft list set inet banIP blocklist.v4 >/dev/null 2>&1 || die "set banIP blocklist.v4 non disponibile"
mkdir -p /etc/banip
touch /etc/banip/banip.blocklist

cp "$BASE_DIR/core/usr/bin/f2b-banip" /usr/bin/f2b-banip
cp "$BASE_DIR/core/usr/bin/f2b-banip-wrapper" /usr/bin/f2b-banip-wrapper
cp "$BASE_DIR/core/usr/sbin/fw-unban-all" /usr/sbin/fw-unban-all
chmod 0755 /usr/bin/f2b-banip /usr/bin/f2b-banip-wrapper /usr/sbin/fw-unban-all
if [ "$INSTALL_TOOLS" = yes ]; then
        cp "$BASE_DIR/tools/usr/sbin/check-fw-ban" /usr/sbin/check-fw-ban
        cp "$BASE_DIR/tools/usr/bin/banip-aggregate-subnets.sh" /usr/bin/banip-aggregate-subnets.sh
        chmod 0755 /usr/sbin/check-fw-ban /usr/bin/banip-aggregate-subnets.sh
fi

# Migrazione: se il vecchio wrapper aveva ALLOWED_SOURCES hardcoded,
# preserviamo quei server e aggiungiamo il proxy che sta facendo il bootstrap.
OLD_SOURCES=''
if [ -r "$WRAPPER_CONF" ]; then
        OLD_SOURCES="$(sed -n "s/^[[:space:]]*ALLOWED_SOURCES=['\"]\([^'\"]*\)['\"].*/\1/p" "$WRAPPER_CONF" | head -n1)"
elif [ -r "$BACKUP_DIR/usr/bin/f2b-banip-wrapper" ]; then
        OLD_SOURCES="$(sed -n "s/^[[:space:]]*ALLOWED_SOURCES=['\"]\([^'\"]*\)['\"].*/\1/p" "$BACKUP_DIR/usr/bin/f2b-banip-wrapper" | head -n1)"
fi

NEW_SOURCES=''
for ip in $OLD_SOURCES $ALLOWED_SOURCE; do
        [ -n "$ip" ] || continue
        case " $NEW_SOURCES " in *" $ip "*) : ;; *) NEW_SOURCES="${NEW_SOURCES:+$NEW_SOURCES }$ip" ;; esac
done
cat > "$WRAPPER_CONF" <<EOF_CONF
# Reactive Web Firewall / f2b-banip-wrapper
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Aggiornato: $(date '+%F %T')
ALLOWED_SOURCES='$NEW_SOURCES'
API_VERSION='$API_VERSION'
EOF_CONF
chmod 0600 "$WRAPPER_CONF"

# Installa/normalizza la chiave runtime come forced-command. Non usiamo
# l'opzione OpenSSH "from=" perché il firewall standard OpenWrt usa Dropbear
# e vogliamo restare compatibili fra release. La sorgente viene verificata
# nuovamente dal wrapper tramite SSH_CONNECTION.
mkdir -p /etc/dropbear
touch "$AUTH_KEYS"
chmod 0600 "$AUTH_KEYS"

PUB_TYPE="$(awk 'NF>=2{print $1; exit}' "$RUNTIME_PUBKEY")"
PUB_BLOB="$(awk 'NF>=2{print $2; exit}' "$RUNTIME_PUBKEY")"
[ -n "$PUB_TYPE" ] && [ -n "$PUB_BLOB" ] || die "chiave pubblica runtime non valida"
TMP_AUTH="$(mktemp /tmp/rwf-authorized-keys.XXXXXX)"
awk -v blob="$PUB_BLOB" 'index($0, blob)==0 {print}' "$AUTH_KEYS" > "$TMP_AUTH"
printf 'command="/usr/bin/f2b-banip-wrapper",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty %s %s rwf-runtime\n' "$PUB_TYPE" "$PUB_BLOB" >> "$TMP_AUTH"
cat "$TMP_AUTH" > "$AUTH_KEYS"
rm -f "$TMP_AUTH"
chmod 0600 "$AUTH_KEYS"

# Self-test locale del motore e del forced-command simulando le variabili SSH.
/usr/bin/f2b-banip check >/dev/null
TEST_IP='198.51.100.247'
/usr/bin/f2b-banip temp-del "$TEST_IP" >/dev/null 2>&1 || true
/usr/bin/f2b-banip temp-add "$TEST_IP" 30 >/dev/null
nft get element inet banIP blocklist.v4 "{ $TEST_IP }" >/dev/null 2>&1 || die "self-test: TEST-NET non presente nel set"
/usr/bin/f2b-banip temp-del "$TEST_IP" >/dev/null

VERSION_OUT="$(SSH_CONNECTION="$ALLOWED_SOURCE 40000 127.0.0.1 22" SSH_ORIGINAL_COMMAND='version' /usr/bin/f2b-banip-wrapper)"
[ "$VERSION_OUT" = "RWF-OPENWRT-API $API_VERSION" ] || die "self-test wrapper fallito: $VERSION_OUT"

ROLLBACK_NEEDED=0
trap - INT TERM HUP EXIT
say "RWF_OPENWRT_INSTALL_OK api=$API_VERSION allowed_sources=[$NEW_SOURCES] backup=$BACKUP_DIR"
