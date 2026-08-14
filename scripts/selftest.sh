#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

MODE="${1:-}"
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RWF_ETC="/etc/reactive-web-firewall"
HELPER="/usr/local/sbin/rwf-helper"
FASTBAN="${RWF_SELFTEST_FASTBAN:-/usr/local/sbin/custom-web-fastban}"
SS_BIN="${RWF_SELFTEST_SS:-$(command -v ss || true)}"
BACKEND_MODE="${RWF_SELFTEST_MODE:-local-only}"
DROP="${RWF_SELFTEST_DROP:-1}"
SUPPRESS_LOG="${RWF_SELFTEST_SUPPRESS_LOG:-1}"

# shellcheck disable=SC1091
source "$BASE_DIR/platform.sh"
rwf_detect_platform || { echo "SELFTEST ERRORE: piattaforma Apache non riconosciuta" >&2; exit 1; }

fail() { echo "SELFTEST ERRORE: $*" >&2; exit 1; }
ok()   { echo "SELFTEST OK: $*"; }

[[ $EUID -eq 0 ]] || fail "eseguire come root"
[[ -x "$HELPER" ]] || fail "helper non trovato: $HELPER"
[[ -x "$FASTBAN" ]] || fail "fastban non trovato: $FASTBAN"
[[ -x "$SS_BIN" ]] || fail "ss non trovato"

journal_since() {
    local since="$1"
    journalctl -t rwf-helper --since "@$since" --no-pager 2>/dev/null || true
}

http_selftest() {
    local tmpdir tmpsock tmppid site_file status1 status2 headers accesslog start_epoch drop_word suppress_word customlog_line lines logs listener

    if systemctl is-active --quiet custom-web-ban-immediate.service; then
        fail "watcher Perl legacy ancora attivo; self-test HTTP malevolo non sicuro"
    fi

    listener="$($SS_BIN -ltnH '( sport = :80 )' 2>/dev/null || true)"
    [[ -n "$listener" ]] || { echo "SELFTEST SKIP: nessun listener TCP/80; test HTTP locale saltato."; return 0; }

    tmpdir="$(mktemp -d /run/reactive-web-firewall/selftest.XXXXXX)"
    chgrp "$RWF_APACHE_GROUP" "$tmpdir"; chmod 0750 "$tmpdir"
    tmpsock="$tmpdir/helper.sock"; headers="$tmpdir/headers"; accesslog="$tmpdir/access.log"; start_epoch="$(date +%s)"
    touch "$accesslog"; chgrp "$RWF_APACHE_GROUP" "$accesslog"; chmod 0660 "$accesslog"

    case "$RWF_APACHE_STYLE" in
        debian) site_file="$RWF_APACHE_ETC/sites-available/rwf-installer-selftest.conf" ;;
        direct) site_file="$RWF_APACHE_ETC/conf.d/zz-rwf-installer-selftest.conf" ;;
    esac

    cleanup_http() {
        set +e
        [[ -n "${tmppid:-}" ]] && { kill "$tmppid" >/dev/null 2>&1 || true; wait "$tmppid" >/dev/null 2>&1 || true; }
        if [[ "$RWF_APACHE_STYLE" == "debian" ]]; then a2dissite rwf-installer-selftest >/dev/null 2>&1 || true; fi
        rm -f "$site_file"
        rwf_apache_configtest >/dev/null 2>&1 && rwf_apache_reload >/dev/null 2>&1 || true
        rm -rf "$tmpdir"
    }
    trap cleanup_http EXIT INT TERM

    cp "$RWF_ETC/whitelist.conf" "$tmpdir/whitelist.conf"
    cat >> "$tmpdir/whitelist.conf" <<'EOW'
RwfWhitelistIP 127.0.0.1/32
RwfWhitelistIP ::1/128
EOW

    "$HELPER" \
        --mode local-only \
        --socket "$tmpsock" \
        --whitelist "$tmpdir/whitelist.conf" \
        --fastban "$FASTBAN" \
        --ss "$SS_BIN" \
        --active-dir /run/custom-web-ban/active \
        --lfd-suppress 90 \
        --max-workers 2 >/dev/null 2>&1 &
    tmppid=$!

    for _ in $(seq 1 60); do [[ -S "$tmpsock" ]] && break; sleep 0.05; done
    [[ -S "$tmpsock" ]] || fail "helper temporaneo non ha creato $tmpsock"
    chgrp "$RWF_APACHE_GROUP" "$tmpsock"; chmod 0660 "$tmpsock"

    drop_word="Off"; [[ "$DROP" == "1" ]] && drop_word="On"
    suppress_word="Off"; [[ "$SUPPRESS_LOG" == "1" ]] && suppress_word="On"
    customlog_line="CustomLog $accesslog combined"
    [[ "$SUPPRESS_LOG" == "1" ]] && customlog_line+=" env=!RWF_SUPPRESS_ACCESSLOG"

    cat > "$site_file" <<EOF_SITE
<VirtualHost 127.0.0.1:80>
    ServerName rwf-installer-selftest.invalid
    RwfEnabled On
    RwfDropConnection $drop_word
    RwfSuppressBlockedAccessLog $suppress_word
    RwfHelperSocket $tmpsock
    RwfRuleTargetRegex installer-target-regex "[?&]rest_route=/batch/v1(?:/|$|[&#])" permanent
    ErrorLog /dev/null
    $customlog_line
</VirtualHost>
EOF_SITE

    if [[ "$RWF_APACHE_STYLE" == "debian" ]]; then a2ensite rwf-installer-selftest >/dev/null; fi
    rwf_apache_configtest >/dev/null
    rwf_apache_reload

    status1="$(curl -sS -o "$tmpdir/body1" -D "$headers" -H 'Host: rwf-installer-selftest.invalid' \
        -w '%{http_code}' --max-time 5 'http://127.0.0.1/?rest_route=%252Fbatch%252Fv1' || true)"
    [[ "$status1" == "403" ]] || fail "atteso HTTP 403 sul TargetRegex normalizzato, ottenuto '$status1'"
    grep -Eiq '^X-RwF:[[:space:]]*blocked' "$headers" || fail "header X-RwF: blocked non trovato sul TargetRegex"

    status2="$(curl -sS -o "$tmpdir/body2" -D "$tmpdir/headers2" -H 'Host: rwf-installer-selftest.invalid' \
        -w '%{http_code}' --max-time 5 'http://127.0.0.1/rwf-benign-cache-followup.txt' 2>/dev/null || true)"
    [[ "$status2" == "403" || "$status2" == "000" || -z "$status2" ]] \
        || fail "cache-hit follow-up non bloccato; HTTP '$status2'"

    sleep 0.25
    logs="$(journal_since "$start_epoch")"
    grep -E 'whitelist-hit ip=127\.0\.0\.1 .*action=drop-event' <<<"$logs" >/dev/null \
        || fail "helper temporaneo non ha registrato whitelist-hit 127.0.0.1"

    if [[ "$SUPPRESS_LOG" == "1" ]]; then
        lines="$(wc -l < "$accesslog")"
        [[ "$lines" -eq 1 ]] || fail "no-log cache-hit atteso: access log contiene $lines righe invece di 1"
        ok "primo match loggato e cache-hit successivo soppresso dall'access log"
    fi

    ok "TargetRegex doppio-decode + Apache -> mod_rwf -> cache/drop -> socket -> helper verificati senza ban reale"
    cleanup_http
    trap - EXIT INT TERM
}

firewall_selftest() {
    local octet test_ip start_epoch logs
    octet=$((100 + RANDOM % 100)); test_ip="198.51.100.${octet}"; start_epoch="$(date +%s)"

    python3 - "$test_ip" <<'PY'
import socket, sys, time
ip = sys.argv[1]
event = (
    "v=1" f"\tip={ip}" "\thost=rwf-installer-selftest.invalid" "\tmethod=GET"
    "\turi=/.git/config" "\trule=installer-firewall-selftest" "\tpolicy=30s"
    f"\tts_us={time.time_ns() // 1000}"
)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(event.encode(), "/run/reactive-web-firewall/helper.sock")
PY

    for _ in $(seq 1 60); do
        logs="$(journal_since "$start_epoch")"
        if [[ "$BACKEND_MODE" == "openwrt" ]]; then
            if grep -E "ban-applied ip=${test_ip//./\\.} .*backend=openwrt rc=0" <<<"$logs" >/dev/null; then
                ok "ban sintetico TEST-NET confermato dal backend OpenWrt per $test_ip (30s)"
                return 0
            fi
        else
            if grep -E "ban-applied ip=${test_ip//./\\.} .*backend=local rc=0" <<<"$logs" >/dev/null; then
                "$FASTBAN" check "$test_ip" >/dev/null 2>&1 || fail "helper dichiara ban locale applicato ma fastban non contiene $test_ip"
                "$FASTBAN" del "$test_ip" >/dev/null 2>&1 || true
                ok "ban sintetico TEST-NET applicato localmente con policy 30s e poi ripulito ($test_ip)"
                return 0
            fi
        fi
        sleep 0.1
    done

    journal_since "$start_epoch" >&2 || true
    fail "ban sintetico TEST-NET non confermato per $test_ip in modalità $BACKEND_MODE"
}

case "$MODE" in
    --http) http_selftest ;;
    --firewall) firewall_selftest ;;
    *) echo "Uso: $0 --http | --firewall" >&2; exit 2 ;;
esac
