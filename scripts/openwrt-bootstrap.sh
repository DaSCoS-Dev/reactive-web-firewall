#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

HOST=""; USER="root"; PORT="22"; KNOWN_HOSTS=""; RUNTIME_KEY=""; PAYLOAD_DIR=""; ADMIN_KEY="${RWF_OPENWRT_ADMIN_KEY:-}"

say(){ printf '%s\n' "$*"; }
warn(){ printf 'ATTENZIONE: %s\n' "$*" >&2; }
die(){ printf 'ERRORE: %s\n' "$*" >&2; exit 1; }

usage(){
    echo "Uso: $0 --host HOST --user USER --port PORT --known-hosts FILE --runtime-key FILE --payload-dir DIR [--admin-key FILE]" >&2
    exit 2
}

while (($#)); do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --known-hosts) KNOWN_HOSTS="$2"; shift 2 ;;
        --runtime-key) RUNTIME_KEY="$2"; shift 2 ;;
        --payload-dir) PAYLOAD_DIR="$2"; shift 2 ;;
        --admin-key) ADMIN_KEY="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -n "$HOST" && -n "$USER" && -n "$KNOWN_HOSTS" && -n "$RUNTIME_KEY" && -d "$PAYLOAD_DIR" ]] || usage
[[ -r "$RUNTIME_KEY" ]] || die "chiave runtime non leggibile: $RUNTIME_KEY"
command -v ssh >/dev/null || die "ssh non disponibile"
command -v ssh-keygen >/dev/null || die "ssh-keygen non disponibile"
command -v tar >/dev/null || die "tar non disponibile"

TARGET="$USER@$HOST"
SSH_BASE=(
    -F /dev/null -p "$PORT"
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o ConnectTimeout=5 -o ConnectionAttempts=1 -o LogLevel=ERROR
)

valid_private_key(){
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || return 1
    case "$f" in *.pub|*-cert.pub|*/known_hosts|*/known_hosts.old|*/config|*.bak) return 1 ;; esac
    timeout 3 ssh-keygen -y -P '' -f "$f" </dev/null >/dev/null 2>&1
}

RUNTIME_PUB_BLOB="$(ssh-keygen -y -f "$RUNTIME_KEY" | awk '{print $2}')"
[[ -n "$RUNTIME_PUB_BLOB" ]] || die "impossibile derivare la chiave pubblica runtime"

is_same_as_runtime_key(){
    local f="$1" blob
    blob="$(ssh-keygen -y -P '' -f "$f" 2>/dev/null | awk '{print $2}' || true)"
    [[ -n "$blob" && "$blob" == "$RUNTIME_PUB_BLOB" ]]
}

admin_probe_with_key(){
    local key="$1" out
    out="$(ssh "${SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$key" "$TARGET" \
        'printf "__RWF_ADMIN_OK__\n"; printf "__RWF_SSH_CONNECTION__%s\n" "$SSH_CONNECTION"; test -r /etc/openwrt_release && cat /etc/openwrt_release' 2>/dev/null || true)"
    grep -q '^__RWF_ADMIN_OK__$' <<<"$out" || return 1
    ADMIN_PROBE_OUTPUT="$out"
    return 0
}

ADMIN_MODE="key"
ADMIN_PROBE_OUTPUT=""
if [[ -n "$ADMIN_KEY" ]]; then
    valid_private_key "$ADMIN_KEY" || die "chiave amministrativa non valida/non cifrata: $ADMIN_KEY"
    is_same_as_runtime_key "$ADMIN_KEY" && die "la chiave amministrativa non può coincidere con la chiave runtime forced-command"
    admin_probe_with_key "$ADMIN_KEY" || die "la chiave amministrativa indicata non apre una shell su $TARGET"
else
    declare -A seen=()
    candidates=()
    for f in /root/.ssh/id_* /etc/fail2ban/keys/* /etc/reactive-web-firewall/*; do
        [[ -e "$f" ]] || continue
        [[ "$f" == "$RUNTIME_KEY" ]] && continue
        [[ -z "${seen[$f]:-}" ]] || continue
        seen[$f]=1
        if valid_private_key "$f" && ! is_same_as_runtime_key "$f"; then
            candidates+=("$f")
        fi
    done
    for f in "${candidates[@]}"; do
        if admin_probe_with_key "$f"; then ADMIN_KEY="$f"; break; fi
    done

    if [[ -z "$ADMIN_KEY" ]]; then
        if [[ ! -t 0 ]]; then die "nessuna chiave amministrativa SSH trovata per bootstrap OpenWrt"; fi
        say "Nessuna chiave amministrativa non cifrata rilevata automaticamente."
        say "  1) Inserisci il percorso di una chiave amministrativa"
        say "  2) Usa SSH interattivo (agent/password) per il solo bootstrap"
        read -r -p "Scelta [2]: " choice
        choice="${choice:-2}"
        if [[ "$choice" == 1 ]]; then
            read -r -p "Percorso chiave amministrativa: " ADMIN_KEY
            valid_private_key "$ADMIN_KEY" || die "chiave amministrativa non valida"
            is_same_as_runtime_key "$ADMIN_KEY" && die "la chiave amministrativa non può coincidere con la chiave runtime forced-command"
            admin_probe_with_key "$ADMIN_KEY" || die "la chiave non apre una shell amministrativa su $TARGET"
        else
            ADMIN_MODE="interactive"
            ADMIN_PROBE_OUTPUT="$(ssh "${SSH_BASE[@]}" "$TARGET" \
                'printf "__RWF_ADMIN_OK__\n"; printf "__RWF_SSH_CONNECTION__%s\n" "$SSH_CONNECTION"; test -r /etc/openwrt_release && cat /etc/openwrt_release')"
            grep -q '^__RWF_ADMIN_OK__$' <<<"$ADMIN_PROBE_OUTPUT" || die "accesso amministrativo interattivo non riuscito"
        fi
    fi
fi

SOURCE_LINE="$(sed -n 's/^__RWF_SSH_CONNECTION__//p' <<<"$ADMIN_PROBE_OUTPUT" | head -n1)"
ALLOWED_SOURCE="$(awk '{print $1}' <<<"$SOURCE_LINE")"
[[ "$ALLOWED_SOURCE" =~ ^[0-9A-Fa-f:.]+$ ]] || die "impossibile ricavare l'IP sorgente del proxy da SSH_CONNECTION: [$SOURCE_LINE]"
say "OpenWrt vede il proxy con sorgente: $ALLOWED_SOURCE"

# Confronto diagnostico con la route locale; l'osservazione remota resta autoritativa.
LOCAL_SRC=""
if command -v ip >/dev/null 2>&1; then
    LOCAL_SRC="$(ip route get "$HOST" 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\([^[:space:]]*\).*/\1/p' | head -n1 || true)"
fi
if [[ -n "$LOCAL_SRC" && "$LOCAL_SRC" != "$ALLOWED_SOURCE" ]]; then
    warn "Il routing locale propone src=$LOCAL_SRC, ma OpenWrt vede src=$ALLOWED_SOURCE."
    if [[ -t 0 ]]; then
        read -r -p "Usare l'indirizzo realmente visto da OpenWrt ($ALLOWED_SOURCE)? [S/n] " ans
        case "${ans,,}" in n|no) die "bootstrap interrotto: sorgente proxy non confermata" ;; esac
    fi
fi

TMP="$(mktemp -d /tmp/rwf-openwrt-payload.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
cp -a "$PAYLOAD_DIR"/. "$TMP"/
PUB="$(ssh-keygen -y -f "$RUNTIME_KEY")"
printf '%s rwf-runtime\n' "$PUB" > "$TMP/runtime.pub"

remote_extract='rm -rf /tmp/rwf-openwrt-install && mkdir -p /tmp/rwf-openwrt-install && tar xzf - -C /tmp/rwf-openwrt-install'
remote_install="/tmp/rwf-openwrt-install/install-openwrt.sh --allowed-source '$ALLOWED_SOURCE' --runtime-pubkey /tmp/rwf-openwrt-install/runtime.pub --install-tools yes; rc=\$?; rm -rf /tmp/rwf-openwrt-install; exit \$rc"

say "Trasferimento payload OpenWrt e installazione..."
if [[ "$ADMIN_MODE" == key ]]; then
    tar czf - -C "$TMP" . | ssh "${SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$ADMIN_KEY" "$TARGET" "$remote_extract"
    ssh "${SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$ADMIN_KEY" "$TARGET" "$remote_install"
else
    # La password/agent vengono richiesti sul terminale; lo stream tar resta su stdin.
    tar czf - -C "$TMP" . | ssh "${SSH_BASE[@]}" "$TARGET" "$remote_extract"
    ssh "${SSH_BASE[@]}" "$TARGET" "$remote_install"
fi

printf 'RWF_OPENWRT_ALLOWED_SOURCE=%s\n' "$ALLOWED_SOURCE"
printf 'RWF_OPENWRT_API=%s\n' '1'
