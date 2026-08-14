#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

RWF_VERSION="2026.08.14-installer-07.0"
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/reactive-web-firewall/${STAMP}"
RWF_ETC="/etc/reactive-web-firewall"
RWF_HELPER_BIN="/usr/local/sbin/rwf-helper"
RWF_HELPER_SERVICE="/etc/systemd/system/rwf-helper.service"
RWF_ACCESSLOG_BIN="/usr/local/sbin/rwf-accesslog-filter"
RWF_PLATFORM_LIB="/usr/local/lib/reactive-web-firewall/platform.sh"
RWF_FISH_BIN="/usr/local/sbin/rwf-fish"
RWF_STATUS_BIN="/usr/local/sbin/rwf-status"
RWF_RUNTIME_CONF="$RWF_ETC/runtime.conf"
RWF_LOG_READER_BIN="/usr/local/sbin/rwf-log-reader"
RWF_LOG_RULES_LIB="/usr/local/lib/reactive-web-firewall/RwfLogRules.pm"
RWF_LOG_READER_CONF="$RWF_ETC/log-reader.conf"
RWF_LOG_READER_SERVICE="/etc/systemd/system/rwf-log-reader.service"
RWF_BACKEND_CONF="$RWF_ETC/backend.conf"
LEGACY_SERVICE="custom-web-ban-immediate.service"
LEGACY_SCRIPT="/usr/local/sbin/custom-web-ban-immediate.pl"

FASTBAN="${RWF_FASTBAN:-/usr/local/sbin/custom-web-fastban}"
FASTBAN_RULESET="${RWF_FASTBAN_RULESET:-/etc/nftables.d/custom-web-fastban.nft}"
FASTBAN_SERVICE="/etc/systemd/system/custom-web-fastban.service"
FASTBAN_STATE_DIR="/var/lib/reactive-web-firewall"
SS_BIN="${RWF_SS:-$(command -v ss || true)}"
SSH_BIN="${RWF_SSH:-$(command -v ssh || true)}"
SSH_KEYGEN="$(command -v ssh-keygen || true)"
SSH_KEYSCAN="$(command -v ssh-keyscan || true)"

FIREWALL_MODE="local-only"
FIREWALL_HOST="${RWF_FIREWALL_HOST:-}"
FIREWALL_USER="${RWF_FIREWALL_USER:-}"
SSH_PORT="${RWF_SSH_PORT:-}"
SSH_KEY="${RWF_SSH_KEY:-}"
KNOWN_HOSTS="${RWF_KNOWN_HOSTS:-}"
FALLBACK_TTL="${RWF_FALLBACK_TTL:-5m}"
FIREWALL_TARGET=""
OPENWRT_ALLOWED_SOURCE=""
OPENWRT_API_VERSION=""

LEGACY_PRESENT=0
LEGACY_ACTIVE_BEFORE=0
LEGACY_ENABLED_BEFORE=0
DISABLE_LEGACY=0
CUTOVER_DONE=0
TEST_URL="${RWF_TEST_URL:-}"
RULES_ACTION="replace"
PRESERVE_WHITELIST=1
DROP_CONNECTION=1
SUPPRESS_ACCESSLOG=1
DETECTION_ENGINE=""
PREVIOUS_ENGINE="none"
LOG_READER_LOG=""

C_RESET='\033[0m'; C_BOLD='\033[1m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_BLUE='\033[34m'
say()  { printf '%b\n' "$*"; }
info() { say "${C_BLUE}==>${C_RESET} $*"; }
ok()   { say "${C_GREEN}OK:${C_RESET} $*"; }
warn() { say "${C_YELLOW}ATTENZIONE:${C_RESET} $*"; }
die()  { say "${C_RED}ERRORE:${C_RESET} $*" >&2; exit 1; }

# shellcheck disable=SC1091
source "$BASE_DIR/scripts/platform.sh"

ask_yes_no() {
    local prompt="$1" default="${2:-y}" answer suffix="[S/n]"
    [[ "$default" == "n" ]] && suffix="[s/N]"
    if [[ ! -t 0 ]]; then [[ "$default" == "y" ]]; return; fi
    read -r -p "$prompt $suffix " answer
    answer="${answer,,}"
    if [[ -z "$answer" ]]; then
        [[ "$default" == "y" ]]
    else
        [[ "$answer" == "s" || "$answer" == "si" || "$answer" == "sì" || "$answer" == "y" || "$answer" == "yes" ]]
    fi
}

prompt_value() {
    local prompt="$1" default="$2" value
    if [[ ! -t 0 ]]; then printf '%s\n' "$default"; return; fi
    read -r -p "$prompt [$default]: " value
    printf '%s\n' "${value:-$default}"
}

backup_path() {
    local path="$1"
    [[ -e "$path" || -L "$path" ]] || return 0
    mkdir -p "$BACKUP_DIR$(dirname "$path")"
    cp -a -- "$path" "$BACKUP_DIR$path"
}

legacy_is_present() {
    [[ -e "$LEGACY_SCRIPT" ]] && return 0
    systemctl cat "$LEGACY_SERVICE" >/dev/null 2>&1 && return 0
    [[ -e "/etc/csf/custom-web-ban-immediate.conf" ]] && return 0
    return 1
}

helper_diagnostics() {
    warn "Diagnostica rwf-helper.service:"
    systemctl status rwf-helper.service --no-pager -l >&2 || true
    journalctl -u rwf-helper.service -n 80 --no-pager >&2 || true
}

wait_for_helper_ready() {
    local timeout_ds="${1:-100}" i
    for ((i=0; i<timeout_ds; ++i)); do
        if [[ -S /run/reactive-web-firewall/helper.sock ]] && systemctl is-active --quiet rwf-helper.service; then return 0; fi
        if systemctl is-failed --quiet rwf-helper.service; then helper_diagnostics; return 1; fi
        sleep 0.1
    done
    helper_diagnostics
    return 1
}

write_rwf_conf() {
    local drop_word="Off" suppress_word="Off"
    (( DROP_CONNECTION )) && drop_word="On"
    (( SUPPRESS_ACCESSLOG )) && suppress_word="On"
    sed \
        -e "s|@RWF_DROP_CONNECTION@|$drop_word|g" \
        -e "s|@RWF_SUPPRESS_ACCESSLOG@|$suppress_word|g" \
        "$BASE_DIR/apache/rwf.conf.in" > "$RWF_CONF_FILE"
    chown root:root "$RWF_CONF_FILE"
    chmod 0644 "$RWF_CONF_FILE"
}

existing_option_default() {
    local directive="$1" file="$2" fallback="$3" value
    [[ -r "$file" ]] || { printf '%s\n' "$fallback"; return; }
    value="$(awk -v d="$directive" 'tolower($1)==tolower(d){print tolower($2); exit}' "$file" 2>/dev/null || true)"
    case "$value" in on) echo y ;; off) echo n ;; *) echo "$fallback" ;; esac
}

service_arg() {
    local name="$1" file="${2:-$RWF_HELPER_SERVICE}"
    [[ -r "$file" ]] || return 1
    sed -nE "s|^[[:space:]]*--${name}[[:space:]]+([^[:space:]\\\\]+).*|\\1|p" "$file" | tail -n 1
}

existing_backend_default() {
    if [[ -r "$RWF_HELPER_SERVICE" ]]; then
        if grep -F -- '--mode local-only' "$RWF_HELPER_SERVICE" >/dev/null 2>&1; then
            echo n
        elif grep -F -- '--mode openwrt' "$RWF_HELPER_SERVICE" >/dev/null 2>&1 || grep -F -- '--firewall ' "$RWF_HELPER_SERVICE" >/dev/null 2>&1; then
            echo y
        else
            echo n
        fi
    else
        echo n
    fi
}

validate_host() {
    local h="$1"
    [[ -n "$h" && "$h" != -* && "$h" != *[[:space:]]* && "$h" != *'/'* && "$h" != *'@'* ]]
}

validate_user() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

validate_fallback_ttl() {
    local v="${1,,}"
    [[ "$v" =~ ^[1-9][0-9]*([smhd])?$ ]]
}

ensure_openwrt_packages() {
    local -a pkgs missing=()
    mapfile -t pkgs < <(rwf_openwrt_packages)
    for pkg in "${pkgs[@]}"; do rwf_package_is_installed "$pkg" || missing+=("$pkg"); done
    if ((${#missing[@]})); then
        warn "Pacchetti SSH necessari per OpenWrt mancanti: ${missing[*]}"
        if ask_yes_no "Installarli ora con ${RWF_PACKAGE_MANAGER}?" y; then
            rwf_install_packages "${missing[@]}"
        else
            return 1
        fi
    fi
    SSH_BIN="${RWF_SSH:-$(command -v ssh || true)}"
    SSH_KEYGEN="$(command -v ssh-keygen || true)"
    SSH_KEYSCAN="$(command -v ssh-keyscan || true)"
    [[ -x "$SSH_BIN" && -x "$SSH_KEYGEN" && -x "$SSH_KEYSCAN" ]]
}

valid_unencrypted_private_key() {
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || return 1
    case "$f" in *.pub|*-cert.pub|*/known_hosts|*/known_hosts.old|*/config|*.bak) return 1 ;; esac
    timeout 3 "$SSH_KEYGEN" -y -P '' -f "$f" </dev/null >/dev/null 2>&1
}

discover_ssh_keys() {
    local preferred="${1:-}" f
    local -A seen=()
    RWF_KEY_CANDIDATES=()

    add_candidate() {
        local c="$1"
        [[ -n "$c" && -z "${seen[$c]:-}" ]] || return 0
        seen["$c"]=1
        valid_unencrypted_private_key "$c" && RWF_KEY_CANDIDATES+=("$c")
    }

    add_candidate "$preferred"
    add_candidate "${RWF_SSH_KEY:-}"
    for f in \
        /etc/fail2ban/keys/* \
        /etc/reactive-web-firewall/* \
        /root/.ssh/id_* \
        /root/.ssh/*ed25519* \
        /root/.ssh/*rsa*; do
        [[ -e "$f" ]] || continue
        add_candidate "$f"
    done
}

generate_openwrt_key() {
    local path="$RWF_ETC/openwrt_rwf_ed25519"
    install -d -o root -g root -m 0755 "$RWF_ETC" || return 1
    if [[ -e "$path" || -e "$path.pub" ]]; then
        path="$RWF_ETC/openwrt_rwf_ed25519_${STAMP}"
    fi
    "$SSH_KEYGEN" -q -t ed25519 -N '' -C "rwf@$(hostname -f 2>/dev/null || hostname)" -f "$path"         || { warn "Generazione chiave SSH fallita."; return 1; }
    chmod 0600 "$path" || return 1
    chmod 0644 "$path.pub" || return 1
    ok "Nuova chiave runtime ed25519 creata: $path"
    info "Se il backend OpenWrt viene installato dal wizard, la chiave pubblica verrà autorizzata automaticamente con forced-command."
    SELECTED_SSH_KEY="$path"
}

choose_ssh_key() {
    local preferred="$1" choice i manual preferred_valid=0
    SELECTED_SSH_KEY=""

    if [[ -n "$preferred" ]] && valid_unencrypted_private_key "$preferred"; then
        preferred_valid=1
    fi

    discover_ssh_keys "$preferred"

    if (( preferred_valid )); then
        # Upgrade/existing backend: the configured key is the safest default.
        if [[ ! -t 0 ]]; then
            SELECTED_SSH_KEY="$preferred"
            return 0
        fi
        say "Chiavi private SSH non cifrate rilevate:"
        for i in "${!RWF_KEY_CANDIDATES[@]}"; do
            say "  $((i+1))) ${RWF_KEY_CANDIDATES[$i]}"
        done
        say "  m) Inserisci un percorso manuale"
        say "  g) Genera una nuova chiave ed25519 dedicata a RwF"
        read -r -p "Scelta [1]: " choice
        choice="${choice:-1}"
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#RWF_KEY_CANDIDATES[@]} )); then
            SELECTED_SSH_KEY="${RWF_KEY_CANDIDATES[$((choice-1))]}"
            return 0
        fi
    else
        # Fresh install: never silently repurpose a generic/root admin key as
        # the forced-command runtime key. Generate a dedicated key by default.
        if [[ ! -t 0 ]]; then
            generate_openwrt_key
            return $?
        fi
        if ((${#RWF_KEY_CANDIDATES[@]})); then
            say "Altre chiavi private non cifrate rilevate (selezione manuale possibile):"
            for i in "${!RWF_KEY_CANDIDATES[@]}"; do
                say "  $((i+1))) ${RWF_KEY_CANDIDATES[$i]}"
            done
        else
            warn "Nessuna chiave runtime RwF esistente rilevata."
        fi
        say "  m) Inserisci un percorso manuale"
        say "  g) Genera una nuova chiave ed25519 dedicata a RwF"
        read -r -p "Scelta [g]: " choice
        choice="${choice:-g}"
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#RWF_KEY_CANDIDATES[@]} )); then
            SELECTED_SSH_KEY="${RWF_KEY_CANDIDATES[$((choice-1))]}"
            warn "Hai scelto esplicitamente una chiave non dedicata: sul firewall verrà vincolata al forced-command RwF."
            return 0
        fi
    fi

    case "${choice,,}" in
        m)
            read -r -p "Percorso chiave privata SSH runtime: " manual
            valid_unencrypted_private_key "$manual" || { warn "Chiave non valida, cifrata o non leggibile: $manual"; return 1; }
            SELECTED_SSH_KEY="$manual"
            warn "La chiave runtime scelta verrà vincolata al forced-command RwF sul firewall."
            ;;
        g)
            generate_openwrt_key || return 1
            ;;
        *)
            warn "Scelta chiave non valida."
            return 1
            ;;
    esac
}

host_key_lookup_name() {
    local host="$1" port="$2"
    if [[ "$port" == "22" ]]; then printf '%s\n' "$host"; else printf '[%s]:%s\n' "$host" "$port"; fi
}

show_key_fingerprints() {
    local data="$1"
    [[ -n "$data" ]] || return 0
    printf '%s\n' "$data" | "$SSH_KEYGEN" -lf - 2>/dev/null || true
}

known_host_material() {
    awk '!/^#/ && NF>=3 {print $2" "$3}' | sort -u
}

ensure_known_host() {
    local host="$1" port="$2" file="$3" lookup scan existing scan_material existing_material common tmp
    lookup="$(host_key_lookup_name "$host" "$port")"
    scan="$($SSH_KEYSCAN -T 5 -p "$port" "$host" 2>/dev/null | awk '!/^#/ && NF>=3 {print}' || true)"
    [[ -n "$scan" ]] || { warn "ssh-keyscan non ha ricevuto alcuna host key da $host:$port"; return 1; }

    say "Host key presentate da $host:$port:"
    show_key_fingerprints "$scan"

    install -d -o root -g root -m 0700 "$(dirname "$file")" || return 1
    if [[ ! -e "$file" ]]; then
        touch "$file" || return 1
        chmod 0600 "$file" || return 1
        chown root:root "$file" || return 1
    fi
    backup_path "$file" || return 1

    existing="$($SSH_KEYGEN -F "$lookup" -f "$file" 2>/dev/null | awk '!/^#/ && NF>=3 {print}' || true)"
    if [[ -z "$existing" ]]; then
        if ! ask_yes_no "Nessuna host key presente in $file. Confermare queste fingerprint e aggiungerle?" n; then
            warn "Host key non confermata."
            return 1
        fi
        printf '%s\n' "$scan" >> "$file" || return 1
        chmod 0600 "$file" || return 1
        ok "Host key OpenWrt aggiunta a $file"
        return 0
    fi

    scan_material="$(printf '%s\n' "$scan" | known_host_material)"
    existing_material="$(printf '%s\n' "$existing" | known_host_material)"
    tmp="$(mktemp -d /tmp/rwf-hostkey.XXXXXX)"
    printf '%s\n' "$scan_material" > "$tmp/scan"
    printf '%s\n' "$existing_material" > "$tmp/existing"
    common="$(comm -12 "$tmp/scan" "$tmp/existing" || true)"
    rm -rf "$tmp"

    if [[ -n "$common" ]]; then
        ok "Host key OpenWrt già presente e coerente in $file"
        return 0
    fi

    warn "La host key presente in $file NON coincide con quelle attualmente presentate da $host:$port."
    say "Fingerprint già memorizzate:"
    show_key_fingerprints "$existing"
    say "Fingerprint appena rilevate:"
    show_key_fingerprints "$scan"
    if ! ask_yes_no "Sostituire esplicitamente la vecchia host key con quella appena mostrata?" n; then
        return 1
    fi

    "$SSH_KEYGEN" -R "$lookup" -f "$file" >/dev/null 2>&1 || true
    printf '%s\n' "$scan" >> "$file" || return 1
    chmod 0600 "$file" || return 1
    ok "Host key OpenWrt sostituita dopo conferma esplicita."
}

openwrt_remote_test() {
    local test_ip cmd output rc
    test_ip="198.51.100.$((100 + RANDOM % 100))"
    cmd="temp-add $test_ip 30 proxy RWF_INSTALLER_PREFLIGHT"
    info "Test SSH/OpenWrt reale con IP TEST-NET $test_ip (30s)"

    if output="$($SSH_BIN \
        -F /dev/null \
        -i "$SSH_KEY" \
        -p "$SSH_PORT" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$KNOWN_HOSTS" \
        -o ConnectTimeout=3 \
        -o ConnectionAttempts=1 \
        -o LogLevel=ERROR \
        "$FIREWALL_TARGET" "$cmd" 2>&1)"; then
        ok "Connessione e comando OpenWrt verificati: $FIREWALL_TARGET:$SSH_PORT"
        [[ -n "$output" ]] && say "$output"
        return 0
    else
        rc=$?
        warn "Test OpenWrt fallito (rc=$rc)."
        [[ -n "$output" ]] && say "$output"
        return 1
    fi
}

openwrt_remote_version() {
    local output
    output="$($SSH_BIN \
        -F /dev/null -i "$SSH_KEY" -p "$SSH_PORT" \
        -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS" \
        -o ConnectTimeout=3 -o ConnectionAttempts=1 -o LogLevel=ERROR \
        "$FIREWALL_TARGET" version 2>/dev/null || true)"
    if [[ "$output" =~ ^RWF-OPENWRT-API[[:space:]]+([0-9]+)$ ]]; then
        OPENWRT_API_VERSION="${BASH_REMATCH[1]}"
        ok "Backend OpenWrt API $OPENWRT_API_VERSION rilevato."
        return 0
    fi
    return 1
}

openwrt_bootstrap() {
    local tmp rc
    tmp="$(mktemp /tmp/rwf-openwrt-bootstrap.XXXXXX)"
    info "Bootstrap/aggiornamento del payload OpenWrt via SSH amministrativo"
    if "$BASE_DIR/scripts/openwrt-bootstrap.sh" \
        --host "$FIREWALL_HOST" \
        --user "$FIREWALL_USER" \
        --port "$SSH_PORT" \
        --known-hosts "$KNOWN_HOSTS" \
        --runtime-key "$SSH_KEY" \
        --payload-dir "$BASE_DIR/openwrt" | tee "$tmp"; then
        rc=0
    else
        rc=$?
    fi
    if (( rc == 0 )); then
        OPENWRT_ALLOWED_SOURCE="$(sed -n 's/^RWF_OPENWRT_ALLOWED_SOURCE=//p' "$tmp" | tail -n1)"
        OPENWRT_API_VERSION="$(sed -n 's/^RWF_OPENWRT_API=//p' "$tmp" | tail -n1)"
    fi
    rm -f "$tmp"
    return "$rc"
}

openwrt_failure_menu() {
    local choice
    OPENWRT_ACTION="abort"
    if [[ ! -t 0 ]]; then return 0; fi
    say ""
    say "OpenWrt non è stato validato."
    say "  1) Correggi configurazione OpenWrt e riparti dall'host/IP"
    say "  2) Prosegui SENZA firewall di frontiera, modalità LOCAL-ONLY"
    say "  3) Interrompi installazione"
    read -r -p "Scelta [1]: " choice
    choice="${choice:-1}"
    case "$choice" in
        1) OPENWRT_ACTION="correct" ;;
        2) OPENWRT_ACTION="local-only" ;;
        *) OPENWRT_ACTION="abort" ;;
    esac
}

configure_openwrt_backend() {
    local existing_target existing_host existing_user existing_port existing_key existing_known
    local backend_already_working=0
    existing_target="${RWF_FIREWALL:-$(service_arg firewall || true)}"
    existing_port="${RWF_SSH_PORT:-$(service_arg ssh-port || true)}"
    existing_key="${RWF_SSH_KEY:-$(service_arg ssh-key || true)}"
    existing_known="${RWF_KNOWN_HOSTS:-$(service_arg known-hosts || true)}"

    if [[ -n "$existing_target" && "$existing_target" == *"@"* ]]; then
        existing_user="${existing_target%@*}"
        existing_host="${existing_target#*@}"
    else
        existing_user="root"
        existing_host=""
    fi
    existing_user="${FIREWALL_USER:-${existing_user:-root}}"
    existing_host="${FIREWALL_HOST:-${existing_host:-}}"
    existing_port="${SSH_PORT:-${existing_port:-22}}"
    existing_key="${SSH_KEY:-${existing_key:-$RWF_ETC/openwrt_rwf_ed25519}}"
    existing_known="${KNOWN_HOSTS:-${existing_known:-$RWF_ETC/openwrt_known_hosts}}"

    if ! ensure_openwrt_packages; then
        warn "Client OpenSSH non disponibile."
        openwrt_failure_menu
        case "$OPENWRT_ACTION" in
            correct) ensure_openwrt_packages || return 3 ;;
            local-only) FIREWALL_MODE="local-only"; return 0 ;;
            *) return 3 ;;
        esac
    fi

    while true; do
        FIREWALL_HOST="$(prompt_value "Host/IP del firewall OpenWrt" "$existing_host")"
        validate_host "$FIREWALL_HOST" || { warn "Host/IP non valido."; continue; }
        FIREWALL_USER="$(prompt_value "Utente SSH OpenWrt" "$existing_user")"
        validate_user "$FIREWALL_USER" || { warn "Utente SSH non valido."; continue; }
        SSH_PORT="$(prompt_value "Porta SSH OpenWrt" "$existing_port")"
        validate_port "$SSH_PORT" || { warn "Porta SSH non valida."; continue; }
        KNOWN_HOSTS="$(prompt_value "File known_hosts dedicato a RwF" "$existing_known")"
        [[ "$KNOWN_HOSTS" == /* ]] || { warn "known_hosts deve essere un percorso assoluto."; continue; }
        FIREWALL_TARGET="$FIREWALL_USER@$FIREWALL_HOST"

        if ! ensure_known_host "$FIREWALL_HOST" "$SSH_PORT" "$KNOWN_HOSTS"; then
            openwrt_failure_menu
            case "$OPENWRT_ACTION" in correct) continue ;; local-only) FIREWALL_MODE="local-only"; return 0 ;; *) return 3 ;; esac
        fi

        if choose_ssh_key "$existing_key"; then
            SSH_KEY="$SELECTED_SSH_KEY"
            existing_key="$SSH_KEY"
        else
            openwrt_failure_menu
            case "$OPENWRT_ACTION" in correct) continue ;; local-only) FIREWALL_MODE="local-only"; return 0 ;; *) return 3 ;; esac
        fi

        backend_already_working=0
        if openwrt_remote_test; then
            backend_already_working=1
            openwrt_remote_version || info "Backend OpenWrt funzionante ma non ancora versionato dal pacchetto RwF."
        fi

        if (( backend_already_working )); then
            if ask_yes_no "Installare/aggiornare anche il payload OpenWrt gestito da RwF?" y; then
                if openwrt_bootstrap; then
                    openwrt_remote_version || { warn "Bootstrap completato ma comando version non disponibile."; continue; }
                    openwrt_remote_test || { warn "Backend non valido dopo bootstrap."; continue; }
                else
                    warn "Bootstrap OpenWrt non riuscito; il backend preesistente risultava comunque operativo."
                    ask_yes_no "Proseguire usando il backend OpenWrt preesistente?" y || continue
                fi
            fi
        else
            warn "La chiave runtime non può ancora eseguire temp-add sul firewall."
            if ask_yes_no "Installare/configurare automaticamente il backend OpenWrt via accesso SSH amministrativo?" y; then
                if ! openwrt_bootstrap; then
                    openwrt_failure_menu
                    case "$OPENWRT_ACTION" in correct) continue ;; local-only) FIREWALL_MODE="local-only"; return 0 ;; *) return 3 ;; esac
                fi
                openwrt_remote_version || { warn "API OpenWrt non rilevata dopo bootstrap."; continue; }
                openwrt_remote_test || { warn "Test temp-add fallito dopo bootstrap."; continue; }
            else
                openwrt_failure_menu
                case "$OPENWRT_ACTION" in correct) continue ;; local-only) FIREWALL_MODE="local-only"; return 0 ;; *) return 3 ;; esac
            fi
        fi

        FALLBACK_TTL="$(prompt_value "TTL del fast-ban locale di fallback se OpenWrt non risponde" "$FALLBACK_TTL")"
        validate_fallback_ttl "$FALLBACK_TTL" || { warn "TTL fallback non valido. Usare per esempio 300, 30s, 5m, 4h o 3d."; continue; }
        FIREWALL_MODE="openwrt"
        return 0
    done
}

write_backend_conf() {
    {
        echo "# Reactive Web Firewall backend configuration"
        echo "# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>"
        echo "# SPDX-License-Identifier: AGPL-3.0-or-later"
        printf 'MODE=%q\n' "$FIREWALL_MODE"
        printf 'FASTBAN=%q\n' "$FASTBAN"
        if [[ "$FIREWALL_MODE" == "openwrt" ]]; then
            printf 'OPENWRT_HOST=%q\n' "$FIREWALL_HOST"
            printf 'OPENWRT_USER=%q\n' "$FIREWALL_USER"
            printf 'OPENWRT_SSH_PORT=%q\n' "$SSH_PORT"
            printf 'OPENWRT_SSH_KEY=%q\n' "$SSH_KEY"
            printf 'OPENWRT_KNOWN_HOSTS=%q\n' "$KNOWN_HOSTS"
            printf 'OPENWRT_FALLBACK_TTL=%q\n' "$FALLBACK_TTL"
            [[ -n "$OPENWRT_ALLOWED_SOURCE" ]] && printf 'OPENWRT_ALLOWED_SOURCE=%q\n' "$OPENWRT_ALLOWED_SOURCE"
            [[ -n "$OPENWRT_API_VERSION" ]] && printf 'OPENWRT_API_VERSION=%q\n' "$OPENWRT_API_VERSION"
        fi
    } > "$RWF_BACKEND_CONF"
    chown root:root "$RWF_BACKEND_CONF"; chmod 0644 "$RWF_BACKEND_CONF"
}

render_helper_service() {
    local template="$1"
    python3 - "$template" "$RWF_HELPER_SERVICE" \
        "$RWF_APACHE_GROUP" "$FASTBAN" "$SS_BIN" "${SSH_BIN:-}" "${SSH_PORT:-22}" \
        "${SSH_KEY:-}" "${KNOWN_HOSTS:-}" "${FIREWALL_TARGET:-}" "$FALLBACK_TTL" <<'PY'
from pathlib import Path
import sys
src, dst, group, fastban, ss, ssh, port, key, known, firewall, ttl = sys.argv[1:]
text = Path(src).read_text()
repl = {
    '@APACHE_GROUP@': group,
    '@FASTBAN@': fastban,
    '@SS@': ss,
    '@SSH@': ssh,
    '@SSH_PORT@': port,
    '@SSH_KEY@': key,
    '@KNOWN_HOSTS@': known,
    '@FIREWALL@': firewall,
    '@FALLBACK_TTL@': ttl,
}
for old, new in repl.items():
    text = text.replace(old, new)
Path(dst).write_text(text)
PY
    chown root:root "$RWF_HELPER_SERVICE"; chmod 0644 "$RWF_HELPER_SERVICE"
}

detect_existing_engine() {
    local e=""
    if [[ -r "$RWF_RUNTIME_CONF" ]]; then
        e="$(awk -F= '/^[[:space:]]*DETECTION_ENGINE=/{gsub(/[\"\047[:space:]]/,"",$2); print tolower($2); exit}' "$RWF_RUNTIME_CONF" 2>/dev/null || true)"
        case "$e" in
            apache|inside-apache) echo inside-apache; return 0 ;;
            log|log-reader) echo log-reader; return 0 ;;
        esac
    fi
    if systemctl is-active --quiet rwf-log-reader.service 2>/dev/null; then echo log-reader; return 0; fi
    if systemctl is-active --quiet "$LEGACY_SERVICE" 2>/dev/null; then echo legacy-log-reader; return 0; fi
    if rwf_apache_module_loaded 2>/dev/null; then echo inside-apache; return 0; fi
    echo none
}

choose_detection_engine() {
    local requested="${RWF_DETECTION_ENGINE:-}" choice default_choice=1
    requested="${requested,,}"
    case "$requested" in
        apache|inside-apache) DETECTION_ENGINE="inside-apache"; return 0 ;;
        log|log-reader) DETECTION_ENGINE="log-reader"; return 0 ;;
        "") ;;
        *) die "RWF_DETECTION_ENGINE non valido: $requested" ;;
    esac

    case "$PREVIOUS_ENGINE" in
        log-reader|legacy-log-reader) default_choice=2 ;;
        *) default_choice=1 ;;
    esac
    if [[ ! -t 0 ]]; then
        [[ "$default_choice" == 2 ]] && DETECTION_ENGINE=log-reader || DETECTION_ENGINE=inside-apache
        return 0
    fi

    say ""
    say "${C_BOLD}Motore di rilevazione${C_RESET}"
    say "  1) Inside Apache   - mod_rwf intercetta prima dell'applicazione"
    say "  2) Log Reader      - legge l'access log Apache dopo la risposta"
    read -r -p "Scelta [$default_choice]: " choice
    choice="${choice:-$default_choice}"
    case "$choice" in
        1) DETECTION_ENGINE="inside-apache" ;;
        2) DETECTION_ENGINE="log-reader" ;;
        *) die "Scelta motore non valida." ;;
    esac
}

write_runtime_conf() {
    {
        echo "# Reactive Web Firewall runtime selection"
        echo "# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>"
        echo "# SPDX-License-Identifier: AGPL-3.0-or-later"
        printf 'VERSION=%q\n' "7.0"
        printf 'DETECTION_ENGINE=%q\n' "$DETECTION_ENGINE"
        printf 'BACKEND=%q\n' "$FIREWALL_MODE"
    } > "$RWF_RUNTIME_CONF"
    chown root:root "$RWF_RUNTIME_CONF"; chmod 0644 "$RWF_RUNTIME_CONF"
}

default_log_path() {
    case "$RWF_DISTRO_FAMILY" in
        debian|suse) echo /var/log/apache2/other_vhosts_access.log ;;
        rhel) echo /var/log/httpd/access_log ;;
        *) echo /var/log/apache2/other_vhosts_access.log ;;
    esac
}

existing_log_path() {
    local f="$RWF_LOG_READER_CONF" v
    if [[ -r "$f" ]]; then
        v="$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/{sub(/^[^=]*=/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$0); print; exit}' "$f" 2>/dev/null || true)"
        [[ -n "$v" ]] && { echo "$v"; return; }
    fi
    echo "$(default_log_path)"
}

prepare_log_reader_conf() {
    local shipped="$BASE_DIR/log-reader/rwf-log-reader.conf" tmp key
    if [[ -r "$RWF_LOG_READER_CONF" ]]; then
        tmp="$(mktemp /tmp/rwf-log-reader-conf.XXXXXX)"
        cp "$RWF_LOG_READER_CONF" "$tmp"
        python3 - "$tmp" "$shipped" "$LOG_READER_LOG" <<'PYLOGCONF'
from pathlib import Path
import sys,re
old=Path(sys.argv[1]); shipped=Path(sys.argv[2]); log=sys.argv[3]
text=old.read_text()
if re.search(r'(?m)^\s*log_file\s*=', text):
    text=re.sub(r'(?m)^\s*log_file\s*=.*$', f'log_file={log}', text, count=1)
else:
    text=f'log_file={log}\n'+text
existing=set(re.findall(r'(?m)^\s*rule\.([A-Za-z0-9_.-]+)\s*=', text))
missing=[]
for line in shipped.read_text().splitlines():
    m=re.match(r'\s*rule\.([A-Za-z0-9_.-]+)\s*=',line)
    if m and m.group(1) not in existing:
        missing.append(line)
if missing:
    text += '\n\n# Rules added by package upgrade; review if desired.\n' + '\n'.join(missing) + '\n'
old.write_text(text)
PYLOGCONF
        install -o root -g root -m 0644 "$tmp" "$RWF_LOG_READER_CONF"
        rm -f "$tmp"
    else
        sed "s|^log_file=.*$|log_file=$LOG_READER_LOG|" "$shipped" > "$RWF_LOG_READER_CONF"
        # If this is a migration from the original watcher, preserve its policy
        # choices while moving enforcement to the common rwf-helper pipeline.
        if [[ -r /etc/csf/custom-web-ban-immediate.conf ]]; then
            python3 - "$RWF_LOG_READER_CONF" /etc/csf/custom-web-ban-immediate.conf <<'PYLEGACY'
from pathlib import Path
import re,sys
newf=Path(sys.argv[1]); oldf=Path(sys.argv[2])
legacy={}
for raw in oldf.read_text(errors='replace').splitlines():
    line=re.sub(r'#.*$','',raw).strip()
    if not line: continue
    m=re.match(r'^([A-Za-z0-9_]+)\s*(?:=|:)\s*(.*?)\s*$',line)
    if m: legacy[m.group(1).lower()]=m.group(2)
map_rules={
 'git_exploit':['git-repository','git-credentials','gitconfig','gitlab-ci','github-workflow'],
 'env_exploit':['env-secret','vscode-sftp','ds-store','wp-config-secret','aws-credentials','aws-config','rclone-conf','rclone-hidden-conf','rclone-user-conf','web-config','scanner-debug-trigger'],
 'framework_exploit':['phpunit-vendor','phpunit-direct'],
 'xmlrpc':['wordpress-xmlrpc'],
 'wp_batch':['wordpress-batch-v1'],
 'sql_injection':['sqli-union-select','sqli-mysql-error'],
 'known_webshell':['known-webshell-name','known-webshell-wso','known-webshell-hellopress'],
 'phpmyadmin_probe':['phpmyadmin-standard','phpmyadmin-admin'],
 'php_probe':['generic-root-php-context'],
 'wp_login':['wordpress-wp-login-context'],
}
text=newf.read_text()
changed=[]
for oldkey,rules in map_rules.items():
    if oldkey not in legacy: continue
    value=legacy[oldkey]
    for rule in rules:
        pat=rf'(?m)^\s*rule\.{re.escape(rule)}\s*=.*$'
        repl=f'rule.{rule}={value}'
        text,n=re.subn(pat,repl,text,count=1)
        if n: changed.append(f'{rule}={value}')
if changed:
    text += '\n# Migrated policy choices from custom-web-ban-immediate.conf.\n'
    newf.write_text(text)
PYLEGACY
            info "Policy del watcher legacy migrate nella configurazione Log Reader."
        fi
        chown root:root "$RWF_LOG_READER_CONF"; chmod 0644 "$RWF_LOG_READER_CONF"
    fi
}

render_log_reader_service() {
    install -o root -g root -m 0644 "$BASE_DIR/systemd/rwf-log-reader.service.in" "$RWF_LOG_READER_SERVICE"
}

restore_direct_apache_disabled_files() {
    [[ "$RWF_APACHE_STYLE" == direct ]] || return 0
    local p
    for p in "$RWF_LOAD_FILE" "$RWF_CONF_FILE" "$RWF_LOG_CONF_FILE"; do
        [[ -e "$p.rwf-disabled" && ! -e "$p" ]] && mv -f "$p.rwf-disabled" "$p" || true
    done
}

rollback_cutover() {
    local rc=$? p
    set +e
    if (( CUTOVER_DONE )); then
        warn "Installazione non completata: ripristino il motore di rilevazione precedente."
        systemctl disable --now rwf-log-reader.service >/dev/null 2>&1 || true
        rwf_apache_disable >/dev/null 2>&1 || true

        # Restore the detection-engine files captured before the cutover. Files
        # that did not exist before a fresh install are removed again.
        for p in \
            "$RWF_MODULE_FILE" "$RWF_LOAD_FILE" "$RWF_CONF_FILE" "$RWF_LOG_CONF_FILE" \
            "$RWF_ETC/apache-rules.conf" "$RWF_RUNTIME_CONF" \
            "$RWF_LOG_READER_BIN" "$RWF_LOG_RULES_LIB" "$RWF_LOG_READER_CONF" "$RWF_LOG_READER_SERVICE"; do
            if [[ -e "$BACKUP_DIR$p" || -L "$BACKUP_DIR$p" ]]; then
                rm -rf -- "$p"
                mkdir -p "$(dirname "$p")"
                cp -a -- "$BACKUP_DIR$p" "$p"
            else
                rm -rf -- "$p"
            fi
        done
        systemctl daemon-reload >/dev/null 2>&1 || true
        case "$PREVIOUS_ENGINE" in
            inside-apache)
                restore_direct_apache_disabled_files
                rwf_apache_enable >/dev/null 2>&1 || true
                rwf_apache_configtest >/dev/null 2>&1 && rwf_apache_reload >/dev/null 2>&1 || true
                ;;
            log-reader)
                rwf_apache_configtest >/dev/null 2>&1 && rwf_apache_reload >/dev/null 2>&1 || true
                systemctl enable --now rwf-log-reader.service >/dev/null 2>&1 || true
                ;;
            legacy-log-reader)
                rwf_apache_configtest >/dev/null 2>&1 && rwf_apache_reload >/dev/null 2>&1 || true
                systemctl enable --now "$LEGACY_SERVICE" >/dev/null 2>&1 || true
                ;;
            *) rwf_apache_configtest >/dev/null 2>&1 && rwf_apache_reload >/dev/null 2>&1 || true ;;
        esac
    fi
    exit "$rc"
}
trap rollback_cutover ERR

[[ $EUID -eq 0 ]] || die "Eseguire come root."
[[ -f "$BASE_DIR/src/mod_rwf.c" && -f "$BASE_DIR/src/rwf-helper-local.c" ]] || die "Pacchetto sorgente incompleto."
[[ -f "$BASE_DIR/log-reader/rwf-log-reader.pl" && -f "$BASE_DIR/log-reader/RwfLogRules.pm" && -f "$BASE_DIR/log-reader/rwf-log-reader.conf" ]] || die "Motore Log Reader incompleto."
[[ -f "$BASE_DIR/local-firewall/custom-web-fastban" && -f "$BASE_DIR/local-firewall/custom-web-fastban.nft" ]] || die "Componente firewall locale incompleto."
[[ -f "$BASE_DIR/scripts/accesslog-filter.py" && -f "$BASE_DIR/scripts/platform.sh" && -f "$BASE_DIR/scripts/rules-merge.py" ]] || die "Pacchetto script incompleto."
[[ -x "$BASE_DIR/scripts/openwrt-bootstrap.sh" && -x "$BASE_DIR/scripts/rwf-fish" && -x "$BASE_DIR/scripts/rwf-status" ]] || die "Utility RwF incomplete."
[[ -x "$BASE_DIR/openwrt/install-openwrt.sh" && -x "$BASE_DIR/openwrt/core/usr/bin/f2b-banip" && -x "$BASE_DIR/openwrt/core/usr/bin/f2b-banip-wrapper" && -x "$BASE_DIR/openwrt/core/usr/sbin/fw-unban-all" ]] || die "Payload OpenWrt incompleto."

say ""
say "${C_BOLD}Reactive Web Firewall installer ${RWF_VERSION}${C_RESET}"
say "Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>"
say "License: AGPL-3.0-or-later"
say ""

# 1. Platform and engine selection.
info "Rilevamento distribuzione, Apache e installazione RwF esistente"
rwf_detect_platform || die "Distribuzione non riconosciuta. Supportate: Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, openSUSE/SLES."
[[ -n "$RWF_APACHE_CTL" ]] || die "apachectl/apache2ctl non trovato."

# We only need a plausible module directory here so existing-engine detection can
# inspect Apache. APXS becomes mandatory only for Inside Apache.
APXS="$(command -v apxs || command -v apxs2 || command -v /usr/sbin/apxs || command -v /usr/sbin/apxs2 || true)"
if [[ -n "$APXS" ]]; then APACHE_MODULE_DIR="$($APXS -q LIBEXECDIR)"; else APACHE_MODULE_DIR="$(rwf_default_module_dir)"; fi
rwf_apache_paths "$APACHE_MODULE_DIR"
PREVIOUS_ENGINE="$(detect_existing_engine)"
info "Motore attualmente rilevato: $PREVIOUS_ENGINE"
choose_detection_engine
ok "Motore selezionato: $DETECTION_ENGINE"

# 2. Engine-specific packages.
mapfile -t required_packages < <(rwf_required_packages "$DETECTION_ENGINE")
missing_packages=()
for pkg in "${required_packages[@]}"; do rwf_package_is_installed "$pkg" || missing_packages+=("$pkg"); done
if ((${#missing_packages[@]})); then
    warn "Pacchetti mancanti: ${missing_packages[*]}"
    ask_yes_no "Installarli ora con ${RWF_PACKAGE_MANAGER}?" y || die "Dipendenze mancanti."
    rwf_install_packages "${missing_packages[@]}"
fi
rwf_detect_platform || die "Apache non rilevabile dopo l'installazione delle dipendenze."
[[ -n "$RWF_APACHE_CTL" ]] || die "apachectl/apache2ctl non trovato."
APXS="$(command -v apxs || command -v apxs2 || command -v /usr/sbin/apxs || command -v /usr/sbin/apxs2 || true)"
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    [[ -n "$APXS" ]] || die "Inside Apache richiede apxs/apxs2 e gli header di sviluppo Apache."
    APACHE_MODULE_DIR="$($APXS -q LIBEXECDIR)"
else
    if [[ -n "$APXS" ]]; then APACHE_MODULE_DIR="$($APXS -q LIBEXECDIR)"; else APACHE_MODULE_DIR="$(rwf_default_module_dir)"; fi
fi
[[ -d "$APACHE_MODULE_DIR" ]] || die "Directory moduli Apache non valida: $APACHE_MODULE_DIR"
rwf_apache_paths "$APACHE_MODULE_DIR"
getent group "$RWF_APACHE_GROUP" >/dev/null || die "Gruppo Apache non trovato: $RWF_APACHE_GROUP"
SS_BIN="${RWF_SS:-$(command -v ss || true)}"
for cmd in gcc curl python3 perl systemctl nft flock logger tail; do command -v "$cmd" >/dev/null 2>&1 || die "Comando richiesto non trovato: $cmd"; done
[[ -x "$SS_BIN" ]] || die "ss non eseguibile: $SS_BIN"
APACHE_VERSION="$($RWF_APACHE_CTL -v 2>/dev/null | awk -F': ' '/Server version/ {print $2}')"
ok "Distribuzione: ${RWF_DISTRO_ID:-unknown} / $RWF_DISTRO_FAMILY"
ok "Apache: ${APACHE_VERSION:-rilevato} / $RWF_APACHE_SERVICE"
[[ "$DETECTION_ENGINE" == inside-apache ]] && ok "apxs: $APXS"

# Recover any access-log filter remnants before using Apache include dumps.
if ! rwf_apache_configtest >/dev/null 2>&1; then
    warn "La configurazione Apache è già sintatticamente invalida prima dell'upgrade."
    if grep -Rqs --include='*.conf' 'env=!RWF_SUPPRESS_ACCESSLOG' "$RWF_APACHE_ETC" 2>/dev/null; then
        info "Rilevati token access-log RwF: tentativo di autoripristino"
        mkdir -p "$BACKUP_DIR/accesslog-preflight-repair"
        "$BASE_DIR/scripts/accesslog-filter.py" --mode sanitize --apache-root "$RWF_APACHE_ETC" --backup-dir "$BACKUP_DIR/accesslog-preflight-repair"
        rwf_apache_configtest || die "Apache resta sintatticamente invalido dopo la rimozione dei token RwF."
    else
        rwf_apache_configtest || true
        die "Apache è già sintatticamente invalido per una causa non riconducibile a RwF."
    fi
fi

# 3. Legacy watcher is a previous Log Reader implementation. Do not stop yet.
if legacy_is_present; then
    LEGACY_PRESENT=1
    systemctl is-active --quiet "$LEGACY_SERVICE" && LEGACY_ACTIVE_BEFORE=1 || true
    systemctl is-enabled --quiet "$LEGACY_SERVICE" && LEGACY_ENABLED_BEFORE=1 || true
    warn "Rilevato watcher Perl legacy; verrà spento soltanto durante il cutover."
fi

# 4. Common whitelist and engine-specific settings.
install -d -o root -g root -m 0755 "$RWF_ETC"
if [[ -e "$RWF_ETC/whitelist.conf" ]]; then
    ask_yes_no "Preservare la whitelist attualmente installata?" y && PRESERVE_WHITELIST=1 || PRESERVE_WHITELIST=0
else
    PRESERVE_WHITELIST=0
fi

if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    if [[ -e "$RWF_ETC/apache-rules.conf" ]]; then
        if ask_yes_no "Aggiornare le regole mantenendo quelle personalizzate?" y; then RULES_ACTION=merge
        elif ask_yes_no "Sostituire completamente apache-rules.conf?" n; then RULES_ACTION=replace
        else RULES_ACTION=preserve; fi
    else RULES_ACTION=replace; fi
    drop_default="$(existing_option_default RwfDropConnection "$RWF_CONF_FILE" y)"
    ask_yes_no "Abilitare drop/reset della connessione dopo match/cache-hit?" "$drop_default" && DROP_CONNECTION=1 || DROP_CONNECTION=0
    log_default="$(existing_option_default RwfSuppressBlockedAccessLog "$RWF_CONF_FILE" y)"
    ask_yes_no "Non scrivere nell'access log le richieste successive bloccate dalla cache RwF?" "$log_default" && SUPPRESS_ACCESSLOG=1 || SUPPRESS_ACCESSLOG=0
else
    LOG_READER_LOG="$(prompt_value "Access log Apache da seguire" "$(existing_log_path)")"
    [[ "$LOG_READER_LOG" == /* && -r "$LOG_READER_LOG" ]] || die "Access log non leggibile: $LOG_READER_LOG"
    info "Verifica formato del log selezionato"
    format_rc=0
    perl "$BASE_DIR/log-reader/rwf-log-reader.pl" --config "$BASE_DIR/log-reader/rwf-log-reader.conf" --check-format "$LOG_READER_LOG" || format_rc=$?
    case "$format_rc" in
        0) ok "Formato access log compatibile." ;;
        4) warn "Il log è vuoto: il formato non può essere verificato ancora."; ask_yes_no "Proseguire e validarlo quando arriveranno le prime richieste?" y || die "Installazione interrotta." ;;
        *) die "Formato access log non riconosciuto. Sono supportati RwF historical e Apache vhost_combined." ;;
    esac
fi

# 5. Common enforcement backend.
backend_default="$(existing_backend_default)"
if ask_yes_no "Usare anche un firewall remoto OpenWrt come backend di frontiera?" "$backend_default"; then
    FIREWALL_MODE=openwrt
    configure_openwrt_backend || die "Configurazione OpenWrt interrotta."
else
    FIREWALL_MODE=local-only
fi
[[ "$FIREWALL_MODE" == local-only ]] && ok "Backend: LOCAL-ONLY, policy applicate a nftables locale." || ok "Backend: OPENWRT ($FIREWALL_TARGET:$SSH_PORT), bridge locale $FALLBACK_TTL."
if [[ -z "$TEST_URL" && -t 0 ]]; then read -r -p "URL reale per smoke test finale (Invio per saltare): " TEST_URL; fi

# 6. Build common helper, and Apache module only when selected.
BUILD_DIR="$(mktemp -d /tmp/rwf-build.XXXXXX)"; trap 'rm -rf "$BUILD_DIR"' EXIT
info "Compilazione privileged helper"
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic "$BASE_DIR/src/rwf-helper-local.c" -o "$BUILD_DIR/rwf-helper"
[[ -x "$BUILD_DIR/rwf-helper" ]] || die "Compilazione rwf-helper fallita."
perl -c "$BASE_DIR/log-reader/RwfLogRules.pm" >/dev/null
perl -c "$BASE_DIR/log-reader/rwf-log-reader.pl" >/dev/null
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    info "Compilazione mod_rwf contro l'Apache installato"
    cp "$BASE_DIR/src/mod_rwf.c" "$BUILD_DIR/mod_rwf.c"
    (cd "$BUILD_DIR" && "$APXS" -c mod_rwf.c)
    [[ -f "$BUILD_DIR/mod_rwf.la" ]] || die "Compilazione mod_rwf non ha prodotto mod_rwf.la."
fi

# 7. Backup all mutable/common detection paths.
info "Backup dei file eventualmente già presenti in $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
for p in \
    "$RWF_MODULE_FILE" "$RWF_LOAD_FILE" "$RWF_CONF_FILE" "$RWF_LOG_CONF_FILE" \
    "$RWF_ETC/apache-rules.conf" "$RWF_ETC/whitelist.conf" "$RWF_BACKEND_CONF" "$RWF_RUNTIME_CONF" \
    "$RWF_LOG_READER_BIN" "$RWF_LOG_RULES_LIB" "$RWF_LOG_READER_CONF" "$RWF_LOG_READER_SERVICE" \
    "$RWF_HELPER_BIN" "$RWF_ACCESSLOG_BIN" "$RWF_PLATFORM_LIB" "$RWF_FISH_BIN" "$RWF_STATUS_BIN" "$RWF_HELPER_SERVICE" \
    "$FASTBAN" "$FASTBAN_RULESET" "$FASTBAN_SERVICE"; do backup_path "$p"; done

# 8. Install common runtime.
install -o root -g root -m 0755 "$BUILD_DIR/rwf-helper" "$RWF_HELPER_BIN"
install -o root -g root -m 0755 "$BASE_DIR/scripts/accesslog-filter.py" "$RWF_ACCESSLOG_BIN"
install -o root -g root -m 0755 "$BASE_DIR/scripts/rwf-fish" "$RWF_FISH_BIN"
install -o root -g root -m 0755 "$BASE_DIR/scripts/rwf-status" "$RWF_STATUS_BIN"
install -d -o root -g root -m 0755 "$(dirname "$RWF_PLATFORM_LIB")" "$(dirname "$RWF_LOG_RULES_LIB")"
install -o root -g root -m 0644 "$BASE_DIR/scripts/platform.sh" "$RWF_PLATFORM_LIB"
install -o root -g root -m 0644 "$BASE_DIR/log-reader/RwfLogRules.pm" "$RWF_LOG_RULES_LIB"
install -o root -g root -m 0755 "$BASE_DIR/log-reader/rwf-log-reader.pl" "$RWF_LOG_READER_BIN"
render_log_reader_service
if [[ "$DETECTION_ENGINE" == log-reader ]]; then prepare_log_reader_conf; elif [[ ! -e "$RWF_LOG_READER_CONF" ]]; then install -o root -g root -m 0644 "$BASE_DIR/log-reader/rwf-log-reader.conf" "$RWF_LOG_READER_CONF"; fi

if (( PRESERVE_WHITELIST )); then
    [[ -e "$RWF_ETC/whitelist.conf" ]] || install -o root -g root -m 0644 "$BASE_DIR/config/whitelist.conf" "$RWF_ETC/whitelist.conf"
else
    install -o root -g root -m 0644 "$BASE_DIR/config/whitelist.conf" "$RWF_ETC/whitelist.conf"
fi
install -d -o root -g root -m 0755 "$(dirname "$FASTBAN_RULESET")" "$FASTBAN_STATE_DIR"
install -o root -g root -m 0755 "$BASE_DIR/local-firewall/custom-web-fastban" "$FASTBAN"
install -o root -g root -m 0644 "$BASE_DIR/local-firewall/custom-web-fastban.nft" "$FASTBAN_RULESET"
install -o root -g root -m 0644 "$BASE_DIR/systemd/custom-web-fastban.service" "$FASTBAN_SERVICE"
write_backend_conf
if [[ "$FIREWALL_MODE" == openwrt ]]; then render_helper_service "$BASE_DIR/systemd/rwf-helper-openwrt.service.in"; else render_helper_service "$BASE_DIR/systemd/rwf-helper-local-only.service.in"; fi

# 9. Prepare target detection engine while previous one keeps serving traffic.
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    info "Installazione DSO Apache tramite apxs"
    (cd "$BUILD_DIR" && "$APXS" -i mod_rwf.la)
    [[ -f "$RWF_MODULE_FILE" ]] || die "mod_rwf.so non presente dopo apxs -i."
    case "$RULES_ACTION" in
        merge)
            rules_tmp="$(mktemp /tmp/rwf-rules-merge.XXXXXX)"
            python3 "$BASE_DIR/scripts/rules-merge.py" --existing "$RWF_ETC/apache-rules.conf" --shipped "$BASE_DIR/config/apache-rules.conf" --output "$rules_tmp"
            install -o root -g root -m 0644 "$rules_tmp" "$RWF_ETC/apache-rules.conf"; rm -f "$rules_tmp" ;;
        preserve) [[ -e "$RWF_ETC/apache-rules.conf" ]] || install -o root -g root -m 0644 "$BASE_DIR/config/apache-rules.conf" "$RWF_ETC/apache-rules.conf" ;;
        replace) install -o root -g root -m 0644 "$BASE_DIR/config/apache-rules.conf" "$RWF_ETC/apache-rules.conf" ;;
    esac
    mkdir -p "$(dirname "$RWF_LOAD_FILE")" "$(dirname "$RWF_CONF_FILE")" "$(dirname "$RWF_LOG_CONF_FILE")"
    cat > "$RWF_LOAD_FILE" <<EOFLOAD
LoadModule rwf_module $RWF_MODULE_FILE
EOFLOAD
    chown root:root "$RWF_LOAD_FILE"; chmod 0644 "$RWF_LOAD_FILE"
    write_rwf_conf
    install -o root -g root -m 0644 "$BASE_DIR/apache/reactive-web-firewall-log.conf" "$RWF_LOG_CONF_FILE"
    if (( SUPPRESS_ACCESSLOG )); then
        "$RWF_ACCESSLOG_BIN" --apachectl "$RWF_APACHE_CTL" --mode enable --backup-dir "$BACKUP_DIR/accesslog-originals" || access_rc=$?
        access_rc="${access_rc:-0}"; [[ "$access_rc" == 0 || "$access_rc" == 4 ]] || die "Filtro access log non configurabile (rc=$access_rc)."
    else
        "$RWF_ACCESSLOG_BIN" --apachectl "$RWF_APACHE_CTL" --mode disable --backup-dir "$BACKUP_DIR/accesslog-disable-originals" || access_rc=$?
        access_rc="${access_rc:-0}"; [[ "$access_rc" == 0 || "$access_rc" == 3 || "$access_rc" == 4 ]] || die "Filtro access log non rimovibile (rc=$access_rc)."
    fi
    rwf_apache_enable
    rwf_apache_configtest || die "Apache configtest fallito preparando Inside Apache."
else
    # Log Reader must see every relevant request; remove mod_rwf-only cache-hit suppression.
    "$RWF_ACCESSLOG_BIN" --apachectl "$RWF_APACHE_CTL" --mode disable --backup-dir "$BACKUP_DIR/accesslog-log-reader" >/dev/null 2>&1 || true
    "$BASE_DIR/scripts/selftest-log-reader.sh"
    rwf_apache_configtest || die "Apache configtest fallito preparando Log Reader."
fi

# 10. Start common enforcement before the cutover.
systemctl daemon-reload
systemctl enable custom-web-fastban.service >/dev/null
systemctl restart custom-web-fastban.service
systemctl is-active --quiet custom-web-fastban.service || die "custom-web-fastban.service non attivo."
systemctl enable rwf-helper.service >/dev/null
systemctl restart rwf-helper.service
wait_for_helper_ready 100 || die "rwf-helper non ha creato il socket entro 10 secondi."
ok "Enforcement comune attivo."

# 11. Controlled cutover. During an engine switch we prefer a very short safe
# overlap over an unprotected gap. The common helper marker suppresses duplicate
# Log Reader handling of requests already caught by mod_rwf. Final state is still
# strictly mutually exclusive.
CUTOVER_DONE=1
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    info "Cutover -> Inside Apache"
    rwf_apache_enable
    rwf_apache_configtest
    rwf_apache_reload
    rwf_apache_module_loaded || die "rwf_module non caricato dopo il cutover."
    # Only after the new early detector is live do we stop the previous reader.
    systemctl disable --now rwf-log-reader.service >/dev/null 2>&1 || true
    (( LEGACY_PRESENT )) && systemctl disable --now "$LEGACY_SERVICE" >/dev/null 2>&1 || true
    systemctl is-active --quiet rwf-log-reader.service && die "Conflitto: Log Reader ancora attivo." || true
else
    info "Cutover -> Log Reader"
    if [[ "$PREVIOUS_ENGINE" == legacy-log-reader ]]; then
        # The original watcher enforces bans itself; avoid overlapping two
        # post-response readers that use different enforcement implementations.
        systemctl disable --now "$LEGACY_SERVICE" >/dev/null 2>&1 || true
    fi
    systemctl enable rwf-log-reader.service >/dev/null
    systemctl restart rwf-log-reader.service
    systemctl is-active --quiet rwf-log-reader.service || { systemctl status rwf-log-reader.service --no-pager -l || true; die "rwf-log-reader.service non attivo."; }
    # If mod_rwf was the previous engine, the new reader is now live before the
    # Apache reload removes the module, avoiding an unprotected interval.
    rwf_apache_disable
    rwf_apache_configtest
    rwf_apache_reload
    rwf_apache_module_loaded && die "Conflitto: mod_rwf risulta ancora caricato." || true
    (( LEGACY_PRESENT )) && systemctl disable --now "$LEGACY_SERVICE" >/dev/null 2>&1 || true
fi
write_runtime_conf
wait_for_helper_ready 50 || die "Helper/socket non disponibili dopo il cutover."

# 12. Engine-specific and common self-tests.
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    info "Self-test Inside Apache"
    RWF_SELFTEST_MODE="$FIREWALL_MODE" RWF_SELFTEST_FASTBAN="$FASTBAN" RWF_SELFTEST_SS="$SS_BIN" \
    RWF_SELFTEST_DROP="$DROP_CONNECTION" RWF_SELFTEST_SUPPRESS_LOG="$SUPPRESS_ACCESSLOG" "$BASE_DIR/scripts/selftest.sh" --http
else
    info "Self-test Log Reader parser/regole"
    "$BASE_DIR/scripts/selftest-log-reader.sh"
fi
if ask_yes_no "Eseguire anche il test sintetico reale del backend firewall su un IP TEST-NET per 30 secondi?" y; then
    RWF_SELFTEST_MODE="$FIREWALL_MODE" RWF_SELFTEST_FASTBAN="$FASTBAN" RWF_SELFTEST_SS="$SS_BIN" "$BASE_DIR/scripts/selftest.sh" --firewall
fi
if [[ -n "$TEST_URL" ]]; then
    http_code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 10 "$TEST_URL" || true)"
    [[ -n "$http_code" && "$http_code" != 000 ]] || die "Smoke test non raggiunge $TEST_URL."
    ok "$TEST_URL risponde HTTP $http_code"
fi

# 13. Final invariant: exactly one detection engine.
info "Verifica finale"
rwf_apache_configtest
module_active=0; log_active=0
rwf_apache_module_loaded && module_active=1 || true
systemctl is-active --quiet rwf-log-reader.service && log_active=1 || true
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then (( module_active == 1 && log_active == 0 )) || die "Invariante motori violata."; else (( module_active == 0 && log_active == 1 )) || die "Invariante motori violata."; fi
systemctl is-active --quiet custom-web-fastban.service || die "custom-web-fastban non attivo."
systemctl is-active --quiet rwf-helper.service || die "rwf-helper non attivo."
[[ -S /run/reactive-web-firewall/helper.sock ]] || die "helper.sock assente."
(( LEGACY_PRESENT )) && systemctl is-active --quiet "$LEGACY_SERVICE" && die "Watcher legacy ancora attivo." || true
"$RWF_STATUS_BIN" || die "rwf-status segnala un conflitto."
ok "Motore, helper e backend coerenti."

CUTOVER_DONE=0
trap - ERR
rm -rf "$BUILD_DIR"; trap - EXIT

say ""
say "${C_GREEN}${C_BOLD}Reactive Web Firewall V7.0 installato e operativo.${C_RESET}"
say ""
say "Distribuzione:      ${RWF_DISTRO_ID:-unknown} / $RWF_DISTRO_FAMILY"
say "Detection engine:   $DETECTION_ENGINE"
say "Backend firewall:   $FIREWALL_MODE"
say "Runtime config:     $RWF_RUNTIME_CONF"
say "Whitelist:          $RWF_ETC/whitelist.conf"
say "Helper:             $RWF_HELPER_BIN"
say "Stato:              $RWF_STATUS_BIN"
say "Raccolta audit:     $RWF_FISH_BIN"
if [[ "$DETECTION_ENGINE" == inside-apache ]]; then
    say "Modulo Apache:      $RWF_MODULE_FILE"
    say "Regole Apache:      $RWF_ETC/apache-rules.conf"
    say "Drop connessione:   $([[ $DROP_CONNECTION -eq 1 ]] && echo On || echo Off)"
    say "No-log cache-hit:   $([[ $SUPPRESS_ACCESSLOG -eq 1 ]] && echo On || echo Off)"
else
    say "Log reader:         $RWF_LOG_READER_BIN"
    say "Log seguito:        $LOG_READER_LOG"
    say "Regole/config:      $RWF_LOG_READER_CONF"
fi
if [[ "$FIREWALL_MODE" == openwrt ]]; then
    say "OpenWrt:            $FIREWALL_TARGET:$SSH_PORT"
    [[ -n "$OPENWRT_API_VERSION" ]] && say "OpenWrt API:        $OPENWRT_API_VERSION"
    [[ -n "$OPENWRT_ALLOWED_SOURCE" ]] && say "Proxy visto come:    $OPENWRT_ALLOWED_SOURCE"
    say "Fallback locale:    $FALLBACK_TTL"
else
    say "Policy locali:      durata/permanenza derivata da ogni regola"
fi
say "Backup install:     $BACKUP_DIR"
