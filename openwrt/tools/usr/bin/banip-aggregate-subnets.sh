#!/bin/sh
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

# ============================================================
# Configurazione
# ============================================================

BLOCKLIST_FILE="${BLOCKLIST_FILE:-/etc/banip/banip.blocklist}"
RELOAD_CMD="${RELOAD_CMD:-/etc/init.d/banip reload}"
DEFAULT_THRESHOLD="${1:-${DEFAULT_THRESHOLD:-5}}"

# Se 1 mostra anche l'elenco degli IP singoli per ogni gruppo trovato.
SHOW_IP_LISTS="${SHOW_IP_LISTS:-1}"

# ============================================================
# Funzioni generiche
# ============================================================

print_blue() {
    printf '\033[1;34m%s\033[0m\n' "$1"
}

print_yellow() {
    printf '\033[1;33m%s\033[0m\n' "$1"
}

print_red() {
    printf '\033[1;31m%s\033[0m\n' "$1"
}

print_green() {
    printf '\033[1;32m%s\033[0m\n' "$1"
}

die() {
    echo "ERRORE: $*" >&2
    exit 1
}

is_positive_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" -gt 0 ] ;;
    esac
}

normalize_yes_no() {
    ans="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"

    case "$ans" in
        s|si|sí|sì|y|yes) echo "yes" ;;
        n|no) echo "no" ;;
        q|quit|exit|esci) echo "quit" ;;
        *) echo "" ;;
    esac
}

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

require_commands() {
    command -v awk >/dev/null 2>&1 || die "awk non trovato"
    command -v sort >/dev/null 2>&1 || die "sort non trovato"
    command -v tr >/dev/null 2>&1 || die "tr non trovato"
    command -v date >/dev/null 2>&1 || die "date non trovato"
    command -v mktemp >/dev/null 2>&1 || die "mktemp non trovato"
    command -v cp >/dev/null 2>&1 || die "cp non trovato"

    [ -r "$BLOCKLIST_FILE" ] || die "file non leggibile: $BLOCKLIST_FILE"
    [ -w "$BLOCKLIST_FILE" ] || die "file non scrivibile: $BLOCKLIST_FILE"
}

ask_threshold() {
    if ! is_positive_number "$DEFAULT_THRESHOLD"; then
        DEFAULT_THRESHOLD=5
    fi

    echo "Soglia di aggregazione default: $DEFAULT_THRESHOLD IP distinti nella stessa /24"
    printf 'Premi INVIO per usare il default, oppure inserisci un altro numero: '
    read -r input_threshold

    if is_positive_number "${input_threshold:-}"; then
        THRESHOLD="$input_threshold"
    else
        THRESHOLD="$DEFAULT_THRESHOLD"
    fi

    echo ""
    print_blue "Soglia usata: $THRESHOLD"
    echo ""
}

count_file_lines() {
    if [ ! -s "$1" ]; then
        echo 0
        return
    fi

    awk 'END { print NR + 0 }' "$1"
}

# ============================================================
# Estrazione e calcolo gruppi
# ============================================================

extract_data() {
    awk \
        -v singles_file="$SINGLES_RAW_FILE" \
        -v existing24_file="$EXISTING_24_RAW_FILE" '
        function valid_octet(o) {
            return (o ~ /^[0-9]+$/ && o >= 0 && o <= 255)
        }

        function valid_ipv4(ip, a, n) {
            n = split(ip, a, ".")
            return (n == 4 && valid_octet(a[1]) && valid_octet(a[2]) && valid_octet(a[3]) && valid_octet(a[4]))
        }

        function prefix24(ip, a) {
            split(ip, a, ".")
            return a[1] "." a[2] "." a[3]
        }

        {
            line = $0
            sub(/^[[:space:]]+/, "", line)

            if (line == "" || line ~ /^#/) {
                next
            }

            token = line
            sub(/[[:space:]#].*$/, "", token)

            if (token ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                if (valid_ipv4(token)) {
                    print prefix24(token) "\t" token >> singles_file
                }
                next
            }

            if (token ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/24$/) {
                split(token, cidr, "/")
                ip = cidr[1]

                if (valid_ipv4(ip)) {
                    print prefix24(ip) >> existing24_file
                }
                next
            }
        }
    ' "$BLOCKLIST_FILE"

    sort -u "$SINGLES_RAW_FILE" > "$SINGLES_FILE"
    sort -u "$EXISTING_24_RAW_FILE" > "$EXISTING_24_FILE"
}

build_groups() {
    awk -v threshold="$THRESHOLD" '
        BEGIN {
            current = ""
            count = 0
            ips = ""
        }

        function flush_group() {
            if (current != "" && count >= threshold) {
                print current "\t" count "\t" ips
            }
        }

        {
            prefix = $1
            ip = $2

            if (current == "") {
                current = prefix
            }

            if (prefix != current) {
                flush_group()
                current = prefix
                count = 0
                ips = ""
            }

            count++
            if (ips == "") {
                ips = ip
            } else {
                ips = ips " " ip
            }
        }

        END {
            flush_group()
        }
    ' "$SINGLES_FILE" | sort > "$GROUPS_FILE"

    awk -F '\t' '{ print $1 }' "$GROUPS_FILE" > "$GROUP_PREFIXES_FILE"

    awk '
        NR == FNR {
            existing[$1] = 1
            next
        }
        ($1 in existing) {
            print $0
        }
    ' "$EXISTING_24_FILE" "$GROUPS_FILE" > "$GROUPS_EXISTING_FILE"

    awk '
        NR == FNR {
            existing[$1] = 1
            next
        }
        !($1 in existing) {
            print $0
        }
    ' "$EXISTING_24_FILE" "$GROUPS_FILE" > "$GROUPS_NEW_FILE"
}

count_removed_singles() {
    if [ ! -s "$GROUPS_FILE" ]; then
        echo 0
        return
    fi

    awk -F '\t' '{ total += $2 } END { print total + 0 }' "$GROUPS_FILE"
}

# ============================================================
# Output e applicazione modifiche
# ============================================================

show_summary() {
    groups_count="$(count_file_lines "$GROUPS_FILE")"
    new_groups_count="$(count_file_lines "$GROUPS_NEW_FILE")"
    existing_groups_count="$(count_file_lines "$GROUPS_EXISTING_FILE")"
    removed_singles="$(count_removed_singles)"

    echo "============================================================"
    echo "Analisi aggregazione banIP"
    echo "File: $BLOCKLIST_FILE"
    echo "Soglia: $THRESHOLD IP distinti nella stessa /24"
    echo "============================================================"
    echo ""

    if [ "$groups_count" -eq 0 ]; then
        print_green "Nessun gruppo da aggregare trovato."
        echo ""
        return
    fi

    print_yellow "Gruppi candidati trovati: $groups_count"
    echo "IP singoli che verrebbero rimossi perché coperti da /24: $removed_singles"
    echo "Nuove subnet /24 da aggiungere: $new_groups_count"
    echo "Subnet /24 già presenti, con IP singoli ridondanti: $existing_groups_count"
    echo ""

    awk \
        -F '\t' \
        -v existing_file="$EXISTING_24_FILE" \
        -v show_ips="$SHOW_IP_LISTS" '
        BEGIN {
            while ((getline p < existing_file) > 0) {
                existing[p] = 1
            }
            close(existing_file)
        }

        {
            prefix = $1
            count = $2
            ips = $3
            subnet = prefix ".0/24"

            if (existing[prefix]) {
                action = "subnet già presente, rimuovo gli IP singoli coperti"
            } else {
                action = "aggiungo subnet " subnet " e rimuovo gli IP singoli"
            }

            printf "- %s: %d IP singoli -> %s\n", subnet, count, action

            if (show_ips == "1") {
                printf "  IP: %s\n", ips
            }
        }
    ' "$GROUPS_FILE"

    echo ""
}

build_new_blocklist() {
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    awk \
        -v groups_file="$GROUP_PREFIXES_FILE" '
        BEGIN {
            while ((getline p < groups_file) > 0) {
                target[p] = 1
            }
            close(groups_file)
        }

        function valid_octet(o) {
            return (o ~ /^[0-9]+$/ && o >= 0 && o <= 255)
        }

        function valid_ipv4(ip, a, n) {
            n = split(ip, a, ".")
            return (n == 4 && valid_octet(a[1]) && valid_octet(a[2]) && valid_octet(a[3]) && valid_octet(a[4]))
        }

        function prefix24(ip, a) {
            split(ip, a, ".")
            return a[1] "." a[2] "." a[3]
        }

        {
            original = $0
            line = $0
            sub(/^[[:space:]]+/, "", line)

            token = line
            sub(/[[:space:]#].*$/, "", token)

            if (token ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && valid_ipv4(token)) {
                prefix = prefix24(token)
                if (prefix in target) {
                    next
                }
            }

            print original
        }
    ' "$BLOCKLIST_FILE" > "$NEW_BLOCKLIST_FILE"

    if [ -s "$GROUPS_NEW_FILE" ]; then
        {
            echo ""
            echo "# --- aggregazioni automatiche ${timestamp} ---"
            awk -F '\t' -v timestamp="$timestamp" '{
                printf "%s.0/24 # aggregato da %d ip singoli - banip-aggregate %s\n", $1, $2, timestamp
            }' "$GROUPS_NEW_FILE"
        } >> "$NEW_BLOCKLIST_FILE"
    fi
}

apply_changes() {
    backup_file="${BLOCKLIST_FILE}.bak.$(date '+%Y%m%d-%H%M%S')"

    cp -p "$BLOCKLIST_FILE" "$backup_file" || die "backup fallito: $backup_file"
    cp "$NEW_BLOCKLIST_FILE" "$BLOCKLIST_FILE" || die "riscrittura fallita: $BLOCKLIST_FILE"

    print_green "File riscritto correttamente."
    echo "Backup: $backup_file"
    echo ""

    print_blue "Eseguo reload banIP: $RELOAD_CMD"
    if sh -c "$RELOAD_CMD"; then
        print_green "Reload banIP completato."
    else
        print_red "ATTENZIONE: reload banIP fallito. Il file è stato riscritto, backup disponibile in: $backup_file"
        return 1
    fi
}

confirm_and_apply() {
    groups_count="$(count_file_lines "$GROUPS_FILE")"

    if [ "$groups_count" -eq 0 ]; then
        return
    fi

    build_new_blocklist

    echo "Vuoi procedere alla riscrittura del file e al reload di banIP?"
    printf '[s] sì, [n] no, [q] esci: '
    read -r answer

    normalized="$(normalize_yes_no "$answer")"

    case "$normalized" in
        yes)
            apply_changes
            ;;
        no|quit|*)
            print_yellow "Nessuna modifica applicata."
            ;;
    esac
}

# ============================================================
# Avvio
# ============================================================

require_commands
ask_threshold

TMP_DIR="$(mktemp -d /tmp/banip-aggregate.XXXXXX)" || die "impossibile creare directory temporanea"

SINGLES_RAW_FILE="$TMP_DIR/singles.raw.tsv"
SINGLES_FILE="$TMP_DIR/singles.tsv"
EXISTING_24_RAW_FILE="$TMP_DIR/existing24.raw.txt"
EXISTING_24_FILE="$TMP_DIR/existing24.txt"
GROUPS_FILE="$TMP_DIR/groups.tsv"
GROUP_PREFIXES_FILE="$TMP_DIR/group-prefixes.txt"
GROUPS_NEW_FILE="$TMP_DIR/groups-new.tsv"
GROUPS_EXISTING_FILE="$TMP_DIR/groups-existing.tsv"
NEW_BLOCKLIST_FILE="$TMP_DIR/banip.blocklist.new"

: > "$SINGLES_RAW_FILE"
: > "$EXISTING_24_RAW_FILE"
: > "$GROUPS_FILE"
: > "$GROUP_PREFIXES_FILE"
: > "$GROUPS_NEW_FILE"
: > "$GROUPS_EXISTING_FILE"

extract_data
build_groups
show_summary
confirm_and_apply

