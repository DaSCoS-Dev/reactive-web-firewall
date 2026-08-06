#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

RWF_CONFIG="${RWF_CONFIG:-/etc/reactive-web-firewall/reactive-web-firewall.conf}"

rwf_trim() {
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

rwf_cfg() {
    local key="$1" default="${2-}" line value
    if [[ -r "$RWF_CONFIG" ]]; then
        line="$(awk -v wanted="$key" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                pos=index($0,"=");
                if (!pos) next;
                k=substr($0,1,pos-1);
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", k);
                if (tolower(k)==tolower(wanted)) value=substr($0,pos+1);
            }
            END { if (value!="") print value }
        ' "$RWF_CONFIG")"
        if [[ -n "$line" ]]; then
            value="$(rwf_trim "$line")"
            printf '%s\n' "$value"
            return 0
        fi
    fi
    printf '%s\n' "$default"
}

rwf_bool() {
    case "${1,,}" in
        1|yes|true|on|enabled) return 0 ;;
        0|no|false|off|disabled) return 1 ;;
        *) echo "Invalid boolean: $1" >&2; return 2 ;;
    esac
}

rwf_duration_seconds() {
    local raw="${1,,}" n unit mult
    if [[ "$raw" =~ ^([1-9][0-9]*)([smhdw]?)$ ]]; then
        n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
        case "$unit" in s|'') mult=1;; m) mult=60;; h) mult=3600;; d) mult=86400;; w) mult=604800;; esac
        printf '%s\n' "$((n * mult))"
        return 0
    fi
    echo "Invalid temporary duration: $1" >&2
    return 1
}

rwf_ports_csv_to_nft() {
    local raw="$1" p out='' seen=' '
    raw="${raw//,/ }"
    for p in $raw; do
        [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )) || { echo "Invalid port: $p" >&2; return 1; }
        [[ "$seen" == *" $p "* ]] && continue
        seen+="$p "
        [[ -z "$out" ]] || out+=", "
        out+="$p"
    done
    [[ -n "$out" ]] || { echo 'Port list is empty' >&2; return 1; }
    printf '%s\n' "$out"
}
