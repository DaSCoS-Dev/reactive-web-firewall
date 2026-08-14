#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Eseguire come root." >&2; exit 1; }
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM_LIB="/usr/local/lib/reactive-web-firewall/platform.sh"
[[ -r "$PLATFORM_LIB" ]] || PLATFORM_LIB="$BASE_DIR/scripts/platform.sh"
# shellcheck disable=SC1090
source "$PLATFORM_LIB"
rwf_detect_platform || { echo "Piattaforma Apache non riconosciuta." >&2; exit 1; }

APXS="$(command -v apxs || command -v apxs2 || true)"
if [[ -n "$APXS" ]]; then MODULE_DIR="$($APXS -q LIBEXECDIR)"; else MODULE_DIR="$(rwf_default_module_dir)"; fi
rwf_apache_paths "$MODULE_DIR"

ask_yes_no() {
    local prompt="$1" answer
    if [[ ! -t 0 ]]; then return 1; fi
    read -r -p "$prompt [s/N] " answer
    answer="${answer,,}"
    [[ "$answer" == "s" || "$answer" == "si" || "$answer" == "sì" || "$answer" == "y" || "$answer" == "yes" ]]
}

echo "Disabilito entrambi i possibili motori RwF e l'helper comune..."
systemctl disable --now rwf-log-reader.service 2>/dev/null || true
systemctl disable --now rwf-helper.service 2>/dev/null || true

if [[ -x /usr/local/sbin/rwf-accesslog-filter ]]; then
    /usr/local/sbin/rwf-accesslog-filter --apachectl "$RWF_APACHE_CTL" --mode disable >/dev/null 2>&1 || true
fi
rwf_apache_disable
rwf_apache_configtest
rwf_apache_reload

if ask_yes_no "Rimuovere binari, servizi e configurazioni dei motori/helper RwF?"; then
    rm -f \
        "$RWF_MODULE_FILE" \
        /usr/local/sbin/rwf-helper \
        /usr/local/sbin/rwf-log-reader \
        /usr/local/sbin/rwf-accesslog-filter \
        /usr/local/sbin/rwf-fish \
        /usr/local/sbin/rwf-status \
        /usr/local/lib/reactive-web-firewall/RwfLogRules.pm \
        /etc/systemd/system/rwf-helper.service \
        /etc/systemd/system/rwf-log-reader.service \
        "$RWF_LOAD_FILE" "$RWF_CONF_FILE" "$RWF_LOG_CONF_FILE" \
        "$RWF_LOAD_FILE.rwf-disabled" "$RWF_CONF_FILE.rwf-disabled" "$RWF_LOG_CONF_FILE.rwf-disabled"

    if ask_yes_no "Rimuovere anche /etc/reactive-web-firewall (regole, whitelist, runtime e backend)?"; then
        rm -rf /etc/reactive-web-firewall
    fi
    rm -rf /usr/local/lib/reactive-web-firewall
fi

permanent_file="/var/lib/reactive-web-firewall/local-permanent.list"
permanent_count=0
[[ -r "$permanent_file" ]] && permanent_count="$(awk 'NF {n++} END {print n+0}' "$permanent_file")"

echo ""
echo "Il firewall locale è comune ai due motori e può essere mantenuto separatamente."
echo "Ban permanenti locali persistenti registrati: $permanent_count"
if ask_yes_no "Rimuovere anche custom-web-fastban e la tabella nftables locale?"; then
    if (( permanent_count > 0 )); then
        echo "ATTENZIONE: la rimozione della tabella renderà immediatamente inefficaci questi ban locali."
        ask_yes_no "Confermare comunque?" || {
            echo "Firewall locale conservato."
            systemctl daemon-reload
            exit 0
        }
    fi
    systemctl disable --now custom-web-fastban.service 2>/dev/null || true
    command -v nft >/dev/null 2>&1 && nft delete table inet custom_web_fastban >/dev/null 2>&1 || true
    rm -f /usr/local/sbin/custom-web-fastban /etc/nftables.d/custom-web-fastban.nft /etc/systemd/system/custom-web-fastban.service
    if ask_yes_no "Eliminare anche lo stato persistente dei ban permanenti locali?"; then
        rm -rf /var/lib/reactive-web-firewall
    fi
else
    echo "Firewall locale e relativi ban conservati."
fi

systemctl daemon-reload
echo "Reactive Web Firewall disabilitato/rimosso secondo le scelte effettuate."
