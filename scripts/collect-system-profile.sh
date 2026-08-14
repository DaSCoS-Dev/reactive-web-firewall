#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
set -Eeuo pipefail

# Sanitized technical profile for RwF performance comparisons.
# Intentionally omits machine/boot IDs, MACs, IP addresses, filesystem shares
# and disk serial numbers.

echo '===== SYSTEM ====='
grep -E '^(PRETTY_NAME|NAME|VERSION_ID)=' /etc/os-release 2>/dev/null || true
uname -rmo 2>/dev/null || true
echo

echo '===== MACHINE ====='
if command -v dmidecode >/dev/null 2>&1; then
    printf 'Manufacturer: '; dmidecode -s system-manufacturer 2>/dev/null || true
    printf 'Product: '; dmidecode -s system-product-name 2>/dev/null || true
    printf 'Version: '; dmidecode -s system-version 2>/dev/null || true
fi
echo

echo '===== CPU ====='
lscpu 2>/dev/null | grep -E '^(Architecture|CPU\(s\)|On-line CPU|Model name|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|CPU max MHz|CPU min MHz|L1d cache|L1i cache|L2 cache|L3 cache):' || true
echo

echo '===== MEMORY ====='
free -h 2>/dev/null || true
if command -v dmidecode >/dev/null 2>&1; then
    dmidecode -t memory 2>/dev/null | grep -E '^[[:space:]]*(Size|Type|Speed|Configured Memory Speed|Manufacturer):' || true
fi
echo

echo '===== BLOCK DEVICES ====='
lsblk -e7 -o NAME,TYPE,SIZE,MODEL,ROTA,TRAN,FSTYPE,MOUNTPOINTS 2>/dev/null || true
echo

echo '===== RAID ====='
cat /proc/mdstat 2>/dev/null || true
echo

echo '===== NETWORK HARDWARE ====='
lspci -nnk 2>/dev/null | grep -A4 -Ei 'Ethernet controller|Network controller' || true
echo
for i in /sys/class/net/*; do
    iface="$(basename "$i")"
    [[ "$iface" == lo ]] && continue
    echo "--- $iface ---"
    if [[ -r "$i/speed" ]]; then
        speed="$(cat "$i/speed" 2>/dev/null || true)"
        [[ -n "$speed" ]] && echo "Nominal speed: ${speed} Mb/s"
    fi
    if command -v ethtool >/dev/null 2>&1; then
        ethtool "$iface" 2>/dev/null | grep -E 'Speed:|Duplex:|Auto-negotiation:|Link detected:' || true
    fi
done
echo

echo '===== APACHE ====='
apachectl -v 2>/dev/null || httpd -v 2>/dev/null || true
apachectl -V 2>/dev/null | grep -E 'Server MPM|SERVER_CONFIG_FILE' || true
echo

echo '===== RWF ====='
apachectl -M 2>/dev/null | grep rwf || true
systemctl show rwf-helper.service -p ActiveState -p SubState -p MemoryCurrent -p CPUUsageNSec --no-pager 2>/dev/null || true
