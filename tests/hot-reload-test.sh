#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
PID=''
cleanup() {
    [[ -z "$PID" ]] || kill "$PID" >/dev/null 2>&1 || true
    [[ -z "$PID" ]] || wait "$PID" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/rules" "$TMP/active" "$TMP/keys"
cp "$BASE/server/etc/reactive-web-firewall/rules.d/"*.pm "$TMP/rules/"
cp "$BASE/server/etc/reactive-web-firewall/allowlist.example" "$TMP/allowlist"
: > "$TMP/access.log"
: > "$TMP/keys/firewall_ed25519"
: > "$TMP/keys/known_hosts"

sed \
  -e "s|@@FIREWALL_HOST@@|192.0.2.1|" \
  -e "s|@@FIREWALL_PORT@@|22|" \
  -e "s|@@FIREWALL_USER@@|root|" \
  -e "s|^apache_log_file *=.*|apache_log_file = $TMP/access.log|" \
  -e "s|^rules_directory *=.*|rules_directory = $TMP/rules|" \
  -e "s|^allowlist_file *=.*|allowlist_file = $TMP/allowlist|" \
  -e "s|^state_file *=.*|state_file = $TMP/state.tsv|" \
  -e "s|^active_directory *=.*|active_directory = $TMP/active|" \
  -e "s|^ssh_key *=.*|ssh_key = $TMP/keys/firewall_ed25519|" \
  -e "s|^known_hosts *=.*|known_hosts = $TMP/keys/known_hosts|" \
  -e 's|^local_fastban_enabled *=.*|local_fastban_enabled = off|' \
  -e 's|^local_socket_kill *=.*|local_socket_kill = off|' \
  "$BASE/server/etc/reactive-web-firewall/reactive-web-firewall.conf.example" > "$TMP/config.conf"

watcher=(perl "$BASE/server/usr/local/sbin/reactive-web-ban.pl"
    --core "$BASE/server/usr/local/lib/reactive-web-firewall/core.pm"
    --config "$TMP/config.conf" --dry-run)

"${watcher[@]}" >"$TMP/stdout" 2>"$TMP/stderr" &
PID=$!

wait_for() {
    local pattern="$1" expected="${2:-1}" i count
    for i in $(seq 1 100); do
        count="$(grep -c -- "$pattern" "$TMP/stderr" 2>/dev/null || true)"
        if (( count >= expected )); then return 0; fi
        sleep 0.05
    done
    echo "Timeout waiting for '$pattern' count $expected" >&2
    cat "$TMP/stderr" >&2 || true
    return 1
}

wait_for 'start build=' 1
line='203.0.113.77 (example.org:443) - - [05/Aug/2026:15:32:57.575 +0200] "GET /.git/config HTTP/1.1" 403 100 "-" "scanner" apache_end_us=1785936777614027'
printf '%s\n' "$line" >> "$TMP/access.log"
wait_for 'match ip=203.0.113.77 rule=git_exploit' 1

# Introduce a syntax error. The running process must keep the previous rules.
printf '\nthis is not valid perl !!!\n' >> "$TMP/rules/030-git-repository.pm"
printf '%s\n' "$line" >> "$TMP/access.log"
wait_for 'runtime-reload-failed' 1
wait_for 'match ip=203.0.113.77 rule=git_exploit' 2

# Restore a valid but fingerprint-distinct module and verify the reload.
cp "$BASE/server/etc/reactive-web-firewall/rules.d/030-git-repository.pm" "$TMP/rules/030-git-repository.pm"
printf '\n# hot reload test marker\n' >> "$TMP/rules/030-git-repository.pm"
printf '%s\n' "$line" >> "$TMP/access.log"
wait_for 'runtime-reloaded' 2
wait_for 'match ip=203.0.113.77 rule=git_exploit' 3

failures="$(grep -c -- 'runtime-reload-failed' "$TMP/stderr" || true)"
[[ "$failures" -eq 1 ]] || { echo "Expected one reload failure, got $failures" >&2; exit 1; }

echo 'Safe hot-reload test passed.'
