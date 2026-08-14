<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V6

**English** | [Italiano](../it/RELEASE-NOTES-V6.md)

Date: 2026-08-13

## Detection engine

- Adds `RwfRuleTargetRegex`, matching a detection-only normalized `path + query` target.
- Printable percent encodings are decoded for two passes for detection, covering `%2F` and `%252F` evasions without modifying Apache's URI.
- Existing Exact/Prefix/Regex behavior remains path-only and backward compatible.
- HTTP installer self-test explicitly validates TargetRegex and double-percent decoding.

## Rule audit

- Audits the legacy immediate Perl watcher family-by-family.
- Closes missing `.env` suffix coverage and adds `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`.
- Adds complete WordPress batch-v1 path/query coverage.
- Adds conservative high-confidence SQLi target signatures.
- Adds known high-confidence webshell/probe signatures observed in production.
- Leaves phpMyAdmin aliases and WordPress XML-RPC disabled by default because they can be legitimate.
- Does not convert response-aware `wp_login` and generic `php_probe` rules into broad early blockers.
- See `PERL-RULE-AUDIT.md`.

## Upgrade-safe rule merge

- Existing installations can merge active rules while preserving local/custom rules.
- Missing shipped rules are appended by name.
- Only exact recognized legacy forms of `env-secret` and `wordpress-batch-v1` are migrated semantically.
- Existing policy is retained on those migrations.
- Whitelist preservation is a separate choice.

## Local firewall fast path

- Removes Python validation from the common add/delete path.
- Temporary adds attempt one direct `nft add element` first.
- Expensive inspection/table recovery occurs only after failure.
- Global file locking is reserved for persistent permanent-state changes.
- Permanent bans remain persisted and restored on service reload.

This change removed a temporary development regression in the local-firewall path.
The public performance audit excludes samples collected during that regression;
see `PRODUCTION-REFERENCE.md` for the current valid baseline.

## Production reference

Adds `PRODUCTION-REFERENCE.md` and `scripts/collect-system-profile.sh` for sanitized production measurements and repeatable hardware profiling.
