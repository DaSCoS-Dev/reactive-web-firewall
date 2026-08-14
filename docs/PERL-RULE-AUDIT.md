<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Legacy Perl → Reactive Web Firewall rule audit

Audit date: 2026-08-14

This document records the migration status of the high-confidence immediate-ban families used by the legacy `custom-web-ban-immediate.pl` watcher. Since V7, RwF has two mutually-exclusive detection engines: **Inside Apache**, which runs before the final response exists, and **Log Reader**, which can safely retain response-aware rules. Enforcement is shared by both engines through `rwf-helper`.

## Audit result

| Legacy family | Legacy policy | V7 status | V7 implementation / reason |
|---|---:|---|---|
| `git_exploit` | permanent | Covered | `.git` plus repository metadata path rules. |
| `env_exploit` | permanent | Covered and expanded | `.env` variants, `web.config`, rclone, AWS credentials, `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`, scanner fingerprint. |
| `framework_exploit` | permanent | Covered | PHPUnit direct/vendor probes. |
| `xmlrpc` | 3d | Available, disabled by default | `/xmlrpc.php` can be legitimate on WordPress; generic package leaves it commented. |
| `wp_batch` | 3d | Covered in V6 | New `RwfRuleTargetRegex` covers both `/wp-json/batch/v1` and `?rest_route=/batch/v1`. |
| `sql_injection` | 2w | Conservative high-confidence subset | Target rules for `UNION ... SELECT` and MySQL `extractvalue()/updatexml()` probes. V6 does not claim to be a general SQL WAF. |
| `known_webshell` | permanent | Covered | Legacy known shell names, `/.wp/wso.php`, HelloPress PHP probes. |
| `phpmyadmin_probe` | permanent | Available, disabled by default | Standard phpMyAdmin paths may be legitimate on another installation. |
| `php_probe` | 1h | Log Reader only | Preserved as `generic-root-php-context`; remains intentionally absent from the early Inside Apache rule set. |
| `wp_login` | 4h | Log Reader only | Preserved as `wordpress-wp-login-context`; remains intentionally absent from the early Inside Apache rule set. |

## Why `RwfRuleTargetRegex` exists

V5 path rules inspect Apache `r->uri`. That correctly excludes the query string, but it meant this legacy signature could not be reproduced:

```text
POST /?rest_route=/batch/v1
```

The Inside Apache engine adds:

```text
RwfRuleTargetRegex <name> <regex> <policy>
```

It evaluates a detection-only target built from `path + ?query`. Printable percent-encoding is decoded for two passes, so `%2F` and `%252F` are both visible as `/` to the detector. Apache's request URI is never rewritten by RwF.

Existing `RwfRuleRegex` remains path-only, preserving V5 semantics.

## Secret-file parity fixes

The legacy watcher also matched values such as:

```text
.env.local
.env-prod
.vscode/sftp.json
.DS_Store
wp-config.php
```

V5's generic `.env` regex did not cover all suffix variants. the Inside Apache `env-secret` migration closes that gap and adds the remaining explicit secret paths.

## SQL injection scope

The legacy immediate watcher delegated SQLi classification to the shared CSF regex code. Production evidence confirms at least these high-confidence signatures:

- `UNION [ALL|DISTINCT] SELECT`
- MySQL error-based probes using `extractvalue(...)`
- MySQL error-based probes using `updatexml(...)`

Inside Apache carries those as target rules with a 2-week policy. It intentionally does not enable generic keyword-only SQL detection, time-based function names, or broad quote/parenthesis heuristics because those are much more application-dependent.

## New production-field signatures

During live validation on the production reverse proxy, additional high-confidence scanner/backdoor paths were observed and are shipped in V6 independently of the legacy audit:

- `/wp-plain.php`
- `/wp-content/themes/seotheme/db.php`
- `/wp-content/plugins/apikey/apikey.php`
- `/wp-content/plugins/apikey/apikey.php.suspected`
- `/(ALFA_DATA/)?alfacgiapi/perl.alfa`
- `/plugins/content/apismtp/apismtp.php`
- `/plugins/content/apismtp/apismtp.php.suspected`

The first five are treated as permanent high-confidence probes; `apismtp` field signatures use 2 weeks.

## Generic-package safety decisions

The default package intentionally leaves these commented:

```text
phpMyAdmin standard aliases
WordPress xmlrpc.php
```

An administrator can enable them when local application knowledge makes them unambiguously malicious.

The Log Reader engine now preserves the two response-context families that can be represented safely from access-log data:

```text
generic root-level *.php response-context probes
wp-login.php response-context probes
```

Burst/rate-based enumeration families remain outside the generic V7 core until a dedicated rate-state design is introduced. This is deliberate: V7 does not turn a rate heuristic into a single-request ban merely for parity.
