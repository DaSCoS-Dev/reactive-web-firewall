<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Reactive Web Firewall V7.0

**English** | [Italiano](../it/RELEASE-NOTES-V7.md)

Release date: 2026-08-14

V7 unifies the two historical RwF development lines into one product and one
installer.

## Two detection engines

The wizard allows one mutually exclusive choice between:

- **Inside Apache**, based on `mod_rwf`;
- **Log Reader**, based on the new self-contained `rwf-log-reader`.

Both engines generate the same event protocol for `rwf-helper`.

## One enforcement pipeline

Both engines can use:

- standalone local firewall enforcement;
- local firewall + OpenWrt.

OpenWrt bootstrap, SSH keys, the forced-command API, whitelist handling, LFD
markers, nftables, and socket termination are not duplicated between engines.

## New Log Reader

The old `custom-web-ban-immediate.pl` combined detection and enforcement. V7
keeps its value as a post-response sensor while removing privileged operations
from the new engine.

The new Log Reader:

- does not depend on CSF or `regex.custom.pm`;
- supports the historical RwF log format and Apache `vhost_combined`;
- preserves shared high-confidence rule families;
- preserves response-context rules for `wp-login` and root-level PHP probes;
- can migrate known policies from `custom-web-ban-immediate.conf`;
- sends events to the helper's shared Unix socket.

## Installer and migration

Changing `Inside Apache <-> Log Reader` is treated as a controlled cutover. The
new engine is prepared before the previous engine is disabled, and mutual
exclusion is verified at the end.

`rwf-status` was added to display the active engine, backend, module/service
state, helper/firewall state, rules, whitelist, and any engine conflict.

`rwf-fish` is now engine-aware.

## Performance audit

The published N=10 baseline remains unchanged and refers to the Inside Apache
path validated in production. Later events collected only as confirmation are
not retroactively added to the sample or its averages.
