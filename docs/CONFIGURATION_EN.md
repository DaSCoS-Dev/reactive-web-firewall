# Configuration and modular rules

## Central server file

All server-side settings live in:

```text
/etc/reactive-web-firewall/reactive-web-firewall.conf
```

It controls the OpenWrt target, SSH, paths, logging, local fast-ban, ports,
socket destruction, packet ring, and each rule policy. Set a policy to `off`
to disable it without editing Perl code.

After changes run:

```bash
sudo reactive-web-validate
sudo reactive-web-apply
```

Policy and `rules.d/*.pm` edits are also hot-reloaded. An invalid edit does not
replace the last valid in-memory ruleset; the watcher logs
`runtime-reload-failed` and continues operating.

## Rule modules

Modules live in:

```text
/etc/reactive-web-firewall/rules.d/
```

Every file returns a Perl hash containing `name`, `description`, `priority`,
`default_policy`, and `detect`. Lower priorities run first. `detect` receives a
normalized request context and returns a short signature or `undef`.

Validate one module:

```bash
perl -c /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
```

Validate the full installation:

```bash
sudo reactive-web-validate
sudo reactive-web-ban.pl --list-rules
```

Rule modules execute as root and must only be editable by trusted administrators.

## OpenWrt configuration

The firewall has its own single file because it runs on a different host:

```text
/etc/reactive-web-firewall/firewall.conf
```

## Safe editing workflow

For operational settings:

```bash
sudoedit /etc/reactive-web-firewall/reactive-web-firewall.conf
sudo reactive-web-validate
sudo reactive-web-apply
```

For one detection family:

```bash
sudoedit /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
perl -c /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
sudo reactive-web-validate
```

Valid policy and rule-module edits are loaded automatically. Run
`reactive-web-apply` when changing ports, paths, SSH, logging or packet-ring
settings. Every module documents its central policy key and validation commands.
