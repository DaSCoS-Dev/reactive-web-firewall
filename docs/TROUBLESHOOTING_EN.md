# Troubleshooting

Use `reactive-web-diagnose` first. Check watcher syntax and journal, confirm that `/var/log/apache2/reactive_web_access.log` receives the real client address, and test the restricted SSH channel with the values shown by `reactive-web-ban.pl --show-config` and stored in `/etc/reactive-web-firewall/reactive-web-firewall.conf`.

For dual-stack Apache sockets, do not force `-4` or `-6` when using `ss -K`:

```bash
ss -Hntpe state connected dst CLIENT_IP sport = :443
ss -K -H -n -t state connected dst CLIENT_IP sport = :443
```

Use `reactive-web-ban.pl --unban IP` for a coordinated remote and local state removal.
