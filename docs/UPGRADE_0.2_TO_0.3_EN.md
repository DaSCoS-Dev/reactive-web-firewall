# Upgrading from the 0.2 series to 0.3

Version 0.3 separates the stable engine from settings and detection signatures.

Back up the current installation first:

```bash
sudo cp -a /etc/reactive-web-firewall \
    "/etc/reactive-web-firewall.backup.$(date +%Y%m%d-%H%M%S)"
sudo cp -a /usr/local/sbin/reactive-web-ban.pl \
    "/usr/local/sbin/reactive-web-ban.pl.backup.$(date +%Y%m%d-%H%M%S)"
```

Run the 0.3 installer with the existing firewall details:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --no-copy-firewall
```

The installer reads the old `rules.conf`, migrates recognised policies and
durations into `reactive-web-firewall.conf`, and preserves the original file.
Default modules are installed only when a file with the same name does not
already exist, so local rule modules are not overwritten.

After upgrading:

```bash
sudo reactive-web-validate
sudo reactive-web-apply
sudo reactive-web-diagnose
```
