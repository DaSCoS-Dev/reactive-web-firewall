# Aggiornamento dalla serie 0.2 alla 0.3

La versione 0.3 separa il motore stabile dalle impostazioni e dalle firme.

Prima dell'aggiornamento:

```bash
sudo cp -a /etc/reactive-web-firewall \
    "/etc/reactive-web-firewall.backup.$(date +%Y%m%d-%H%M%S)"
sudo cp -a /usr/local/sbin/reactive-web-ban.pl \
    "/usr/local/sbin/reactive-web-ban.pl.backup.$(date +%Y%m%d-%H%M%S)"
```

Eseguire poi l'installer 0.3 con gli stessi dati del firewall:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --no-copy-firewall
```

L'installer legge il vecchio `rules.conf`, migra policy e durate riconosciute nel
nuovo `reactive-web-firewall.conf` e conserva il file originale. I moduli
predefiniti vengono installati solo quando il file omonimo non esiste, così le
regole personalizzate non vengono sovrascritte.

Dopo l'aggiornamento:

```bash
sudo reactive-web-validate
sudo reactive-web-apply
sudo reactive-web-diagnose
```

I file principali diventano:

```text
/etc/reactive-web-firewall/reactive-web-firewall.conf
/etc/reactive-web-firewall/rules.d/*.pm
/etc/reactive-web-firewall/firewall.conf          # sul firewall OpenWrt
```
