# Risoluzione problemi

## Il watcher non parte

```bash
perl -c /usr/local/sbin/reactive-web-ban.pl
reactive-web-ban.pl --show-config
journalctl -u reactive-web-ban.service -n 100 --no-pager
```

## Apache non produce righe

```bash
a2query -c reactive-web-firewall
apache2ctl -t -D DUMP_RUN_CFG
tail -F /var/log/apache2/reactive_web_access.log
```

Controllare `mod_remoteip` se `%h` mostra sempre il proxy intermedio.

## Il canale OpenWrt fallisce

```bash
source /etc/reactive-web-firewall/connection.conf
ssh -p "$FIREWALL_PORT" -i /etc/reactive-web-firewall/keys/firewall_ed25519   -o IdentitiesOnly=yes -o UserKnownHostsFile=/etc/reactive-web-firewall/keys/known_hosts   "$FIREWALL_TARGET" check
```

Sul firewall:

```sh
logread -e reactive-fw
/usr/local/sbin/reactive-fw-ban check
nft list table inet reactive_web_firewall
```

## `ss -K` restituisce zero ma non chiude

Verificare prima che il filtro trovi davvero il socket. Con Apache dual-stack non forzare `-4` o `-6`:

```bash
ss -Hntpe state connected dst CLIENT_IP sport = :443
ss -K -H -n -t state connected dst CLIENT_IP sport = :443
```

## Unban apparentemente inefficace

Usare il comando coordinato:

```bash
reactive-web-ban.pl --unban IP
```

Il fast-ban locale normalmente è già stato rimosso e possiede comunque un timeout di sicurezza.
