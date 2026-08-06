# Configurazione e regole modulari

## File centrale lato server

Tutte le impostazioni operative sono raccolte in:

```text
/etc/reactive-web-firewall/reactive-web-firewall.conf
```

Qui si configurano firewall OpenWrt, SSH, percorsi, log, fast-ban locale, porte,
socket kill, packet ring e durata/abilitazione di ogni famiglia di regole.
Una policy impostata a `off` disabilita la regola senza modificare il codice.

Dopo ogni modifica:

```bash
sudo reactive-web-validate
sudo reactive-web-apply
```

Le sole modifiche alle policy e ai file `rules.d/*.pm` vengono ricaricate anche
automaticamente. Se la nuova versione contiene un errore, il watcher conserva
le ultime regole valide e registra `runtime-reload-failed`.

## Moduli delle regole

I moduli sono in:

```text
/etc/reactive-web-firewall/rules.d/
```

Ogni file restituisce un hash Perl con `name`, `description`, `priority`,
`default_policy` e `detect`. I numeri di priorità più bassi vengono valutati
prima. La funzione `detect` riceve il contesto normalizzato della richiesta e
deve restituire una breve firma oppure `undef`.

Validazione del singolo file:

```bash
perl -c /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
```

Validazione dell'intero sistema:

```bash
sudo reactive-web-validate
sudo reactive-web-ban.pl --list-rules
```

Test di una riga Apache senza applicare ban:

```bash
sudo reactive-web-ban.pl --test-line 'RIGA APACHE COMPLETA'
```

I moduli Perl vengono eseguiti dal watcher come root: devono essere modificati
solo da amministratori fidati e restare di proprietà di root.

## Configurazione OpenWrt

Il firewall mantiene un unico file separato, perché risiede su un altro host:

```text
/etc/reactive-web-firewall/firewall.conf
```

## Flusso di modifica sicuro

Per le impostazioni operative:

```bash
sudoedit /etc/reactive-web-firewall/reactive-web-firewall.conf
sudo reactive-web-validate
sudo reactive-web-apply
```

Per una singola famiglia di firme:

```bash
sudoedit /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
perl -c /etc/reactive-web-firewall/rules.d/070-known-webshells.pm
sudo reactive-web-validate
```

Non è necessario riavviare il watcher dopo una modifica valida a policy o
moduli: il caricamento è automatico. `reactive-web-apply` resta consigliato
quando cambiano porte, percorsi, SSH, logging o packet ring.

Ogni modulo contiene direttamente i comandi di validazione e il nome della
policy centrale che lo abilita o ne determina la durata.

## Perché due file di configurazione

Il server e OpenWrt sono host distinti. Il server ha un solo file centrale per
tutte le proprie impostazioni; il firewall ha un solo file centrale separato.
Non esistono copie permanenti delle stesse policy su entrambi gli host: OpenWrt
resta l'autorità dei ban, mentre il proxy mantiene soltanto il ponte locale
transitorio.
