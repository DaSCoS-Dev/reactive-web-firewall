# Reactive Web Firewall 0.2.1

Reactive Web Firewall collega un reverse proxy Apache a un firewall OpenWrt e reagisce a firme web ad alta confidenza in pochi millisecondi.

Il principio è semplice:

```text
richiesta sicuramente malevola terminata
        ↓
riga disponibile nel GlobalLog Apache
        ↓
fast-ban nftables locale sul server
        ↓
ss -K sulle connessioni già accettate
        ↓
ban definitivo e persistente su OpenWrt
        ↓
secondo sweep e rimozione del fast-ban locale
```

Il server chiude immediatamente il proprio cancello. OpenWrt resta l'autorità definitiva dei ban. La regola locale ha un timeout di sicurezza e viene rimossa appena il firewall conferma l'applicazione.

## Cosa rileva immediatamente

Il watcher interviene soltanto su firme considerate sufficientemente forti:

- repository `.git`;
- file `.env`, credenziali AWS, `.vscode/sftp.json`, `.DS_Store`, `wp-config.php`;
- probe PHPUnit;
- WordPress REST `batch/v1`;
- `xmlrpc.php`;
- webshell PHP note;
- SQL injection con firme strutturate;
- probe PHP generici con condizioni restrittive;
- probe a `wp-login.php` con condizioni restrittive.

Durata e disabilitazione delle singole famiglie sono configurabili in `/etc/reactive-web-firewall/rules.conf` e vengono rilette senza riavviare il servizio.

## Condizioni tecniche

### Server

Configurazione prevista e controllata dall'installer:

- Debian 12 o successivo, oppure Ubuntu 22.04/24.04 LTS o successivo;
- Apache HTTP Server 2.4.19 o superiore;
- systemd;
- nftables;
- `iproute2` con `ss -K` e kernel con `CONFIG_INET_DIAG_DESTROY`;
- client OpenSSH;
- accesso root per l'installazione;
- il server deve vedere nel log l'IP reale del client.

Se Apache è dietro un altro proxy o load balancer, configurare correttamente `mod_remoteip` prima di attivare il watcher. Bloccare l'indirizzo del proxy intermedio sarebbe assai poco poetico e molto distruttivo.

### Firewall

- OpenWrt con accesso shell root;
- firewall nftables/fw4;
- Dropbear oppure OpenSSH server;
- comando `nft`;
- comando `conntrack`;
- il traffico web verso il server deve attraversare questo firewall;
- il server deve poter raggiungere il servizio SSH del firewall;
- package manager `apk` oppure `opkg`.

banIP è opzionale. Con `--backend auto` viene usato soltanto se i set `inet banIP blocklist.v4` e `blocklist.v6` sono realmente attivi. In caso contrario viene usata la tabella nftables autonoma inclusa nel progetto.

La release è stata riallineata a una produzione con OpenWrt 25.12.2, kernel 6.12, `apk`, banIP 1.8.5 e firewall x86/64. Non richiede però quei numeri esatti.

## Installazione automatica

Estrarre l'archivio sul server:

```bash
unzip reactive-web-firewall-0.2.1.zip
cd reactive-web-firewall-0.2.1
```

Controllare soltanto i prerequisiti server:

```bash
sudo ./install.sh --check-only
```

Installazione completa, compreso OpenWrt:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --install-firewall
```

Con porta SSH differente:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --firewall-port 222 \
    --install-firewall
```

Backend esplicito:

```bash
sudo ./install.sh \
    --firewall-host 192.0.2.1 \
    --backend banip \
    --install-firewall
```

L'installer:

1. controlla o installa i pacchetti server;
2. valida sintassi Perl, Bash e shell OpenWrt;
3. installa il `GlobalLog` Apache dedicato;
4. installa fast-ban, watcher, servizi e packet ring;
5. genera una chiave Ed25519 dedicata;
6. mostra l'impronta della host key OpenWrt;
7. copia il bundle firewall;
8. installa una chiave con comando forzato, senza shell, PTY o forwarding;
9. verifica il canale ristretto;
10. avvia il watcher solo quando OpenWrt risponde correttamente.

## Installazione OpenWrt manuale

Per copiare i file senza eseguire automaticamente l'installer remoto:

```bash
sudo ./install.sh --firewall-host 192.0.2.1
```

Lo script stampa il comando da eseguire sul firewall. Dopo averlo eseguito, tornare sul server e completare:

```bash
sudo ./finish-server.sh
```

## Chiave SSH e permessi

La chiave privata viene conservata sul server:

```text
/etc/reactive-web-firewall/keys/firewall_ed25519
```

Sul firewall viene aggiunta una riga a:

```text
/etc/dropbear/authorized_keys
```

oppure, con OpenSSH:

```text
/root/.ssh/authorized_keys
```

La chiave può eseguire esclusivamente `/usr/local/sbin/reactive-fw-dispatch`. Il dispatcher:

- verifica l'IP sorgente tramite `SSH_CONNECTION`;
- accetta solo una grammatica ristretta;
- rifiuta metacaratteri e comandi arbitrari;
- non concede shell, port forwarding, agent forwarding, X11 o PTY.

## Apache

Il progetto installa:

```text
/etc/apache2/conf-available/reactive-web-firewall.conf
```

Il file definisce un formato indipendente:

```apache
LogFormat "%h (%v:%p) ... apache_end_us=%{end:usec}t" reactive_web_combined
GlobalLog ${APACHE_LOG_DIR}/reactive_web_access.log reactive_web_combined
```

Non copia né modifica VirtualHost applicativi. In particolare, configurazioni specifiche di siti raccolte durante lo sviluppo, non fanno parte della distribuzione.

## Gestione

Stato e diagnostica:

```bash
sudo reactive-web-diagnose
sudo systemctl status reactive-web-ban.service
sudo journalctl -t reactive-web-ban -o short-precise
```

Configurazione effettiva:

```bash
sudo reactive-web-ban.pl --show-config
```

Stato locale dei ban noti al watcher:

```bash
sudo reactive-web-ban.pl --list-state
```

Unban completo, firewall e stato locale:

```bash
sudo reactive-web-ban.pl --unban 203.0.113.77
```

Testare una riga senza applicare alcun ban:

```bash
sudo reactive-web-ban.pl --test-line \
'203.0.113.77 (example.org:443) - - [05/Aug/2026:15:32:57.575 +0200] "GET /.git/config HTTP/1.1" 403 100 "-" "scanner" apache_end_us=1785936777614027'
```

## Report forense

Con packet ring attivo:

```bash
sudo reactive-web-ban-report 203.0.113.77
```

Il report unisce:

- log Apache e rotazioni compresse;
- eventi del watcher con timestamp al microsecondo;
- pacchetti TCP 80/443 presenti nel ring PCAP.

I PCAP possono contenere metadati di traffico e una porzione iniziale dei pacchetti. Valutare privacy, conservazione e accessi prima di abilitarli su sistemi soggetti a requisiti specifici.

## Fast-ban locale

La tabella del server è:

```text
inet reactive_web_fastban
```

e contiene set IPv4/IPv6 con timeout. Le regole interessano soltanto TCP 80 e 443 e hanno priorità `-250`, prima delle normali accettazioni `established,related`.

Nel funzionamento normale l'elemento locale vive poche centinaia di millisecondi. Se OpenWrt non conferma il ban, resta fino alla scadenza automatica configurata, per impostazione predefinita cinque minuti.

## Backend OpenWrt

### banIP

L'ordine di `sync-add` è deliberato:

1. aggiunta diretta al set nftables attivo;
2. verifica con `nft get element`;
3. eliminazione conntrack;
4. persistenza in `/etc/banip/banip.blocklist`;
5. nessun reload di banIP.

Questo evita la finestra introdotta da un reload asincrono.

### Standalone

Il progetto installa `inet reactive_web_firewall` con catene `input` e `forward` a priorità `-200`, set permanenti e set temporanei con timeout. La blocklist persistente si trova in:

```text
/etc/reactive-web-firewall/blocklist
```

## Allowlist

Aggiungere esclusivamente IP esatti a:

```text
/etc/reactive-web-firewall/allowlist
```

Il watcher rilegge il file automaticamente.

## Limiti

- La prima richiesta malevola deve arrivare ad Apache e terminare affinché venga scritta la riga di log.
- Non è un WAF e non sostituisce patch, hardening, autenticazione o segmentazione.
- Una firma troppo ampia può produrre falsi positivi. Le regole immediate devono restare conservatrici.
- `ss -K` va provato sul kernel reale. Il DROP locale continua comunque a impedire nuove comunicazioni web.
- La protezione remota dipende dalla raggiungibilità SSH del firewall. In caso di guasto resta il fast-ban locale fino al timeout.

## Rimozione

Server:

```bash
sudo ./uninstall-server.sh
```

Firewall:

```sh
sh /tmp/reactive-web-firewall-install/uninstall-firewall.sh
```

Le procedure preservano configurazioni, chiavi, blocklist e catture come backup di sicurezza.

## Autore, copyright e licenza

Creatore e titolare originario del copyright: **Daniele Stefano Continenza**  
Email: **daniele@dascos.info**

Copyright © 2026 Daniele Stefano Continenza.

Il progetto è distribuito secondo la **GNU Affero General Public License
versione 3 o, a scelta, una versione successiva** (`AGPL-3.0-or-later`).
Chi modifica il software e lo rende disponibile agli utenti attraverso una
rete deve rispettare anche gli obblighi previsti dalla sezione 13 della AGPL.

Vedere [LICENSE](LICENSE), [NOTICE](NOTICE) e [AUTHORS.md](AUTHORS.md).
