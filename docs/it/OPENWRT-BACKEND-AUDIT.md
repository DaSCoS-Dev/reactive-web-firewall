<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Audit del backend OpenWrt

[English](../en/OPENWRT-BACKEND-AUDIT.md) | **Italiano**

Questo documento registra l'audit delle dipendenze usato per trasformare il lato
OpenWrt di Reactive Web Firewall in un componente distribuibile, invece che in
un prerequisito esterno.

## Mappa delle dipendenze runtime

```text
Apache proxy / rwf-helper
        │
        │ chiave SSH runtime, forced command
        ▼
/usr/bin/f2b-banip-wrapper
        │
        ├─ temp-add / temp-del
        ├─ sync-add / sync-del
        └─ unban-all
              │
              ├─ /usr/bin/f2b-banip
              │    ├─ nft table inet banIP
              │    ├─ blocklist.v4 / blocklist.v6
              │    ├─ /etc/banip/banip.blocklist
              │    └─ pulizia conntrack
              │
              └─ /usr/sbin/fw-unban-all
```

## Classificazione

| Componente | Classificazione | Note |
|---|---|---|
| `/usr/bin/f2b-banip` | CORE | motore globale per ban temporanei/permanenti |
| `/usr/bin/f2b-banip-wrapper` | CORE | API SSH ristretta / forced command |
| `/usr/sbin/fw-unban-all` | CORE/ADMIN | rollback completo/unban manuale; IPv4/IPv6 |
| `/usr/sbin/check-fw-ban` | TOOL | diagnostica dello stato di un IP |
| `/usr/bin/banip-aggregate-subnets.sh` | TOOL | manutenzione/aggregazione blocklist |
| `/usr/sbin/f2b-portban` | NON RICHIESTO | sottosistema Fail2ban separato per porte specifiche |
| `/etc/config/banip` | CONFIG SITO | mai copiato integralmente |
| `/etc/dropbear/authorized_keys` | CONFIG SITO | unito, mai sostituito |

## Comportamento dell'installer

Quando viene selezionata la modalità OpenWrt, l'installer sul proxy:

1. valida la host key del firewall;
2. seleziona o crea una chiave SSH runtime dedicata;
3. prova un backend già presente, se disponibile;
4. può installare/aggiornare il payload incluso tramite una sessione SSH amministrativa separata;
5. ricava `ALLOWED_SOURCES` dal primo campo di `SSH_CONNECTION` **come visto da OpenWrt**;
6. preserva gli IP sorgente già autorizzati durante la migrazione da un vecchio wrapper hardcoded;
7. aggiunge/normalizza la chiave pubblica runtime con `command="/usr/bin/f2b-banip-wrapper"` e restrizioni su forwarding/PTY;
8. installa `banip` e `conntrack` solo quando necessario;
9. preserva `/etc/config/banip`, modificando soltanto le impostazioni minime di enable/autoblocklist;
10. esegue un test locale add/delete su indirizzo TEST-NET e poi il normale test runtime remoto dal proxy.

La chiave runtime non necessita di una shell root senza restrizioni. L'accesso
SSH amministrativo serve soltanto per installare o aggiornare il payload OpenWrt.

## Restrizione dell'indirizzo sorgente

`ALLOWED_SOURCES` non è hardcoded nella distribuzione. Il valore autorevole è
l'indirizzo client riportato nella variabile `SSH_CONNECTION` della sessione di
bootstrap su OpenWrt.

Se la tabella di routing locale del proxy indica un indirizzo sorgente diverso,
l'installer avvisa e richiede conferma invece di sceglierne uno in silenzio.

La riga della authorized key evita volutamente di dipendere da opzioni di
restrizione sorgente disponibili solo in OpenSSH. La validazione della sorgente
viene ripetuta in `f2b-banip-wrapper`, mantenendo la compatibilità con il server
SSH Dropbear normalmente usato da OpenWrt.

## API

Il wrapper ristretto espone:

```text
version
capabilities
check
check-ip <IP>
temp-add <IP> <seconds> [host source]
temp-del <IP> [host source]
sync-add <IP> [host source]
sync-del <IP> [host source]
unban-all <IP>
```

I comandi specifici per porta restano disponibili solo se il sottosistema
separato `f2b-portban` è già installato.

`version` restituisce attualmente:

```text
RWF-OPENWRT-API 1
```

## Correzioni effettuate durante l'audit

- `ALLOWED_SOURCES` è stato spostato dai dati hardcoded del wrapper a `/etc/f2b-banip-wrapper.conf`.
- Le vecchie liste hardcoded di sorgenti vengono migrate e preservate.
- `check` non rende più `f2b-portban` una dipendenza runtime artificiale.
- È stata corretta la validazione del numero di argomenti di `temp-del-port` per la compatibilità opzionale.
- `fw-unban-all` ora gestisce i set di ban globali IPv6 oltre a IPv4.
- `check-fw-ban` non perde più lo stato `found` attraverso una pipeline/subshell.
- Il sottosistema non correlato `f2b-portban` non viene intenzionalmente incluso nel core RwF.
