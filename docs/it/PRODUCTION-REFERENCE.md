<!--
Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Riferimento di produzione e audit prestazionale

[English](../en/PRODUCTION-REFERENCE.md) | **Italiano**

Data baseline audit: 2026-08-14

Queste misure provengono da un vero reverse proxy Apache di produzione mentre il
motore di rilevazione **Inside Apache** veniva validato contro traffico malevolo
non sollecitato. Sono **misure di riferimento osservate in produzione**, non
requisiti minimi né prestazioni garantite. Il traffico sintetico degli
installer/self-test è escluso. Non devono essere presentate come benchmark del
motore Log Reader, il cui punto di rilevazione è intenzionalmente successivo alla
scrittura dell'access log da parte di Apache.

## Hardware di produzione di riferimento

| Componente | Sistema di riferimento |
|---|---|
| Sistema | Lenovo E50-00 / prodotto 90BX005XIX |
| CPU | Intel Pentium J2900 @ 2.41 GHz |
| Topologia CPU | 4 core fisici, 4 thread, senza SMT |
| RAM | 4 GB Samsung DDR3 @ 1333 MT/s |
| Storage | 2 × Crucial BX500 SATA SSD, 240 GB |
| RAID | Linux software RAID1 per `/boot` e `/` |
| NIC | Realtek RTL8111/8168/8411 PCIe Gigabit Ethernet |
| Link durante l'audit | 1 Gbit/s, full duplex |
| OS | Ubuntu 22.04.5 LTS, x86-64 |
| Kernel | Linux 5.15.0-176-generic |
| Apache | 2.4.52 (Ubuntu), MPM event |
| Backend firewall | OpenWrt con bridge/fallback nftables locale |

L'hardware è volutamente modesto. I risultati devono essere letti nel contesto
del carico di produzione concorrente, dello stato dello scheduler e della
latenza esterna SSH/OpenWrt.

## Cosa viene misurato

RwF ha più milestone di protezione, che non devono essere fuse in un ambiguo
“tempo di ban”:

1. **Gestione della richiesta RwF** dentro Apache.
2. **Consegna socket al helper** dal modulo al helper privilegiato.
3. **Chiusura/abort della connessione a livello applicativo** da Apache/RwF.
4. **Blocco nftables locale** sul reverse proxy.
5. **Conferma perimetrale** da OpenWrt.
6. **Completamento del worker** dopo socket sweep e pulizia del fallback.

La shared cache Apache è intenzionalmente attiva prima che i punti 4 e 5 siano
completati, quindi le richieste successive non devono attendere l'enforcement
del firewall.

## Baseline di produzione valida: 10 ban reali non sollecitati

La baseline pubblica include **10 eventi reali di produzione raccolti mentre il
fast path locale funzionava normalmente**. Una regressione temporanea di
sviluppo nel percorso del firewall locale viene esclusa deliberatamente perché
è stata identificata, rimossa e non rappresenta l'implementazione distribuita.
Nessun valore di quella regressione viene simulato, corretto o mescolato nelle
statistiche. Anche il traffico installer/self-test è escluso.

I primi cinque eventi validi sono stati conservati come statistiche aggregate
esatte; i cinque successivi sono stati conservati singolarmente. Per questo una
mediana complessiva N=10 **non viene inventata** quando non sono disponibili
tutti e dieci i valori grezzi originali.

### Metriche disponibili su tutti i 10 eventi validi

| Metrica | N | Media | Min | Max |
|---|---:|---:|---:|---:|
| consegna modulo → helper | 10 | **0.330 ms** | 0.142 ms | 0.532 ms |
| richiesta → blocco nftables locale | 10 | **47.308 ms** | 37.446 ms | 55.418 ms |
| richiesta → conferma OpenWrt | 10 | **268.434 ms** | 199.945 ms | 372.444 ms |
| worker helper completo | 10 | **339.031 ms** | 271.786 ms | 438.281 ms |

### Sottoinsieme dettagliato: 5 eventi conservati singolarmente

Questi cinque eventi aggiungono strumentazione che non è stata conservata per
ogni campione valido precedente. Sono riportati separatamente solo perché le
metriche disponibili differiscono, non per sostenere l'esistenza di una coorte
di versione software.

| Metrica | N | Media | Mediana | Min | Max |
|---|---:|---:|---:|---:|---:|
| consegna modulo → helper | 5 | 0.332 ms | 0.283 ms | 0.224 ms | 0.497 ms |
| add di `custom-web-fastban` | 5 | **42.819 ms** | 45.405 ms | 35.595 ms | 48.588 ms |
| richiesta → blocco nftables locale | 5 | **44.640 ms** | 47.280 ms | 37.446 ms | 50.497 ms |
| sweep `ss -K` pre | 5 | 10.579 ms | 10.749 ms | 9.512 ms | 11.745 ms |
| comando remoto OpenWrt | 5 | 201.406 ms | 162.215 ms | 140.686 ms | 281.630 ms |
| richiesta → conferma OpenWrt | 5 | 256.858 ms | 213.026 ms | 199.945 ms | 330.302 ms |
| rimozione fallback locale | 5 | 57.815 ms | 56.176 ms | 52.921 ms | 65.396 ms |
| worker helper completo | 5 | 326.003 ms | 289.664 ms | 271.786 ms | 395.423 ms |

Il campione conservato singolarmente copre firme reali differenti e traffico sia
HTTP/1.1 sia HTTP/2, inclusa la gestione shared-cache fra richieste/connessioni
concorrenti.

## Misure Apache/cache da traffico reale

Le osservazioni rappresentative includono:

- normale elaborazione RwF no-match nell'ordine di poche decine di microsecondi;
- primi match di regole ad alta confidenza nell'ordine di poche centinaia di microsecondi dentro RwF;
- blocchi cached/paralleli successivi intorno a cento microsecondi dentro RwF;
- transazioni Apache complete per richieste bloccate comunemente sotto pochi millisecondi;
- richieste HTTP/2 concorrenti bloccate dalla shared cache mentre nftables e OpenWrt stavano ancora elaborando il primo evento.

Queste osservazioni spiegano perché `richiesta → blocco nftables locale` non è la
finestra di esposizione dell'applicazione. La decisione applicativa avviene prima.

## Audit della chiusura a livello pacchetto

La correlazione fra PCAP e timestamp RwF/helper mostra la chiusura applicativa
prima del completamento del firewall locale/perimetrale. Osservazioni anonime
rappresentative:

| Scenario | Osservazione a livello pacchetto | nftables locale | OpenWrt |
|---|---:|---:|---:|
| HTTP/2, stream concorrenti sulla stessa connessione TCP | primo RST del proxy circa **3.886 ms** dopo il timestamp sorgente RwF vincente | 50.497 ms | 328.861 ms |
| target WordPress batch HTTP/1.1 | FIN del proxy circa **0.663 ms** dopo il timestamp sorgente RwF | 47.280 ms | 199.945 ms |
| HTTP/2, due connessioni TCP simultanee | seconda richiesta bloccata da cache in **0.089 ms** dentro RwF prima del completamento del firewall locale | 49.011 ms | 213.026 ms |
| probe PHPUnit | FIN del proxy circa **0.844 ms** dopo il timestamp sorgente RwF | 38.968 ms | 212.154 ms |

I record applicativi TLS esatti non possono essere associati ai singoli stream
HTTP/2 cifrati senza decifratura; la correlazione usa quindi i timestamp delle
richieste forniti da Apache insieme alla temporizzazione FIN/RST TCP e non
sovrastima ciò che il packet capture dimostra.

## Interpretazione operativa

```text
richiesta malevola
  ↓
match regola RwF / cache-add       sub-ms fino a pochi ms
  ↓
richieste successive               blocco shared-cache, tipicamente sub-ms in RwF
  ↓
close/abort connessione Apache     osservato prima del completamento firewall
  ↓
nftables locale                    blocco di ammissione locale
  ↓
OpenWrt                             blocco perimetrale
```

Gli stadi esterni di enforcement possono essere più lenti senza lasciare libere
le richieste successive di raggiungere l'applicazione, perché la cache Apache
copre già quell'intervallo.

## Riproduzione del profilo hardware sanitizzato

Eseguire:

```bash
./scripts/collect-system-profile.sh
```

Lo script omette intenzionalmente machine ID, boot ID, indirizzi MAC, indirizzi
IP, seriali dei dischi e dettagli di share private montate.

## Aggiornamento dell'audit

Quando si aggiungono campioni:

- usare solo eventi malevoli reali e non sollecitati;
- mantenere separati gli eventi installer/self-test;
- includere solo misure rappresentative del fast path attualmente distribuito;
- non “correggere” né simulare mai un campione grezzo per renderlo comparabile;
- riportare N e solo statistiche supportate da dati grezzi/aggregati preservati;
- dove esiste un PCAP, correlare RwF, FIN/RST, blocco locale e conferma remota.
