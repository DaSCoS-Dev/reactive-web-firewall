# Integrazione opzionale CSF/LFD

Reactive Web Firewall non richiede CSF. Se LFD analizza lo stesso log Apache,
può vedere le righe già accodate dopo il ban immediato e applicare un secondo
ban con durata differente.

Il file `immediate-ban-marker-snippet.pm` contiene un helper da integrare nel
proprio `regex.custom.pm`. Dopo aver estratto l'IP della riga:

```perl
return 0 if rwf_immediate_ban_active($ip);
```

Non sostituire ciecamente un `regex.custom.pm` esistente: il file CSF è spesso
specifico dell'installazione e va unito manualmente.
