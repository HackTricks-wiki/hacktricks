{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash viene utilizzato per **raccogliere, trasformare e inviare log** attraverso un sistema noto come **pipeline**. Queste pipeline sono composte da fasi di **input**, **filter** e **output**. Un aspetto interessante si presenta quando Logstash opera su una macchina compromessa.

### Configurazione della Pipeline

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
Questo file rivela dove si trovano i file **.conf**, contenenti configurazioni dei pipeline. Quando si utilizza un **Elasticsearch output module**, è comune che i **pipelines** includano **Elasticsearch credentials**, che spesso possiedono ampi privilegi a causa della necessità di Logstash di scrivere dati su Elasticsearch. I caratteri jolly nei percorsi di configurazione consentono a Logstash di eseguire tutti i pipeline corrispondenti nella directory designata.

### Privilege Escalation via Writable Pipelines

Per tentare l'escalation dei privilegi, prima identifica l'utente sotto il quale il servizio Logstash è in esecuzione, tipicamente l'utente **logstash**. Assicurati di soddisfare **uno** di questi criteri:

- Possedere **accesso in scrittura** a un file **.conf** del pipeline **o**
- Il file **/etc/logstash/pipelines.yml** utilizza un carattere jolly e puoi scrivere nella cartella di destinazione

Inoltre, **una** di queste condizioni deve essere soddisfatta:

- Capacità di riavviare il servizio Logstash **o**
- Il file **/etc/logstash/logstash.yml** ha **config.reload.automatic: true** impostato

Data la presenza di un carattere jolly nella configurazione, creare un file che corrisponde a questo carattere jolly consente l'esecuzione di comandi. Ad esempio:
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
Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio fornito, il comando **whoami** viene eseguito ogni 120 secondi, con il suo output diretto a **/tmp/output.log**.

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileverà automaticamente e applicherà nuove o modificate configurazioni della pipeline senza necessità di riavvio. Se non c'è un carattere jolly, le modifiche possono comunque essere apportate alle configurazioni esistenti, ma si consiglia cautela per evitare interruzioni.

## References

{{#include ../../banners/hacktricks-training.md}}
