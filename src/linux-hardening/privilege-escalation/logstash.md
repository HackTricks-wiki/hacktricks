{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग **लॉग इकट्ठा करने, रूपांतरित करने और भेजने** के लिए किया जाता है, जिसे **पाइपलाइनों** के रूप में जाना जाता है। ये पाइपलाइन्स **इनपुट**, **फिल्टर**, और **आउटपुट** चरणों से बनी होती हैं। एक दिलचस्प पहलू तब उत्पन्न होता है जब Logstash एक समझौता किए गए मशीन पर काम करता है।

### Pipeline Configuration

पाइपलाइन्स को फ़ाइल **/etc/logstash/pipelines.yml** में कॉन्फ़िगर किया जाता है, जो पाइपलाइन कॉन्फ़िगरेशन के स्थानों की सूची देता है:
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
यह फ़ाइल उन **.conf** फ़ाइलों का स्थान प्रकट करती है, जिनमें पाइपलाइन कॉन्फ़िगरेशन होते हैं। जब **Elasticsearch output module** का उपयोग किया जाता है, तो **pipelines** में अक्सर **Elasticsearch credentials** शामिल होते हैं, जिनमें Logstash की आवश्यकता के कारण व्यापक विशेषाधिकार होते हैं कि वह Elasticsearch में डेटा लिख सके। कॉन्फ़िगरेशन पथों में वाइल्डकार्ड Logstash को निर्दिष्ट निर्देशिका में सभी मेल खाने वाले पाइपलाइनों को निष्पादित करने की अनुमति देते हैं।

### Writable Pipelines के माध्यम से विशेषाधिकार वृद्धि

विशेषाधिकार वृद्धि का प्रयास करने के लिए, पहले उस उपयोगकर्ता की पहचान करें जिसके तहत Logstash सेवा चल रही है, आमतौर पर **logstash** उपयोगकर्ता। सुनिश्चित करें कि आप इनमें से **एक** मानदंड को पूरा करते हैं:

- एक पाइपलाइन **.conf** फ़ाइल में **लेखन पहुंच** हो **या**
- **/etc/logstash/pipelines.yml** फ़ाइल में वाइल्डकार्ड का उपयोग किया गया है, और आप लक्षित फ़ोल्डर में लिख सकते हैं

इसके अतिरिक्त, इनमें से **एक** शर्त को पूरा किया जाना चाहिए:

- Logstash सेवा को पुनः प्रारंभ करने की क्षमता **या**
- **/etc/logstash/logstash.yml** फ़ाइल में **config.reload.automatic: true** सेट है

कॉन्फ़िगरेशन में वाइल्डकार्ड दिए जाने पर, एक फ़ाइल बनाना जो इस वाइल्डकार्ड से मेल खाती है, कमांड निष्पादन की अनुमति देता है। उदाहरण के लिए:
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
यहाँ, **interval** निष्पादन की आवृत्ति को सेकंड में निर्धारित करता है। दिए गए उदाहरण में, **whoami** कमांड हर 120 सेकंड में चलती है, और इसका आउटपुट **/tmp/output.log** में भेजा जाता है।

**/etc/logstash/logstash.yml** में **config.reload.automatic: true** के साथ, Logstash स्वचालित रूप से नए या संशोधित पाइपलाइन कॉन्फ़िगरेशन का पता लगाएगा और उन्हें लागू करेगा बिना किसी पुनरारंभ की आवश्यकता के। यदि कोई वाइल्डकार्ड नहीं है, तो मौजूदा कॉन्फ़िगरेशन में संशोधन किए जा सकते हैं, लेकिन व्यवधान से बचने के लिए सावधानी बरतने की सलाह दी जाती है।

## References

{{#include ../../banners/hacktricks-training.md}}
