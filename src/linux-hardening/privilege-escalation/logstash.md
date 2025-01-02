{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash inatumika kwa **kusanya, kubadilisha, na kutuma logi** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter**, na **output**. Nyenzo ya kuvutia inajitokeza wakati Logstash inafanya kazi kwenye mashine iliyovunjwa.

### Pipeline Configuration

Pipelines zinapangiliwa katika faili **/etc/logstash/pipelines.yml**, ambayo inataja maeneo ya mipangilio ya pipeline:
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
Hii faili inaonyesha mahali ambapo faili za **.conf**, zinazoshikilia mipangilio ya pipeline, ziko. Wakati wa kutumia **Elasticsearch output module**, ni kawaida kwa **pipelines** kujumuisha **Elasticsearch credentials**, ambazo mara nyingi zina mamlaka makubwa kutokana na hitaji la Logstash kuandika data kwenye Elasticsearch. Wildcards katika njia za mipangilio zinamruhusu Logstash kutekeleza pipelines zote zinazolingana katika directory iliyoainishwa.

### Kupanda Mamlaka kupitia Pipelines Zinazoweza Kuandikwa

Ili kujaribu kupanda mamlaka, kwanza tambua mtumiaji ambaye huduma ya Logstash inafanya kazi chini yake, kawaida ni mtumiaji wa **logstash**. Hakikisha unakidhi **moja** ya vigezo hivi:

- Kuwa na **ufikiaji wa kuandika** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima yatimizwe:

- Uwezo wa kuanzisha upya huduma ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Kutoa wildcard katika mipangilio, kuunda faili inayolingana na wildcard hii kunaruhusu utekelezaji wa amri. Kwa mfano:
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
Hapa, **interval** inamaanisha mara ya utekelezaji kwa sekunde. Katika mfano uliopewa, amri ya **whoami** inatekelezwa kila sekunde 120, na matokeo yake yanaelekezwa kwa **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutekeleza kiotomatiki mipangilio mipya au iliyobadilishwa ya pipeline bila kuhitaji kuanzisha upya. Ikiwa hakuna wildcard, mabadiliko bado yanaweza kufanywa kwa mipangilio iliyopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.

## References

{{#include ../../banners/hacktricks-training.md}}
