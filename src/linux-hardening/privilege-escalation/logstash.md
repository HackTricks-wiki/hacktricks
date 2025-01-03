{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash inatumika **kusanya, kubadilisha, na kutuma kumbukumbu** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter**, na **output**. Kipengele cha kuvutia kinajitokeza wakati Logstash inafanya kazi kwenye mashine iliyoathiriwa.

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
Hii faili inaonyesha mahali ambapo faili za **.conf**, zinazoshikilia mipangilio ya pipeline, ziko. Wakati wa kutumia **Elasticsearch output module**, ni kawaida kwa **pipelines** kujumuisha **Elasticsearch credentials**, ambazo mara nyingi zina mamlaka makubwa kutokana na hitaji la Logstash kuandika data kwenye Elasticsearch. Wildcards katika njia za mipangilio zinamruhusu Logstash kutekeleza pipelines zote zinazolingana katika saraka iliyoainishwa.

### Kupanda Mamlaka kupitia Pipelines Zinazoweza Kuandikwa

Ili kujaribu kupanda mamlaka, kwanza tambua mtumiaji ambaye huduma ya Logstash inafanya kazi chini yake, kawaida ni mtumiaji wa **logstash**. Hakikisha unakidhi **moja** ya vigezo hivi:

- Kuwa na **ufikiaji wa kuandika** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Uwezo wa kuanzisha upya huduma ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Ili kuwa na wildcard katika mipangilio, kuunda faili inayolingana na wildcard hii kunaruhusu utekelezaji wa amri. Kwa mfano:
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
Hapa, **interval** inabainisha mzunguko wa utekelezaji kwa sekunde. Katika mfano uliopewa, amri ya **whoami** inatekelezwa kila sekunde 120, na matokeo yake yanaelekezwa kwa **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua kiotomatiki na kutekeleza mipangilio mipya au iliyobadilishwa ya bomba bila kuhitaji kuanzisha upya. Ikiwa hakuna wildcard, mabadiliko bado yanaweza kufanywa kwa mipangilio iliyopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.

## References

{{#include ../../banners/hacktricks-training.md}}
