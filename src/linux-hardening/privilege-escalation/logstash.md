{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i slanje logova** kroz sistem poznat kao **pipelines**. Ove pipelines se sastoje od **input**, **filter** i **output** faza. Zanimljiv aspekt se javlja kada Logstash radi na kompromitovanoj mašini.

### Pipeline Configuration

Pipelines se konfigurišu u datoteci **/etc/logstash/pipelines.yml**, koja navodi lokacije konfiguracija pipelines:
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi koji sadrže konfiguracije pipeline-a. Kada se koristi **Elasticsearch output module**, uobičajeno je da **pipeline-i** uključuju **Elasticsearch kredencijale**, koji često imaju opsežne privilegije zbog potrebe Logstash-a da piše podatke u Elasticsearch. Wildcard-ovi u putanjama konfiguracije omogućavaju Logstash-u da izvrši sve odgovarajuće pipeline-e u određenom direktorijumu.

### Eskalacija privilegija putem zapisivih pipeline-a

Da biste pokušali eskalaciju privilegija, prvo identifikujte korisnika pod kojim Logstash servis radi, obično korisnika **logstash**. Uverite se da ispunjavate **jedan** od ovih kriterijuma:

- Imate **pristup za pisanje** u **.conf** fajl pipeline-a **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, i možete pisati u ciljni folder

Pored toga, **jedan** od ovih uslova mora biti ispunjen:

- Mogućnost ponovnog pokretanja Logstash servisa **ili**
- Fajl **/etc/logstash/logstash.yml** ima postavljeno **config.reload.automatic: true**

S obzirom na wildcard u konfiguraciji, kreiranje fajla koji odgovara ovom wildcard-u omogućava izvršavanje komandi. Na primer:
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
Ovde, **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, **whoami** komanda se izvršava svake 120 sekundi, a njen izlaz se usmerava na **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski otkriti i primeniti nove ili izmenjene konfiguracije cevi bez potrebe za ponovnim pokretanjem. Ako nema džokera, izmene se i dalje mogu vršiti na postojećim konfiguracijama, ali se savetuje oprez kako bi se izbegle smetnje.

## References

{{#include ../../banners/hacktricks-training.md}}
