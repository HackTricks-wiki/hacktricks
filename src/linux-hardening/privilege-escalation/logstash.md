{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash jest używany do **zbierania, przekształcania i wysyłania logów** przez system znany jako **pipelines**. Te pipelines składają się z etapów **input**, **filter** i **output**. Interesujący aspekt pojawia się, gdy Logstash działa na skompromitowanej maszynie.

### Pipeline Configuration

Pipelines są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który wymienia lokalizacje konfiguracji pipelines:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf**, zawierające konfiguracje potoków. Przy użyciu **modułu wyjściowego Elasticsearch**, powszechnie zdarza się, że **potoki** zawierają **poświadczenia Elasticsearch**, które często mają szerokie uprawnienia z powodu potrzeby Logstasha do zapisywania danych w Elasticsearch. Znaki wieloznaczne w ścieżkach konfiguracji pozwalają Logstashowi na wykonanie wszystkich pasujących potoków w wyznaczonym katalogu.

### Eskalacja uprawnień za pomocą zapisywalnych potoków

Aby spróbować eskalacji uprawnień, najpierw zidentyfikuj użytkownika, pod którym działa usługa Logstash, zazwyczaj użytkownika **logstash**. Upewnij się, że spełniasz **jedno** z tych kryteriów:

- Posiadasz **dostęp do zapisu** do pliku potoku **.conf** **lub**
- Plik **/etc/logstash/pipelines.yml** używa znaku wieloznacznego, a ty możesz zapisywać w docelowym folderze

Dodatkowo, **jedno** z tych warunków musi być spełnione:

- Możliwość ponownego uruchomienia usługi Logstash **lub**
- Plik **/etc/logstash/logstash.yml** ma ustawione **config.reload.automatic: true**

Mając znak wieloznaczny w konfiguracji, stworzenie pliku, który pasuje do tego znaku, pozwala na wykonanie polecenia. Na przykład:
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
Tutaj **interval** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** jest uruchamiane co 120 sekund, a jego wyjście jest kierowane do **/tmp/output.log**.

Dzięki **config.reload.automatic: true** w **/etc/logstash/logstash.yml**, Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje potoków bez potrzeby ponownego uruchamiania. Jeśli nie ma znaku wieloznacznego, modyfikacje mogą być nadal wprowadzane do istniejących konfiguracji, ale zaleca się ostrożność, aby uniknąć zakłóceń.

## References

{{#include ../../banners/hacktricks-training.md}}
