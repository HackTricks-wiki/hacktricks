{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Protokolle zu sammeln, zu transformieren und zu versenden** durch ein System, das als **Pipelines** bekannt ist. Diese Pipelines bestehen aus **Eingabe**, **Filter** und **Ausgabe** Phasen. Ein interessantes Aspekt tritt auf, wenn Logstash auf einem kompromittierten Rechner arbeitet.

### Pipeline-Konfiguration

Pipelines werden in der Datei **/etc/logstash/pipelines.yml** konfiguriert, die die Standorte der Pipeline-Konfigurationen auflistet:
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
Diese Datei zeigt, wo sich die **.conf**-Dateien mit den Pipeline-Konfigurationen befinden. Bei der Verwendung eines **Elasticsearch output module** ist es üblich, dass **Pipelines** **Elasticsearch-Anmeldeinformationen** enthalten, die oft umfangreiche Berechtigungen besitzen, da Logstash Daten in Elasticsearch schreiben muss. Platzhalter in den Konfigurationspfaden ermöglichen es Logstash, alle übereinstimmenden Pipelines im angegebenen Verzeichnis auszuführen.

### Privilegieneskalation über beschreibbare Pipelines

Um eine Privilegieneskalation zu versuchen, identifizieren Sie zunächst den Benutzer, unter dem der Logstash-Dienst läuft, typischerweise den **logstash**-Benutzer. Stellen Sie sicher, dass Sie **eine** dieser Kriterien erfüllen:

- Besitzen Sie **Schreibzugriff** auf eine Pipeline-**.conf**-Datei **oder**
- Die **/etc/logstash/pipelines.yml**-Datei verwendet einen Platzhalter, und Sie können in den Zielordner schreiben

Zusätzlich muss **eine** dieser Bedingungen erfüllt sein:

- Fähigkeit, den Logstash-Dienst neu zu starten **oder**
- Die **/etc/logstash/logstash.yml**-Datei hat **config.reload.automatic: true** gesetzt

Angesichts eines Platzhalters in der Konfiguration ermöglicht das Erstellen einer Datei, die mit diesem Platzhalter übereinstimmt, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungsfrequenz in Sekunden. Im gegebenen Beispiel wird der **whoami**-Befehl alle 120 Sekunden ausgeführt, wobei die Ausgabe an **/tmp/output.log** geleitet wird.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** wird Logstash automatisch neue oder modifizierte Pipeline-Konfigurationen erkennen und anwenden, ohne dass ein Neustart erforderlich ist. Wenn es kein Wildcard gibt, können weiterhin Änderungen an bestehenden Konfigurationen vorgenommen werden, jedoch ist Vorsicht geboten, um Unterbrechungen zu vermeiden.

## References

{{#include ../../banners/hacktricks-training.md}}
