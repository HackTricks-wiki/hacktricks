# Überwachung der Dateiintegrität

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem zukünftigen Status zu vergleichen und Änderungen hervorzuheben**.

Beispielsweise kann der Hash jeder Datei des Dateisystems berechnet und gespeichert werden, um herauszufinden, welche Dateien geändert wurden.\
Dies kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Services und allen anderen Dingen geschehen, die sich nicht oder nur geringfügig ändern sollten.

Eine **nützliche Baseline** speichert normalerweise mehr als nur einen Digest: Auch Berechtigungen, Besitzer, Gruppe, Zeitstempel, Inode, Symlink-Ziel, ACLs und ausgewählte erweiterte Attribute sind eine Überwachung wert. Aus Sicht der Angreifer-Suche hilft dies dabei, **Manipulationen ausschließlich an Berechtigungen**, **atomaren Dateiersatz** und **Persistenz über geänderte Service-/Unit-Dateien** zu erkennen, selbst wenn sich der Content-Hash nicht als Erstes ändert.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ist eine wichtige Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Es kombiniert normalerweise:

1. **Baseline-Vergleich:** Metadaten und kryptografische Prüfsummen (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche speichern.
2. **Echtzeitbenachrichtigungen:** OS-native Datei-Events abonnieren, um zu erfahren, **welche Datei wann geändert wurde und idealerweise welcher Prozess/welcher Benutzer sie verändert hat**.
3. **Periodischer Rescan:** Nach Reboots, verlorenen Events, Ausfällen von Agents oder absichtlichen Anti-Forensik-Aktivitäten erneut Vertrauen herstellen.

Für Threat Hunting ist FIM normalerweise nützlicher, wenn der Fokus auf **wichtigen Pfaden** liegt, etwa:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-Units, Cron-Verzeichnisse, SSH-Material, PAM-Module, Web-Roots
- Windows-Persistenzpfade, Service-Binaries, Dateien geplanter Tasks, Startup-Ordner
- Beschreibbare Container-Layer und per Bind-Mount eingebundene Secrets/Konfigurationen

## Echtzeit-Backends und Blind Spots

### Linux

Das Collection-Backend ist relevant:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: einfach und verbreitet, aber Watch-Limits können ausgeschöpft werden und einige Edge Cases werden übersehen.
- **`auditd` / Audit-Framework**: besser, wenn benötigt wird, **wer die Datei geändert hat** (`auid`, Prozess, pid, ausführbare Datei).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige betrieblichen Probleme reiner `inotify`-Deployments zu reduzieren.

Einige praktische Stolpersteine:<sup>[[1]](#references)</sup>

- Wenn ein Programm eine Datei durch `write temp -> rename` **ersetzt**, kann es nutzlos werden, nur die Datei selbst zu überwachen. **Überwache das übergeordnete Verzeichnis**, nicht nur die Datei.
- Auf `inotify` basierende Collector können bei **sehr großen Verzeichnisbäumen**, **Hard-Link-Aktivitäten** oder nachdem eine **überwachte Datei gelöscht wurde**, Events übersehen oder beeinträchtigt werden.
- Sehr große rekursive Watch-Sets können unbemerkt fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig eingestellt sind.
- Netzwerkdateisysteme sind normalerweise schlechte FIM-Ziele für Monitoring mit geringem Rauschen.

Beispiel für Baseline und Verifizierung mit AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Beispiel für eine auf Pfade zur Persistenz von Angreifern ausgerichtete `osquery`-FIM-Konfiguration:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Wenn du **process attribution** statt ausschließlich Änderungen auf Pfadebene benötigst, bevorzuge auditgestützte Telemetrie wie `osquery` `process_file_events` oder den Wazuh-`whodata`-Modus.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Unter Windows ist FIM effektiver, wenn du **change journals** mit **high-signal process/file telemetry** kombinierst:

- Das **NTFS USN Journal** liefert ein dauerhaftes volumenweites Protokoll der Dateiänderungen.
- **Sysmon Event ID 11** ist für die Erkennung der Dateierstellung bzw. des Überschreibens nützlich.
- **Sysmon Event ID 2** hilft bei der Erkennung von **timestomping**.
- **Sysmon Event ID 15** ist für **named alternate data streams (ADS)** wie `Zone.Identifier` oder versteckte Payload-Streams nützlich.

Schnelle Beispiele für die USN-Triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weiterführende Anti-Forensic-Ideen rund um **timestamp manipulation**, **ADS abuse** und **USN tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container-FIM verpasst häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` werden Änderungen in die **writable upper layer** (`upperdir`/`diff`) des Containers geschrieben, nicht in die schreibgeschützten Image-Layer. Daher:

- Die Überwachung ausschließlich von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen übersehen, nachdem der Container neu erstellt wurde.
- Die Überwachung des **Host-Pfads**, der die writable layer abbildet, oder des relevanten bind-mounted volume ist häufig sinnvoller.
- FIM auf Image-Layern unterscheidet sich von FIM auf dem Dateisystem des laufenden Containers.

## Angreiferorientierte Hunting-Hinweise

- Überwache **service definitions** und **task schedulers** ebenso sorgfältig wie Binärdateien. Angreifer erlangen häufig Persistenz, indem sie eine Unit-Datei, einen Cron-Eintrag oder eine Task-XML-Datei ändern, statt `/bin/sshd` zu patchen.
- Ein Content-Hash allein ist unzureichend. Viele Kompromittierungen zeigen sich zunächst als **owner/mode/xattr/ACL drift**.
- Wenn du einen ausgereiften Einbruch vermutest, tue beides: **real-time FIM** für aktuelle Aktivitäten und einen **cold baseline comparison** von vertrauenswürdigen Medien.
- Wenn der Angreifer Root- oder Kernel-Ausführung erlangt hat, gehe davon aus, dass der FIM-Agent, seine Datenbank und sogar die Ereignisquelle manipuliert werden können. Speichere Logs und Baselines wann immer möglich remote oder auf schreibgeschützten Medien.

## Werkzeuge

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referenzen

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
