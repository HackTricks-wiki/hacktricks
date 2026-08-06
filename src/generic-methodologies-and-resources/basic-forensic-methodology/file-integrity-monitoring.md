# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem zukünftigen Status zu vergleichen und Änderungen hervorzuheben**.

Beispielsweise kann der Hash jeder Datei des Dateisystems berechnet und gespeichert werden, um feststellen zu können, welche Dateien geändert wurden.\
Dies kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Diensten und allen anderen Dingen durchgeführt werden, die sich nicht oder nur geringfügig ändern sollten.

Eine **nützliche Baseline** speichert in der Regel mehr als nur einen Digest: Auch Berechtigungen, Eigentümer, Gruppe, Zeitstempel, Inode, Symlink-Ziel, ACLs und ausgewählte erweiterte Attribute sollten erfasst werden. Aus Sicht der Angreifer-Jagd hilft dies dabei, **Manipulationen, die nur Berechtigungen betreffen**, **atomaren Dateiaustausch** und **Persistence durch geänderte Service-/Unit-Dateien** zu erkennen, selbst wenn sich der Content-Hash nicht als Erstes ändert.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ist eine kritische Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien überwacht. Es kombiniert normalerweise:

1. **Baseline-Vergleich:** Metadaten und kryptografische Prüfsummen (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche speichern.
2. **Echtzeit-Benachrichtigungen:** OS-native Datei-Events abonnieren, um zu erfahren, **welche Datei wann geändert wurde und idealerweise welcher Prozess/welcher Benutzer darauf zugegriffen hat**.
3. **Periodischer Re-Scan:** Nach Neustarts, verlorenen Events, Ausfällen von Agents oder absichtlichen Anti-Forensik-Aktivitäten erneut Vertrauen in die Ergebnisse herstellen.

Für Threat Hunting ist FIM normalerweise nützlicher, wenn es sich auf **besonders wichtige Pfade** konzentriert, wie etwa:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-Units, Cron-Verzeichnisse, SSH-Material, PAM-Module, Web-Root-Verzeichnisse
- Windows-Persistence-Verzeichnisse, Service-Binaries, Dateien geplanter Tasks, Startup-Ordner
- Beschreibbare Container-Layer und per Bind-Mount eingebundene Secrets/Konfigurationen

## Real-Time Backends & Blind Spots

### Linux

Das Collection-Backend ist relevant:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: einfach und verbreitet, aber Watch-Limits können ausgeschöpft werden und einige Edge Cases werden nicht erkannt.
- **`auditd` / audit framework**: besser, wenn benötigt wird, **wer die Datei geändert hat** (`auid`, Prozess, pid, ausführbare Datei).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige betrieblichen Probleme einfacher `inotify`-Deployments zu reduzieren.

Einige praktische Fallstricke:<sup>[[1]](#references)</sup>

- Wenn ein Programm eine Datei mit `write temp -> rename` **ersetzt**, ist die Überwachung der Datei selbst möglicherweise nicht mehr sinnvoll. **Überwache das übergeordnete Verzeichnis**, nicht nur die Datei.
- Auf `inotify` basierende Collector können bei **sehr großen Verzeichnisbäumen**, **Hard-Link-Aktivitäten** oder nach dem **Löschen einer überwachten Datei** Events verpassen oder beeinträchtigt werden.
- Sehr große rekursive Watch-Sets können unbemerkt fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig eingestellt sind.
- Network Filesystems sind für geräuscharme Überwachung mit FIM normalerweise ungeeignete Ziele.

Beispiel für eine Baseline und deren Überprüfung mit AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Beispiel für eine auf Persistenzpfade von Angreifern fokussierte `osquery`-FIM-Konfiguration:<sup>[[1]](#references)</sup>
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
Wenn du **Prozesszuordnung** statt ausschließlich Änderungen auf Pfadebene benötigst, bevorzuge audit-gestützte Telemetrie wie `osquery` `process_file_events` oder den Wazuh-`whodata`-Modus.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Unter Windows ist FIM leistungsfähiger, wenn du **Change Journals** mit **hochsensitiver Prozess-/Dateitelemetrie** kombinierst:

- Das **NTFS USN Journal** stellt ein persistentes, volumenbezogenes Protokoll von Dateiänderungen bereit.
- **Sysmon Event ID 11** ist nützlich, um die Erstellung und das Überschreiben von Dateien zu erkennen.
- **Sysmon Event ID 2** hilft bei der Erkennung von **Timestomping**.
- **Sysmon Event ID 15** ist nützlich für **benannte alternative Datenströme (ADS)** wie `Zone.Identifier` oder versteckte Payload-Streams.

Kurze Beispiele für die USN-Triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weiterführende Anti-Forensic-Ideen rund um **timestamp manipulation**, **ADS abuse** und **USN tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container-FIM übersieht häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` werden Änderungen in die **beschreibbare obere Schicht** (`upperdir`/`diff`) geschrieben, nicht in die schreibgeschützten Image-Schichten. Daher:

- Die Überwachung ausschließlich von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen übersehen, nachdem der Container neu erstellt wurde.
- Die Überwachung des **Host-Pfads**, der die beschreibbare Schicht bereitstellt, oder des relevanten bind-gemounteten Volumes ist oft hilfreicher.
- FIM auf Image-Schichten unterscheidet sich von FIM auf dem Dateisystem des laufenden Containers.

## Angreiferorientierte Hunting-Hinweise

- Überwache **Servicedefinitionen** und **Task-Scheduler** ebenso sorgfältig wie Binaries. Angreifer erreichen häufig Persistenz, indem sie eine Unit-Datei, einen Cron-Eintrag oder eine Task-XML-Datei ändern, anstatt `/bin/sshd` zu patchen.
- Ein alleiniger Content-Hash ist nicht ausreichend. Viele Kompromittierungen zeigen sich zunächst durch **Abweichungen bei Owner, Mode, xattr oder ACL**.
- Wenn du einen ausgereiften Einbruch vermutest, führe beides durch: **Echtzeit-FIM** für aktuelle Aktivitäten und einen **Vergleich mit einer Offline-Baseline** von vertrauenswürdigen Medien.
- Wenn der Angreifer Root- oder Kernel-Ausführung erlangt hat, gehe davon aus, dass der FIM-Agent, seine Datenbank und sogar die Ereignisquelle manipuliert werden können. Speichere Logs und Baselines nach Möglichkeit remote oder auf schreibgeschützten Medien.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referenzen

- [1] [Überwachung der Dateiintegrität mit osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux nachverfolgen: Ein Anwendungsfall für die Überwachung der Dateiintegrität (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh-Dateiintegritätsüberwachung (Syscheck- und whodata-Modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
