# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem zukünftigen Status zu vergleichen und Änderungen hervorzuheben**.

Beispielsweise kann der Hash jeder Datei des Dateisystems berechnet und gespeichert werden, um herauszufinden, welche Dateien geändert wurden.\
Dies kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Services und allen anderen Dingen gemacht werden, die sich nicht oder nur geringfügig ändern sollten.

Eine **nützliche Baseline** speichert normalerweise mehr als nur einen Digest: Auch Berechtigungen, Besitzer, Gruppe, Zeitstempel, Inode, Symlink-Ziel, ACLs und ausgewählte erweiterte Attribute sind eine Nachverfolgung wert.<sup>[[4]](#references)</sup> Aus Sicht der Angreiferjagd hilft dies dabei, **Manipulationen ausschließlich an Berechtigungen**, den **atomaren Austausch von Dateien** und **Persistenz durch modifizierte Service-/Unit-Dateien** zu erkennen, selbst wenn sich der Inhaltshash nicht als Erstes ändert.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ist eine wichtige Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Es kombiniert normalerweise:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline-Vergleich:** Metadaten und kryptografische Prüfsummen (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche speichern.
2. **Echtzeitbenachrichtigungen:** OS-native Datei-Events abonnieren, um zu erfahren, **welche Datei wann geändert wurde und idealerweise welcher Prozess/welcher Benutzer darauf zugegriffen hat**.
3. **Periodischer Re-Scan:** Nach Neustarts, verlorenen Events, Ausfällen von Agents oder absichtlichen Anti-Forensik-Aktivitäten erneut Vertrauen aufbauen.

Für Threat Hunting ist FIM normalerweise nützlicher, wenn es auf **wichtige Pfade** fokussiert ist, beispielsweise:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-Units, Cron-Verzeichnisse, SSH-Material, PAM-Module, Web-Roots
- Windows-Persistenzpfade, Service-Binaries, Dateien geplanter Tasks, Autostartordner
- Beschreibbare Container-Layer und per Bind-Mount eingebundene Secrets/Konfigurationen

## Echtzeit-Backends und Blind Spots

### Linux

Das Collection-Backend ist relevant:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: einfach und verbreitet, aber Watch-Limits können ausgeschöpft werden und einige Edge Cases werden übersehen.
- **`auditd` / Audit-Framework**: besser, wenn benötigt wird, **wer die Datei geändert hat** (Login-UID, Prozess-ID und Prozessname).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige betriebliche Probleme einfacher `inotify`-Deployments zu reduzieren.

Einige praktische Fallstricke:<sup>[[1]](#references)[[5]](#references)</sup>

- Wenn ein Programm eine Datei mit `write temp -> rename` **ersetzt**, kann es nutzlos werden, nur die Datei selbst zu überwachen. **Überwache das übergeordnete Verzeichnis**, nicht nur die Datei.
- Auf `inotify` basierende Collector können bei **sehr großen Verzeichnisbäumen**, **Hard-Link-Aktivitäten** oder nachdem eine **überwachte Datei gelöscht wurde**, Events verpassen oder beeinträchtigt werden.
- Sehr große rekursive Watch-Sets können unbemerkt fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig sind.
- Bei auf `inotify` basierendem Monitoring sind Netzwerkdateisysteme ein Blind Spot, da Änderungen auf der Remote-Seite nicht gemeldet werden.

Beispiel für eine Baseline und deren Überprüfung mit AIDE:<sup>[[4]](#references)</sup>
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
Wenn du **process attribution** und nicht nur Änderungen auf Pfadebene benötigst, bevorzuge auditbasierte Telemetrie wie `osquery` `process_file_events` oder den Wazuh-`whodata`-Modus.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Unter Windows ist FIM leistungsfähiger, wenn du **change journals** mit **high-signal process/file telemetry** kombinierst:<sup>[[6]](#references)[[7]](#references)</sup>

- Das **NTFS USN Journal** liefert ein dauerhaftes, volumenbezogenes Protokoll von Dateiänderungen.
- **Sysmon Event ID 11** ist nützlich für die Erstellung und das Überschreiben von Dateien.
- **Sysmon Event ID 2** hilft bei der Erkennung von **timestomping**.
- **Sysmon Event ID 15** ist nützlich für **named alternate data streams (ADS)** wie `Zone.Identifier` oder versteckte Payload-Streams.

Schnelle Beispiele für die USN-Triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weiterführende Anti-Forensic-Ideen rund um **timestamp manipulation**, **ADS abuse** und **USN tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container-FIM übersieht häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` kombiniert das Container-Dateisystem schreibgeschützte Image-`lowerdir`-Layer mit einer beschreibbaren **oberen Ebene** (`upperdir`/`diff`), und Schreibvorgänge in Image-Dateien werden in diese obere Ebene kopiert.<sup>[[8]](#references)</sup> Daher:

- Die Überwachung ausschließlich von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen übersehen, nachdem der Container neu erstellt wurde.
- Die Überwachung des **Host-Pfads**, der die beschreibbare Ebene oder das relevante bind-gemountete Volume bereitstellt, ist häufig nützlicher.
- FIM auf Image-Layern unterscheidet sich von FIM auf dem Dateisystem des laufenden Containers.

## Angreiferorientierte Hunting-Hinweise

- Verfolge **service definitions** und **task schedulers** ebenso sorgfältig wie Binärdateien. Angreifer erreichen häufig Persistenz, indem sie eine Unit-Datei, einen Cron-Eintrag oder eine Task-XML-Datei ändern, anstatt `/bin/sshd` zu patchen.
- Ein Content-Hash allein ist nicht ausreichend. Viele Kompromittierungen zeigen sich zunächst als **Abweichungen bei Besitzer, Modus, xattr oder ACL**.
- Wenn du einen fortgeschrittenen Einbruch vermutest, tue beides: **Echtzeit-FIM** für neue Aktivitäten und einen **Abgleich mit einer kalten Baseline** von vertrauenswürdigen Medien.
- Wenn der Angreifer Root- oder Kernel-Ausführung besitzt, behandle den FIM-Agenten und seine Datenbank als nicht vertrauenswürdig. Speichere Logs und Baselines nach Möglichkeit remote oder auf schreibgeschützten Medien.<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Dateiintegritätsüberwachung mit osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux nachverfolgen: Ein Anwendungsfall für die Dateiintegritätsüberwachung (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh-Dateiintegritätsüberwachung (Syscheck- und whodata-Modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE-Handbuch Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS-Speichertreiber](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Erweiterte Wazuh-FIM-Einstellungen](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
