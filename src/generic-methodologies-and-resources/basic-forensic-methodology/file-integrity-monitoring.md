# Überwachung der Dateiintegrität

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem zukünftigen Status zu vergleichen und Änderungen hervorzuheben**.

Beispielsweise kann der Hash jeder Datei des Dateisystems berechnet und gespeichert werden, um festzustellen, welche Dateien geändert wurden.\
Dies kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Diensten und allen anderen Dingen gemacht werden, die sich nicht oder nur geringfügig ändern sollten.

Eine **nützliche Baseline** speichert normalerweise mehr als nur einen Digest: Auch Berechtigungen, Besitzer, Gruppe, Zeitstempel, Inode, Symlink-Ziel, ACLs und ausgewählte erweiterte Attribute sind eine Überwachung wert.<sup>[[4]](#references)</sup> Aus Sicht der Suche nach Angreifern hilft dies dabei, **Manipulationen, die nur Berechtigungen betreffen**, **atomaren Dateiaustausch** und **Persistenz über geänderte Service-/Unit-Dateien** zu erkennen, selbst wenn sich der Content-Hash nicht als Erstes ändert.

### Überwachung der Dateiintegrität

File Integrity Monitoring (FIM) ist eine kritische Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Es kombiniert normalerweise:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline-Vergleich:** Metadaten und kryptografische Checksummen (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche speichern.
2. **Echtzeitbenachrichtigungen:** OS-native Datei-Events abonnieren, um zu wissen, **welche Datei wann geändert wurde und idealerweise welcher Prozess/welcher Benutzer darauf zugegriffen hat**.
3. **Periodischer Rescan:** Nach Neustarts, verlorenen Events, Ausfällen von Agents oder absichtlichen Anti-Forensik-Aktivitäten erneut Vertrauen aufbauen.

Für Threat Hunting ist FIM normalerweise hilfreicher, wenn es sich auf **wichtige Pfade** konzentriert, wie etwa:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-Units, Cron-Verzeichnisse, SSH-Material, PAM-Module, Web-Roots
- Windows-Persistenzverzeichnisse, Service-Binaries, Dateien geplanter Tasks, Startup-Ordner
- Beschreibbare Container-Layer und per Bind-Mount eingebundene Secrets/Konfigurationen

## Echtzeit-Backends und Blindspots

### Linux

Das Collection-Backend ist relevant:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: einfach und weit verbreitet, aber Watch-Limits können erschöpft werden und einige Edge Cases werden nicht erfasst.
- **`auditd` / Audit-Framework**: besser, wenn benötigt wird, **wer die Datei geändert hat** (Login-UID, Prozess-ID und Prozessname).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige der betrieblichen Probleme einfacher `inotify`-Deployments zu reduzieren.

Einige praktische Stolperfallen:<sup>[[1]](#references)[[5]](#references)</sup>

- Wenn ein Programm eine Datei mit `write temp -> rename` **ersetzt**, kann die Überwachung der Datei selbst nicht mehr zuverlässig sein. **Das übergeordnete Verzeichnis überwachen**, nicht nur die Datei.
- Auf `inotify` basierende Collector können bei **sehr großen Verzeichnisbäumen**, **Hard-Link-Aktivitäten** oder nachdem eine **überwachte Datei gelöscht wurde**, Events verpassen oder beeinträchtigt werden.
- Sehr große rekursive Watch-Sets können unbemerkt fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig sind.
- Bei auf `inotify` basierender Überwachung sind Netzwerkdateisysteme ein Blindspot, da Änderungen auf dem Remote-System nicht gemeldet werden.

Beispiel für eine Baseline und Verifizierung mit AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Beispielkonfiguration für `osquery` FIM mit Fokus auf Persistenzpfade von Angreifern:<sup>[[1]](#references)</sup>
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
Wenn du **process attribution** statt nur Änderungen auf Pfadebene benötigst, bevorzuge audit-gestützte Telemetrie wie `osquery` `process_file_events` oder den Wazuh-`whodata`-Modus.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry ist kein FIM

Auf modernen Linux-Systemen ist die Überwachung von `openat(2)`, `write(2)` oder anderen syscall-Einstiegspunkten **nicht gleichbedeutend mit der Überwachung der daraus resultierenden Dateisystemoperation**. Der Proof of Concept **Curing** aus dem Jahr 2025 stellte Datei- und Netzwerkanfragen über `io_uring` in die Warteschlange, sodass Produkte oder Richtlinien, die ausschließlich an den entsprechenden Per-Operation-syscall-Einstiegspunkten ansetzten, ihre Prozess-Telemetrie verloren. In denselben Tests beobachtete eine pfadbezogene FIM-Komponente weiterhin Dateiänderungen. Dies zeigt, dass es sich um einen **Blind Spot bei der Platzierung von Hooks** handelt, nicht um eine Umgehung von Berechtigungen oder eine Möglichkeit, jedes FIM-Backend zu umgehen.<sup>[[10]](#references)</sup>

Bei der Validierung eines Sensors solltest du denselben Canary über mehrere Pfade ändern: normales `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomisches Ersetzen und `io_uring`. Prüfe nicht nur, ob die endgültige Hash-Abweichung erkannt wird, sondern auch, ob das Ereignis den verantwortlichen Prozess, den Container/die cgroup, den im Namespace sichtbaren Pfad, den Inode und das Rename-Paar beibehält. Ein fehlendes Echtzeitereignis, auf das anschließend eine Abweichung beim periodischen Scan folgt, muss als **Telemetrieverlust** und nicht als routinemäßige, ungeklärte Änderung behandelt werden.<sup>[[10]](#references)[[11]](#references)</sup>

Bei eBPF-basierter Überwachung solltest du gemeinsame Kernel-Enforcement-Points gegenüber einer Liste von syscall-entry-Probes bevorzugen. Die File-Access-Policy von Tetragon verwendet beispielsweise `security_file_permission`, um gewöhnliche I/O, `sendfile`, `copy_file_range`, AIO und `io_uring` abzudecken. Speicherzuordnungen werden separat mit `security_mmap_file` und Größenänderungen mit `security_path_truncate` abgedeckt. Dies veranschaulicht auch, warum ein einzelner Hook nur selten eine vollständige Abdeckung bietet.<sup>[[11]](#references)</sup>

### Windows

Unter Windows ist FIM stärker, wenn du **change journals** mit **hoch aussagekräftiger Prozess-/Datei-Telemetrie** kombinierst:<sup>[[6]](#references)[[7]](#references)</sup>

- Das **NTFS USN Journal** liefert ein persistentes Volume-weites Protokoll von Dateiänderungen.
- **Sysmon Event ID 11** ist für die Erstellung/Überschreibung von Dateien nützlich.
- **Sysmon Event ID 2** hilft bei der Erkennung von **timestomping**.
- **Sysmon Event ID 15** ist nützlich für **benannte alternative Datenströme (ADS)** wie `Zone.Identifier` oder versteckte Payload-Streams.

Schnelle USN-Triage-Beispiele:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weiterführende Anti-Forensic-Ideen rund um **timestamp manipulation**, **ADS abuse** und **USN tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container-FIM übersieht häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` kombiniert das Container-Dateisystem schreibgeschützte Image-`lowerdir`-Layer mit einer beschreibbaren **oberen Schicht** (`upperdir`/`diff`), und Schreibvorgänge in Image-Dateien werden in diese obere Schicht kopiert.<sup>[[8]](#references)</sup> Daher:

- Die Überwachung ausschließlich von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen übersehen, nachdem der Container neu erstellt wurde.
- Die Überwachung des **Host-Pfads**, der die beschreibbare Schicht oder das relevante bind-gemountete Volume bereitstellt, ist häufig nützlicher.
- FIM auf Image-Layern unterscheidet sich von FIM auf dem Dateisystem des laufenden Containers.

## Auf Angreifer ausgerichtete Hunting-Hinweise

- Überwache **Service-Definitionen** und **Task-Scheduler** genauso sorgfältig wie Binärdateien. Angreifer erreichen häufig Persistenz, indem sie eine Unit-Datei, einen Cron-Eintrag oder eine Task-XML-Datei ändern, anstatt `/bin/sshd` zu patchen.
- Ein Content-Hash allein ist unzureichend. Viele Kompromittierungen zeigen sich zuerst durch **Abweichungen bei Besitzer/Modus/xattr/ACL**.
- Wenn du eine fortgeschrittene Intrusion vermutest, führe beides durch: **Echtzeit-FIM** für aktuelle Aktivitäten und einen **Abgleich mit einer kalten Baseline** von vertrauenswürdigen Medien.
- Wenn der Angreifer Root- oder Kernel-Ausführung besitzt, betrachte den FIM-Agenten und seine Datenbank als nicht vertrauenswürdig. Speichere Logs und Baselines nach Möglichkeit remote oder auf schreibgeschützten Medien.<sup>[[4]](#references)</sup>

## Werkzeuge

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring mit osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing von Linux: Ein Anwendungsfall für File Integrity Monitoring (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck- und whodata-Modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE-Handbuch Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS-Speichertreiber](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Erweiterte Wazuh-FIM-Einstellungen](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit umgeht Linux-Sicherheitstools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Dateinamenzugriff: synchrone, asynchrone, gemappte und Trunkierungs-Pfade abdecken (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
