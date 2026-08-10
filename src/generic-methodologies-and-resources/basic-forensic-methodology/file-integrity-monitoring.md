# Überwachung der Dateiintegrität

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem zukünftigen Status zu vergleichen und Änderungen hervorzuheben**.

Beispielsweise kann der Hash jeder Datei des Dateisystems berechnet und gespeichert werden, um herauszufinden, welche Dateien geändert wurden.\
Dies kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Diensten und allen anderen Dingen gemacht werden, die sich nicht oder nur geringfügig ändern sollten.

Eine **nützliche Baseline** speichert normalerweise mehr als nur einen Digest: Auch Berechtigungen, Besitzer, Gruppe, Zeitstempel, Inode, Symlink-Ziel, ACLs und ausgewählte erweiterte Attribute sind eine Überwachung wert.<sup>[[4]](#references)</sup> Aus Sicht der Angreiferjagd hilft dies dabei, **Manipulationen ausschließlich an Berechtigungen**, **atomaren Dateiersatz** und **Persistenz durch geänderte Dienst-/Unit-Dateien** zu erkennen, selbst wenn sich der Inhalts-Hash nicht als Erstes ändert.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ist eine wichtige Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Es kombiniert normalerweise:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline comparison:** Metadaten und kryptografische Prüfsummen (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche speichern.
2. **Real-time notifications:** OS-native Datei-Events abonnieren, um zu erfahren, **welche Datei wann geändert wurde und idealerweise welcher Prozess/welcher Benutzer darauf zugegriffen hat**.
3. **Periodic re-scan:** Nach Neustarts, verlorenen Events, Ausfällen des Agents oder gezielten Anti-Forensik-Aktivitäten erneut scannen, um die Zuverlässigkeit wiederherzustellen.

Für Threat Hunting ist FIM normalerweise nützlicher, wenn es sich auf **wichtige Pfade** konzentriert, wie etwa:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd`-Units, Cron-Verzeichnisse, SSH-Material, PAM-Module, Web-Roots
- Windows-Persistenzverzeichnisse, Service-Binaries, Dateien geplanter Tasks, Autostart-Ordner
- Beschreibbare Container-Layer und eingebundene Secrets/Konfigurationen

## Echtzeit-Backends und blinde Flecken

### Linux

Das Collection-Backend ist relevant:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: einfach und verbreitet, aber Watch-Limits können ausgeschöpft werden und einige Sonderfälle werden nicht erkannt.
- **`auditd` / audit framework**: besser, wenn benötigt wird, **wer die Datei geändert hat** (Login-UID, Prozess-ID und Prozessname).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige betriebliche Probleme einfacher `inotify`-Deployments zu reduzieren.

Einige praktische Stolperfallen:<sup>[[1]](#references)[[5]](#references)</sup>

- Wenn ein Programm eine Datei mit `write temp -> rename` **ersetzt**, kann die Überwachung der Datei selbst unbrauchbar werden. **Das übergeordnete Verzeichnis überwachen**, nicht nur die Datei.
- Auf `inotify` basierende Collector können bei **riesigen Verzeichnisbäumen**, **Hard-Link-Aktivitäten** oder nach dem **Löschen einer überwachten Datei** Events verpassen oder beeinträchtigt werden.
- Sehr große rekursive Watch-Mengen können unbemerkt fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig eingestellt sind.
- Bei auf `inotify` basierender Überwachung sind Netzwerkdateisysteme ein blinder Fleck, da Änderungen aus der Ferne nicht gemeldet werden.

Beispiel für Baseline und Verifizierung mit AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Beispiel für eine auf Persistenzpfade von Angreifern ausgerichtete `osquery`-FIM-Konfiguration:<sup>[[1]](#references)</sup>
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
Wenn du **Prozesszuordnung** statt lediglich Änderungen auf Pfadebene benötigst, bevorzuge audit-gestützte Telemetrie wie `osquery` `process_file_events` oder den Wazuh-`whodata`-Modus.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Unter Windows ist FIM besonders leistungsfähig, wenn du **Änderungsjournale** mit **high-signal Prozess-/Dateitelemetrie** kombinierst:<sup>[[6]](#references)[[7]](#references)</sup>

- Das **NTFS USN Journal** liefert ein persistentes volumenbezogenes Protokoll von Dateiänderungen.
- **Sysmon Event ID 11** ist nützlich für die Erkennung von Dateierstellung und -überschreibung.
- **Sysmon Event ID 2** hilft bei der Erkennung von **Timestomping**.
- **Sysmon Event ID 15** ist nützlich für **benannte alternative Datenströme (ADS)** wie `Zone.Identifier` oder versteckte Payload-Streams.

Schnelle USN-Triagebeispiele:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weiterführende Anti-Forensic-Ideen zur **Manipulation von Zeitstempeln**, zum **ADS-Missbrauch** und zum **USN-Tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container-FIM übersieht häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` kombiniert das Container-Dateisystem schreibgeschützte Image-`lowerdir`-Layer mit einem beschreibbaren **oberen Layer** (`upperdir`/`diff`), und Schreibvorgänge in Image-Dateien werden in diesen oberen Layer kopiert.<sup>[[8]](#references)</sup> Daher:

- Die Überwachung ausschließlich von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen übersehen, nachdem der Container neu erstellt wurde.
- Die Überwachung des **Host-Pfads**, der den beschreibbaren Layer unterstützt, oder des relevanten bind-gemounteten Volumes ist häufig nützlicher.
- FIM auf Image-Layern unterscheidet sich von FIM auf dem Dateisystem des laufenden Containers.

## Angreiferorientierte Hunting-Hinweise

- Verfolge **Servicedefinitionen** und **Task-Scheduler** genauso sorgfältig wie Binaries. Angreifer erlangen häufig Persistenz, indem sie eine Unit-Datei, einen Cron-Eintrag oder eine Task-XML-Datei ändern, statt `/bin/sshd` zu patchen.
- Ein Content-Hash allein ist unzureichend. Viele Compromises zeigen sich zuerst durch **Abweichungen bei Besitzerrechten, Modi, xattrs oder ACLs**.
- Wenn du eine ausgereifte Intrusion vermutest, führe beides durch: **Echtzeit-FIM** für aktuelle Aktivitäten und einen **Vergleich mit einer Cold Baseline** von vertrauenswürdigen Medien.
- Wenn der Angreifer Root- oder Kernel-Ausführung besitzt, betrachte den FIM-Agenten und dessen Datenbank als nicht vertrauenswürdig. Speichere Logs und Baselines nach Möglichkeit remote oder auf schreibgeschützten Medien.<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Dateiintegritätsüberwachung mit osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux nachverfolgen: Ein Anwendungsfall für die Dateiintegritätsüberwachung (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh-Dateiintegritätsüberwachung (Syscheck- und Whodata-Modus)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE-Handbuch Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7)-Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS-Speichertreiber](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Erweiterte Wazuh-FIM-Einstellungen](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
