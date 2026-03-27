# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Eine Baseline besteht darin, einen Snapshot bestimmter Teile eines Systems zu erstellen, um **ihn mit einem späteren Zustand zu vergleichen und Änderungen hervorzuheben**.

Zum Beispiel kann man den Hash jeder Datei des Dateisystems berechnen und speichern, um herauszufinden, welche Dateien verändert wurden.\
Das kann auch mit erstellten Benutzerkonten, laufenden Prozessen, laufenden Services und allem anderen gemacht werden, das sich nicht (oder kaum) ändern sollte.

Eine **nützliche Baseline** speichert normalerweise mehr als nur einen Digest: Berechtigungen, Owner, Group, Timestamps, Inode, Symlink-Target, ACLs und ausgewählte erweiterte Attribute sind ebenfalls sinnvoll zu überwachen. Aus der Perspektive von Threat Hunting hilft das, **nur-Berechtigungsmanipulationen**, **atomaren Dateiersatz** und **Persistenz über geänderte service/unit-Dateien** zu erkennen, selbst wenn der Inhalts-Hash nicht als Erstes geändert wird.

### File Integrity Monitoring

File Integrity Monitoring (FIM) ist eine kritische Sicherheitstechnik, die IT-Umgebungen und Daten schützt, indem sie Änderungen an Dateien verfolgt. Es kombiniert in der Regel:

1. **Baseline-Vergleich:** Metadaten und kryptographische Checksums speichern (bevorzugt `SHA-256` oder besser) für zukünftige Vergleiche.
2. **Echtzeit-Benachrichtigungen:** OS-native Datei-Events abonnieren, um zu wissen, **welche Datei sich wann und idealerweise welcher Prozess/Benutzer angefasst hat**.
3. **Periodisches Re-Scan:** Vertrauen wiederherstellen nach Reboots, verlorenen Events, Agent-Ausfällen oder gezielter Anti-Forensik-Aktivität.

Für Threat Hunting ist FIM in der Regel nützlicher, wenn es sich auf **hochwertige Pfade** fokussiert wie:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers und bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Das Erfassungs-Backend ist entscheidend:

- **`inotify` / `fsnotify`**: einfach und verbreitet, aber Watch-Limits können erschöpft werden und einige Edge-Cases werden verpasst.
- **`auditd` / audit framework**: besser, wenn man wissen muss, **wer die Datei geändert hat** (`auid`, Prozess, pid, executable).
- **`eBPF` / `kprobes`**: neuere Optionen, die von modernen FIM-Stacks verwendet werden, um Events anzureichern und einige der operativen Probleme einfacher `inotify`-Deployments zu reduzieren.

Einige praktische Stolperfallen:

- Wenn ein Programm eine Datei **ersetzt** mit `write temp -> rename`, kann das Überwachen der Datei selbst aufhören nützlich zu sein. **Überwache das Parent-Directory**, nicht nur die Datei.
- `inotify`-basierte Collector können bei **riesigen Verzeichnisbäumen**, **Hardlink-Aktivität** oder nachdem eine **überwachte Datei gelöscht wurde** Dinge verpassen oder degradiert arbeiten.
- Sehr große rekursive Watch-Sets können stillschweigend fehlschlagen, wenn `fs.inotify.max_user_watches`, `max_user_instances` oder `max_queued_events` zu niedrig sind.
- Netzdateisysteme sind in der Regel schlechte FIM-Ziele für rauscharme Überwachung.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Beispielkonfiguration für `osquery` FIM, fokussiert auf Pfade zur Angreifer-Persistenz:
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
If you need **Prozesszuordnung** instead of only path-level changes, prefer audit-backed telemetry such as `osquery` `process_file_events` or Wazuh `whodata` mode.

### Windows

On Windows, FIM is stronger when you combine **Änderungsjournale** with **hochwertiger Prozess-/Datei-Telemetrie**:

- **NTFS USN Journal** liefert ein persistentes, volumenweites Protokoll von Dateiänderungen.
- **Sysmon Event ID 11** ist nützlich zur Erkennung von Datei-Erstellung/-Überschreibung.
- **Sysmon Event ID 2** hilft, **timestomping** zu erkennen.
- **Sysmon Event ID 15** ist nützlich für **named alternate data streams (ADS)** wie `Zone.Identifier` oder versteckte payload streams.

Schnelle USN-Triage-Beispiele:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Für weitergehende anti-forensische Ideen zu **timestamp manipulation**, **ADS abuse**, und **USN tampering** siehe [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Container

Container FIM übersieht häufig den tatsächlichen Schreibpfad. Bei Docker `overlay2` werden Änderungen in die **beschreibbare obere Schicht** (`upperdir`/`diff`) geschrieben, nicht in die schreibgeschützten Image-Layer. Daher:

- Die Überwachung nur von Pfaden **innerhalb** eines kurzlebigen Containers kann Änderungen verpassen, die nach dem Neustarten des Containers auftreten.
- Die Überwachung des **Host-Pfads**, der die beschreibbare Schicht unterstützt, oder des relevanten bind-gemounteten Volumes ist oft nützlicher.
- FIM auf Image-Layern unterscheidet sich von FIM auf dem laufenden Container-Dateisystem.

## Angreifer-orientierte Hunting-Hinweise

- Verfolge **service definitions** und **task schedulers** ebenso sorgfältig wie Binärdateien. Angreifer erreichen Persistenz oft durch Modifikation einer unit file, eines cron entry oder einer task XML statt durch das Patchen von `/bin/sshd`.
- Ein Inhalts-Hash allein reicht nicht aus. Viele Kompromittierungen zeigen sich zuerst als **owner/mode/xattr/ACL drift**.
- Wenn du einen fortgeschrittenen Einbruch vermutest, mache beides: **real-time FIM** für aktuelle Aktivität und einen **cold baseline comparison** von vertrauenswürdigen Medien.
- Wenn der Angreifer root- oder Kernel-Ausführung hat, gehe davon aus, dass der FIM-Agent, seine Datenbank und sogar die Ereignisquelle manipuliert werden können. Speichere Logs und Baselines wann immer möglich remote oder auf schreibgeschütztem Medium.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
