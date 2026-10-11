# Prozesse, Crontab, Systemd und D-Bus

{{#include ../../banners/hacktricks-training.md}}

Geplante Jobs und Interprozesskommunikation können Code mit anderen Berechtigungen als denen des aufrufenden Prozesses starten. Prüfe Besitzer, Befehl und beschreibbare Eingaben eines Dienstes oder Jobs, bevor du ihn testest.

- [Prozesse und Dienstpfade auflisten](process-enumeration-and-service-paths.md) behandelt Prozessbäume, Laufzeitdateien und systemd-Ausführungsketten.
- [Cron-Jobs und systemd-Timer](cron-and-systemd-timers.md) behandelt das Auffinden geplanter Aufgaben und beschreibbarer Eingaben.
- [D-Bus-Auflistung und Rechteausweitung durch Command Injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) behandelt den Nachrichtenbus und privilegierte Dienstmethoden.
- [Auszuführende Payloads](payloads-to-execute.md) enthält Payloads, die verwendet werden können, sobald ein Ausführungspfad identifiziert wurde.

Für eine umfassendere Überprüfung von Cron-Jobs und systemd-Diensten verwende die [Linux-Checkliste zur Rechteausweitung](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
