# Prozesse, Crontab, Systemd und D-Bus

{{#include ../../banners/hacktricks-training.md}}

Geplante Jobs und Interprozesskommunikation können Code mit anderen Berechtigungen als denen des Aufrufers starten. Prüfe Besitzer, Befehl und beschreibbare Eingaben eines Dienstes oder Jobs, bevor du ihn testest.

- [Prozesse und Dienstpfade aufzählen](process-enumeration-and-service-paths.md) behandelt Prozessbäume, Laufzeitdateien und Systemd-Ausführungsketten.
- [Cron-Jobs und Systemd-Timer](cron-and-systemd-timers.md) behandelt das Auffinden geplanter Aufgaben und beschreibbare Eingaben.
- [D-Bus-Aufzählung und Privilegieneskalation durch Command Injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) behandelt den Nachrichtenbus und privilegierte Dienstmethoden.
- [Payloads zur Ausführung](payloads-to-execute.md) enthält Payloads, die verwendet werden können, sobald ein Ausführungspfad identifiziert wurde.

Für eine umfassendere Überprüfung von Cron-Jobs und Systemd-Diensten verwende die [Linux-Checkliste zur Privilegieneskalation](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
