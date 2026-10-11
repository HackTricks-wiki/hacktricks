# Prozesse, Crontab, Systemd und D-Bus

{{#include ../../banners/hacktricks-training.md}}

Geplante Jobs und Interprozesskommunikation können Code mit anderen Berechtigungen als denen des aufrufenden Prozesses starten. Prüfe vor dem Testen den Besitzer, den Befehl und die beschreibbaren Eingaben eines Dienstes oder Jobs.

- [Prozessaufzählung und Dienstpfade](process-enumeration-and-service-paths.md) behandelt Prozessbäume, Laufzeitdateien und systemd-Ausführungsketten.
- [Cron-Jobs und systemd-Timer](cron-and-systemd-timers.md) behandelt das Auffinden geplanter Aufgaben und beschreibbare Eingaben.
- [D-Bus-Aufzählung und Privilegieneskalation durch Command Injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) behandelt den Nachrichtenbus und Methoden privilegierter Dienste.
- [Auszuführende Payloads](payloads-to-execute.md) sammelt Payloads, die verwendet werden können, wenn ein Ausführungspfad identifiziert wurde.

Für eine umfassendere Prüfung von Cron-Jobs und systemd-Diensten verwende die [Linux-Checkliste zur Privilegieneskalation](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
