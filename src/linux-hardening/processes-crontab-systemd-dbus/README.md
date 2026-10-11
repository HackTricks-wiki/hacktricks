# Procesy, Crontab, Systemd i D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zaplanowane zadania i komunikacja międzyprocesowa mogą uruchamiać kod z uprawnieniami innymi niż uprawnienia wywołującego. Przed testowaniem sprawdź właściciela, polecenie i zapisywalne dane wejściowe usługi lub zadania.

- [Wyliczanie procesów i ścieżki usług](process-enumeration-and-service-paths.md) omawia drzewa procesów, pliki czasu działania i łańcuchy wykonywania systemd.
- [Zadania cron i timery systemd](cron-and-systemd-timers.md) omawia wykrywanie zaplanowanych zadań i zapisywalne dane wejściowe.
- [Wyliczanie D-Bus i eskalacja uprawnień przez wstrzyknięcie poleceń](d-bus-enumeration-and-command-injection-privilege-escalation.md) omawia magistralę komunikatów i metody uprzywilejowanych usług.
- [Payloady do wykonania](payloads-to-execute.md) zawiera payloady, których można użyć po zidentyfikowaniu ścieżki wykonania.

Aby dokładniej przeanalizować zadania cron i usługi systemd, skorzystaj z [listy kontrolnej eskalacji uprawnień w systemie Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
