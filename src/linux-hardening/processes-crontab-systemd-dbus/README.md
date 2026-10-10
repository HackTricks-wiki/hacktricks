# Procesy, Crontab, Systemd i D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zaplanowane zadania i komunikacja międzyprocesowa mogą uruchamiać kod z uprawnieniami innymi niż uprawnienia wywołującego. Przed testowaniem sprawdź właściciela, polecenie oraz zapisywalne dane wejściowe usługi lub zadania.

- [Wyliczanie procesów i ścieżki usług](process-enumeration-and-service-paths.md) opisuje drzewa procesów, pliki środowiska uruchomieniowego i łańcuchy wykonywania systemd.
- [Zadania Cron i timery systemd](cron-and-systemd-timers.md) opisuje wykrywanie zadań zaplanowanych i zapisywalne dane wejściowe.
- [Wyliczanie D-Bus i eskalacja uprawnień przez wstrzyknięcie poleceń](d-bus-enumeration-and-command-injection-privilege-escalation.md) opisuje magistralę komunikatów i metody uprzywilejowanych usług.
- [Payloads do wykonania](payloads-to-execute.md) zawiera payloady, których można użyć po zidentyfikowaniu ścieżki wykonania.

Aby szerzej przeanalizować zadania Cron i usługi systemd, skorzystaj z [listy kontrolnej eskalacji uprawnień w Linuksie](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
