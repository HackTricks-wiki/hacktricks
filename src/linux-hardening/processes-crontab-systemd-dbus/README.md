# Procesi, Crontab, Systemd i D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zakazani poslovi i međuprocesna komunikacija mogu pokretati kod sa privilegijama koje se razlikuju od privilegija pozivaoca. Pre testiranja proverite vlasnika, komandu i ulaze u koje može da se upisuje za servis ili posao.

- [Enumeracija procesa i putanje servisa](process-enumeration-and-service-paths.md) obrađuje stabla procesa, izvršne datoteke i lance izvršavanja systemd-a.
- [Cron poslovi i systemd tajmeri](cron-and-systemd-timers.md) obrađuje otkrivanje zakazanih zadataka i ulaze u koje može da se upisuje.
- [Enumeracija D-Bus-a i eskalacija privilegija ubacivanjem komandi](d-bus-enumeration-and-command-injection-privilege-escalation.md) obrađuje magistralu poruka i metode privilegovanih servisa.
- [Payload-i za izvršavanje](payloads-to-execute.md) sadrži payload-e koji mogu da se koriste kada je identifikovana putanja izvršavanja.

Za detaljniji pregled cron poslova i systemd servisa koristite [kontrolnu listu za eskalaciju privilegija na Linux-u](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
