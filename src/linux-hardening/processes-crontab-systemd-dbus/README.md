# Procesi, Crontab, Systemd i D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zakazani poslovi i međuprocesna komunikacija mogu da pokrenu kod sa privilegijama koje se razlikuju od privilegija pozivaoca. Pre testiranja proverite vlasnika, komandu i ulaze koji se mogu menjati za servis ili posao.

- [Enumeracija procesa i putanje servisa](process-enumeration-and-service-paths.md) obrađuje stabla procesa, datoteke tokom rada i systemd lance izvršavanja.
- [Cron poslovi i systemd tajmeri](cron-and-systemd-timers.md) obrađuje otkrivanje zakazanih zadataka i ulaze koji se mogu menjati.
- [Enumeracija D-Bus-a i eskalacija privilegija putem command injection-a](d-bus-enumeration-and-command-injection-privilege-escalation.md) obrađuje magistralu poruka i metode privilegovanih servisa.
- [Payloads za izvršavanje](payloads-to-execute.md) sadrži payloads koji mogu da se koriste kada je utvrđena putanja izvršavanja.

Za širi pregled cron poslova i systemd servisa koristite [Linux kontrolnu listu za eskalaciju privilegija](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
