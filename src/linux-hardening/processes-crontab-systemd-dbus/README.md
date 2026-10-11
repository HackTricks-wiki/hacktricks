# Procesi, Crontab, Systemd i D-Bus

{{#include ../../banners/hacktricks-training.md}}

Zakazani poslovi i međuprocesna komunikacija mogu pokrenuti kod sa privilegijama koje se razlikuju od privilegija pozivaoca. Pre testiranja proverite vlasnika, komandu i ulaze koji se mogu menjati za servis ili posao.

- [Enumeracija procesa i putanje servisa](process-enumeration-and-service-paths.md) obrađuje stabla procesa, runtime datoteke i systemd lance izvršavanja.
- [Cron poslovi i systemd tajmeri](cron-and-systemd-timers.md) obrađuje otkrivanje zakazanih zadataka i ulaze koji se mogu menjati.
- [Enumeracija D-Bus-a i eskalacija privilegija putem command injection-a](d-bus-enumeration-and-command-injection-privilege-escalation.md) obrađuje sabirnicu poruka i metode privilegovanih servisa.
- [Payloads za izvršavanje](payloads-to-execute.md) sadrži payloads koji se mogu koristiti kada se utvrdi putanja izvršavanja.

Za detaljniji pregled cron poslova i systemd servisa koristite [Linux kontrolnu listu za eskalaciju privilegija](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
