# Processi, Crontab, Systemd e D-Bus

{{#include ../../banners/hacktricks-training.md}}

I job pianificati e la comunicazione tra processi possono avviare codice con privilegi diversi da quelli del chiamante. Prima di eseguire test, controlla il proprietario, il comando e gli input scrivibili di un servizio o di un job.

- [Enumerazione dei processi e percorsi dei servizi](process-enumeration-and-service-paths.md) tratta gli alberi dei processi, i file di runtime e le catene di esecuzione di systemd.
- [Cron jobs e timer di systemd](cron-and-systemd-timers.md) tratta l’individuazione delle attività pianificate e degli input scrivibili.
- [Enumerazione di D-Bus e privilege escalation tramite command injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) tratta il bus dei messaggi e i metodi dei servizi privilegiati.
- [Payload da eseguire](payloads-to-execute.md) raccoglie payload utilizzabili quando è stato individuato un percorso di esecuzione.

Per un’analisi più ampia dei cron jobs e dei servizi systemd, consulta la [checklist di privilege escalation su Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
