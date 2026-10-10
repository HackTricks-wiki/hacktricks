# Processus, Crontab, Systemd et D-Bus

{{#include ../../banners/hacktricks-training.md}}

Les tâches planifiées et la communication interprocessus peuvent lancer du code avec des privilèges différents de ceux de l’appelant. Avant de tester un service ou une tâche, examinez son propriétaire, sa commande et les entrées modifiables.

- [Énumération des processus et chemins des services](process-enumeration-and-service-paths.md) couvre les arbres de processus, les fichiers d’exécution et les chaînes d’exécution de systemd.
- [Tâches Cron et minuteries systemd](cron-and-systemd-timers.md) couvre la découverte des tâches planifiées et des entrées modifiables.
- [Énumération de D-Bus et escalade de privilèges par injection de commandes](d-bus-enumeration-and-command-injection-privilege-escalation.md) couvre le bus de messages et les méthodes des services privilégiés.
- [Payloads à exécuter](payloads-to-execute.md) rassemble des payloads utilisables lorsqu’un chemin d’exécution a été identifié.

Pour examiner plus largement les tâches Cron et les services systemd, consultez la [liste de vérification de l’escalade de privilèges Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
