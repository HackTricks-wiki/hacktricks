# Processus, Crontab, Systemd et D-Bus

{{#include ../../banners/hacktricks-training.md}}

Les tâches planifiées et la communication interprocessus peuvent lancer du code avec des privilèges différents de ceux de l’appelant. Avant tout test, vérifiez le propriétaire, la commande et les entrées modifiables en écriture d’un service ou d’une tâche.

- [Énumération des processus et chemins des services](process-enumeration-and-service-paths.md) traite des arbres de processus, des fichiers d’exécution et des chaînes d’exécution de systemd.
- [Tâches Cron et timers systemd](cron-and-systemd-timers.md) traite de la découverte des tâches planifiées et des entrées modifiables en écriture.
- [Énumération de D-Bus et élévation de privilèges par injection de commandes](d-bus-enumeration-and-command-injection-privilege-escalation.md) traite du bus de messages et des méthodes des services privilégiés.
- [Payloads à exécuter](payloads-to-execute.md) rassemble des payloads pouvant être utilisés lorsqu’un chemin d’exécution a été identifié.

Pour examiner plus largement les tâches Cron et les services systemd, consultez la [liste de vérification de l’élévation de privilèges sous Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
