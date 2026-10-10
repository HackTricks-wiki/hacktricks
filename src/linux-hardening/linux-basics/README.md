# Bases de Linux

{{#include ../../banners/hacktricks-training.md}}

Voici le point de départ pour évaluer un hôte Linux. Les pages couvrent un processus général d’escalade de privilèges, des commandes pratiques, les variables d’environnement et les restrictions courantes qui affectent les programmes pouvant être exécutés sur un hôte.

- [Escalade de privilèges Linux](linux-privilege-escalation/README.md) présente les étapes d’énumération et les chemins d’escalade locale potentiels. Pour une liste de tâches plus courte, consultez la [checklist d’escalade de privilèges](../main-system-information/linux-privilege-escalation-checklist.md).
- [Démarrage du shell, alias et historique](shell-startup-aliases-and-history.md) explique la résolution des commandes, l’exécution des fichiers de démarrage et les indices présents dans l’historique.
- [Commandes Linux utiles](useful-linux-commands.md) rassemble des commandes permettant d’inspecter les fichiers, les processus, les services et l’environnement.
- [Variables d’environnement Linux](linux-environment-variables.md) explique comment les valeurs d’environnement affectent l’exécution et où des valeurs sensibles peuvent apparaître.
- [Contourner les restrictions Linux](bypass-linux-restrictions/README.md) couvre les shells restreints et les environnements d’exécution, notamment les protections du système de fichiers, `noexec` et les systèmes distroless.

## Exploitation binaire native

Lorsqu’une évaluation révèle un exécutable Linux vulnérable, consultez les ressources pertinentes sur l’exploitation binaire :

- [Format ELF et comportement du chargeur](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) et [protections binaires et contournements](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) expliquent la structure de l’exécutable et les mesures d’atténuation.
- [Exploitation de la pile](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) et [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) couvrent les attaques par détournement du flux de contrôle.
- [Exploitation du heap de Libc](../../binary-exploitation/libc-heap/README.md) et [format strings](../../binary-exploitation/format-strings/README.md) couvrent d’autres scénarios courants de corruption mémoire.

Des études de cas spécifiques au kernel sont liées depuis les [ressources Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
