# Notions de base de Linux

{{#include ../../banners/hacktricks-training.md}}

C’est le point de départ pour évaluer un hôte Linux. Ces pages présentent un processus général d’élévation de privilèges, des commandes pratiques, des variables d’environnement et des restrictions courantes qui influent sur ce qui peut être exécuté sur un hôte.

- [Élévation de privilèges sous Linux](linux-privilege-escalation/README.md) décrit les étapes d’énumération et les pistes potentielles d’élévation locale. Pour une liste de tâches plus courte, consultez la [liste de vérification pour l’élévation de privilèges](../main-system-information/linux-privilege-escalation-checklist.md).
- [Démarrage du shell, alias et historique](shell-startup-aliases-and-history.md) explique la résolution des commandes, l’exécution des fichiers de démarrage et les indices présents dans l’historique.
- [Commandes Linux utiles](useful-linux-commands.md) regroupe des commandes pour examiner les fichiers, les processus, les services et l’environnement.
- [Variables d’environnement Linux](linux-environment-variables.md) explique comment les valeurs d’environnement influent sur l’exécution et où des valeurs sensibles peuvent apparaître.
- [Contourner les restrictions de Linux](bypass-linux-restrictions/README.md) traite des shells et des environnements d’exécution restreints, notamment des protections du système de fichiers, de `noexec` et des systèmes distroless.

## Exploitation native de binaires

Lorsqu’une évaluation met au jour un exécutable Linux vulnérable, consultez les ressources pertinentes de Binary Exploitation :

- [Format ELF et comportement du chargeur](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) et [protections des binaires et contournements](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) expliquent la disposition de l’exécutable et ses mesures d’atténuation.
- [Exploitation de la pile](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) et [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) traitent des attaques visant le flot de contrôle.
- [Exploitation du tas libc](../../binary-exploitation/libc-heap/README.md) et [chaînes de format](../../binary-exploitation/format-strings/README.md) traitent d’autres vecteurs courants de corruption de mémoire.

Des études de cas propres au kernel sont accessibles depuis les ressources [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
