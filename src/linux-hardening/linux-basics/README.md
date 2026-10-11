# Bases de Linux

{{#include ../../banners/hacktricks-training.md}}

C’est le point de départ pour l’évaluation d’un hôte Linux. Ces pages couvrent un processus général de privilege escalation, des commandes pratiques, les variables d’environnement et les restrictions courantes qui déterminent ce qui peut être exécuté sur un hôte.

- [Privilege escalation sous Linux](linux-privilege-escalation/README.md) présente les étapes d’énumération et les pistes potentielles d’escalade locale. Pour une liste de tâches plus courte, consultez la [liste de vérification de privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Démarrage du shell, alias et historique](shell-startup-aliases-and-history.md) explique la résolution des commandes, l’exécution des fichiers de démarrage et les indices présents dans l’historique.
- [Commandes Linux utiles](useful-linux-commands.md) rassemble des commandes pour examiner les fichiers, les processus, les services et l’environnement.
- [Variables d’environnement Linux](linux-environment-variables.md) explique comment les valeurs d’environnement influent sur l’exécution et où des valeurs sensibles peuvent apparaître.
- [Contourner les restrictions Linux](bypass-linux-restrictions/README.md) traite des shells et environnements d’exécution restreints, notamment des protections du système de fichiers, de `noexec` et des systèmes distroless.

## Exploitation native de binaires

Lorsqu’une évaluation met au jour un exécutable Linux vulnérable, consultez les ressources pertinentes de Binary Exploitation :

- [Format ELF et comportement du chargeur](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) et [protections des binaires et contournements](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) expliquent l’organisation des exécutables et leurs mécanismes de protection.
- [Exploitation de la pile](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) et [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) traitent des attaques par détournement du flux de contrôle.
- [Exploitation du heap de libc](../../binary-exploitation/libc-heap/README.md) et [chaînes de format](../../binary-exploitation/format-strings/README.md) traitent d’autres formes courantes de corruption mémoire.

Des études de cas spécifiques au kernel sont accessibles depuis [les ressources Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
