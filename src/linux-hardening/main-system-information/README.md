# Informations principales sur le système

{{#include ../../banners/hacktricks-training.md}}

Inspectez le noyau, le système de fichiers, les outils privilégiés et les voies d’évasion disponibles sur l’hôte avant de choisir une technique d’escalade locale. La [checklist d’escalade de privilèges](linux-privilege-escalation-checklist.md) fournit un ordre d’opérations concis.

- [Évaluation des vulnérabilités du noyau et exposition à l’exécution](kernel-vulnerability-assessment.md) vérifie l’applicabilité aux builds, l’accessibilité et les mesures d’atténuation actives.
- [Modules du noyau et abus de modprobe](kernel-modules-and-modprobe.md) traite du chargement de modules et de l’exposition des chemins des outils auxiliaires.
- [Abus des commandes sudo](sudo-command-abuse.md) examine comment les commandes déléguées peuvent franchir les limites de privilèges.
- [Liens symboliques, liens physiques et descripteurs de fichiers](filesystem-links-and-file-descriptors.md) traite de la redirection de chemins et des fichiers hérités ou supprimés mais encore ouverts.
- [Système de fichiers, inodes et récupération](filesystem-inodes-and-recovery.md) explique les comportements du système de fichiers utiles lors d’une investigation.
- [Checklist : escalade de privilèges Linux](linux-privilege-escalation-checklist.md) répertorie les vérifications de l’hôte et renvoie vers des ressources plus détaillées.
- [Évasion des jails](escaping-from-limited-bash.md) traite des shells limités et des environnements restreints.
- [Documentation sur le noyau, LPE et CVE](kernel-lpe-cves/README.md) regroupe des analyses ciblées sur l’escalade locale de privilèges et les vulnérabilités.
{{#include ../../banners/hacktricks-training.md}}
