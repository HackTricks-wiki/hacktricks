# Informations système principales

{{#include ../../banners/hacktricks-training.md}}

Inspectez le noyau de l’hôte, le système de fichiers, les outils privilégiés et les voies d’évasion disponibles avant de choisir une technique d’escalade locale. La [liste de contrôle de l’escalade de privilèges](linux-privilege-escalation-checklist.md) propose un ordre d’opérations concis.

- [Évaluation des vulnérabilités du noyau et exposition à l’exécution](kernel-vulnerability-assessment.md) vérifie l’applicabilité des builds, l’accessibilité et les mesures d’atténuation actives.
- [Modules du noyau et détournement de modprobe](kernel-modules-and-modprobe.md) traite du chargement des modules et de l’exposition des chemins des programmes auxiliaires.
- [Détournement de commandes Sudo](sudo-command-abuse.md) examine comment les commandes déléguées peuvent franchir les limites de privilèges.
- [Liens symboliques, liens physiques et descripteurs de fichiers](filesystem-links-and-file-descriptors.md) traite de la redirection de chemins et des fichiers hérités ou ouverts puis supprimés.
- [Système de fichiers, inodes et récupération](filesystem-inodes-and-recovery.md) explique les comportements du système de fichiers utiles lors d’une enquête.
- [Liste de contrôle : escalade de privilèges Linux](linux-privilege-escalation-checklist.md) répertorie les vérifications de l’hôte et renvoie vers des ressources plus détaillées.
- [Échapper aux jails](escaping-from-limited-bash.md) traite des shells limités et des environnements contraints.
- [Ressources sur le noyau, les LPE et les CVE](kernel-lpe-cves/README.md) regroupe des analyses ciblées sur l’escalade locale de privilèges et les vulnérabilités.
{{#include ../../banners/hacktricks-training.md}}
