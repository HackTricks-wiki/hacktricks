# Renforcement de Linux

{{#include ../banners/hacktricks-training.md}}

Utilisez cette section pour examiner les hôtes Linux, comprendre les limites de privilèges et vérifier les contrôles qui restreignent l’accès local. Commencez par les [bases de Linux](linux-basics/README.md) et la [liste de vérification de l’élévation de privilèges](main-system-information/linux-privilege-escalation-checklist.md) pour une évaluation générale, puis consultez le sujet pertinent ci-dessous.

- [Bases de Linux](linux-basics/README.md) : méthodologie d’élévation de privilèges, commandes utiles, variables d’environnement et contournements de restrictions.
- [Informations système principales](main-system-information/README.md) : noyau, modules, sudo, comportement du système de fichiers, jails et liste de vérification de l’élévation de privilèges.
- [Informations utilisateur](user-information/README.md) : identités Linux, groupes, transfert de l’agent SSH et intégration à Active Directory.
- [Fichiers intéressants et permissions](interesting-files-permissions/README.md) : chemins accessibles en écriture, capabilities, comportement SUID, NFS, expansion des jokers et SELinux.
- [Informations réseau](network-information/README.md) : services locaux, sockets et exemples d’exploitation liés au réseau.
- [Informations sur les logiciels](software-information/README.md) : modules d’authentification et surfaces d’attaque spécifiques aux applications.
- [Processus, crontab, systemd et D-Bus](processes-crontab-systemd-dbus/README.md) : exécution planifiée et communication interprocessus.
- [Conteneurs et espaces de noms](containers-namespaces/README.md) : moteurs d’exécution, limites d’isolation et renforcement des conteneurs.
- [Post-exploitation](post-exploitation/README.md) : recherche d’identifiants, persistance et techniques complémentaires au niveau de l’hôte.
{{#include ../banners/hacktricks-training.md}}
