# Durcissement Linux

{{#include ../banners/hacktricks-training.md}}

Utilisez cette section pour examiner les hôtes Linux, comprendre les limites de privilèges et passer en revue les contrôles qui restreignent l’accès local. Commencez par les [bases de Linux](linux-basics/README.md) et la [checklist d’élévation de privilèges](main-system-information/linux-privilege-escalation-checklist.md) pour une évaluation générale, puis consultez le sujet pertinent ci-dessous.

- [Bases de Linux](linux-basics/README.md) : méthodologie d’élévation de privilèges, commandes utiles, variables d’environnement et contournements des restrictions.
- [Informations système principales](main-system-information/README.md) : noyau, modules, sudo, comportement du système de fichiers, jails et checklist d’élévation de privilèges.
- [Informations utilisateur](user-information/README.md) : identités Linux, groupes, transfert de l’agent SSH et intégration d’Active Directory.
- [Fichiers intéressants et permissions](interesting-files-permissions/README.md) : chemins accessibles en écriture, capabilities, comportement SUID, NFS, expansion des caractères génériques et SELinux.
- [Informations réseau](network-information/README.md) : services locaux, sockets et exemples d’exploitation liés au réseau.
- [Informations logicielles](software-information/README.md) : modules d’authentification et surfaces d’attaque propres aux applications.
- [Processus, crontab, systemd et D-Bus](processes-crontab-systemd-dbus/README.md) : exécution planifiée et communication interprocessus.
- [Conteneurs et namespaces](containers-namespaces/README.md) : runtimes, limites d’isolation et durcissement des conteneurs.
- [Abus des fichiers de contrôle de politique AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive) : vérifiez si un helper privilégié peut écrire dans un fichier de contrôle AppArmor ouvert par un utilisateur local.
- [Post-exploitation](post-exploitation/README.md) : découverte d’identifiants, persistance et techniques de suivi au niveau de l’hôte.

Sur les noyaux concernés, l’ouverture d’un fichier de contrôle de politique AppArmor dans securityfs par un utilisateur non privilégié peut réussir, même si une écriture directe est refusée. Si un helper privilégié hérite de ce fichier comme stdout, son écriture peut modifier la politique chargée ; il s’agit d’une voie d’attaque locale distincte du simple fait de trouver un profil de conteneur insuffisamment restrictif. Vérifiez les correctifs du noyau et du helper fournis par le fournisseur avant de tester cette faille.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Avis technique de Qualys sur CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Base de connaissances sur la vulnérabilité CrackArmor d’Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
