# Informations sur les utilisateurs

{{#include ../../banners/hacktricks-training.md}}

L’identité de l’utilisateur, l’appartenance aux groupes et les identifiants délégués déterminent les ressources auxquelles un processus peut accéder. Vérifiez l’identité effective et les groupes supplémentaires avant d’examiner les chemins d’accès ci-dessous.

- [Utilisateurs, sessions et artefacts d’identifiants](user-and-session-triage.md) traite de l’énumération des comptes, des connexions actives, des artefacts SSH et shell, ainsi que des magasins d’identifiants.
- [UID réels, effectifs et sauvegardés](euid-ruid-suid.md) explique les changements d’identité liés aux programmes SUID et à l’exécution des processus.
- [Groupes intéressants pour l’élévation de privilèges sous Linux](interesting-groups-linux-pe/README.md) traite des accès accordés par les groupes, notamment LXD/LXC.
- [Exploitation de l’agent de transfert SSH](ssh-forward-agent-exploitation.md) examine les risques liés aux identifiants SSH transférés.
- [Active Directory sous Linux](linux-active-directory.md) traite des hôtes intégrés à un environnement AD.

{{#include ../../banners/hacktricks-training.md}}
