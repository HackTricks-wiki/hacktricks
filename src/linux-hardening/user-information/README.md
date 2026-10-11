# Informations sur les utilisateurs

{{#include ../../banners/hacktricks-training.md}}

L’identité d’un utilisateur, son appartenance à des groupes et ses identifiants délégués déterminent les ressources auxquelles un processus peut accéder. Vérifiez l’identité effective et les groupes supplémentaires avant d’examiner les chemins d’accès ci-dessous.

- [Utilisateurs, sessions et artefacts d’identifiants](user-and-session-triage.md) couvre l’énumération des comptes, les connexions actives, les artefacts SSH et shell, ainsi que les magasins d’identifiants.
- [Identifiants utilisateur réels, effectifs et sauvegardés](euid-ruid-suid.md) explique les changements d’identité liés aux programmes SUID et à l’exécution des processus.
- [Groupes intéressants pour l’élévation de privilèges sous Linux](interesting-groups-linux-pe/README.md) couvre les accès accordés par les groupes, notamment LXD/LXC.
- [Exploitation de l’agent de transfert SSH](ssh-forward-agent-exploitation.md) examine les risques liés aux identifiants SSH transférés.
- [Active Directory sous Linux](linux-active-directory.md) couvre les hôtes joints à un environnement AD.

{{#include ../../banners/hacktricks-training.md}}
