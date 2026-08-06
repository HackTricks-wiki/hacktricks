# Checklist - Élévation de privilèges locale sous Windows

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher les vecteurs d’élévation de privilèges locale sous Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir les [**informations système**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des [**exploits du kernel à l’aide de scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Utiliser **Google pour rechercher** des **exploits du kernel**
- [ ] Utiliser **searchsploit pour rechercher** des **exploits du kernel**
- [ ] Informations intéressantes dans les [**variables d’environnement**](windows-local-privilege-escalation/index.html#environment) ?
- [ ] Mots de passe dans l’[**historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) ?
- [ ] Informations intéressantes dans les [**paramètres Internet**](windows-local-privilege-escalation/index.html#internet-settings) ?
- [ ] [**Lecteurs**](windows-local-privilege-escalation/index.html#drives) ?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus) ?
- [ ] [**Auto-updaters d’agents tiers / abus d’IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) ?

### [Énumération de la journalisation/de l’AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres d’[**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)et de [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)est actif
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) ?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credentials mises en cache**](windows-local-privilege-escalation/index.html#cached-credentials) ?
- [ ] Vérifier la présence d’un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Stratégie AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) ?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / élévation silencieuse via UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md) ?<sup>[[1]](#references)</sup>
- [ ] [**Propagation du registre d’accessibilité du Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md) ?<sup>[[2]](#references)</sup>
- [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les [**privilèges**](windows-local-privilege-escalation/index.html#users-and-groups) de l’utilisateur **actuel**
- [ ] Êtes-vous [**membre d’un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups) ?
- [ ] Vérifier si l’un de ces tokens est activé [ici](windows-local-privilege-escalation/index.html#token-manipulation) : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Vérifier si vous disposez de [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) pour lire les volumes bruts et contourner les ACL de fichiers
- [ ] [**Sessions utilisateur**](windows-local-privilege-escalation/index.html#logged-users-sessions) ?
- [ ] Vérifier les [**répertoires personnels des utilisateurs**](windows-local-privilege-escalation/index.html#home-folders) (accès ?)
- [ ] Vérifier la [**stratégie de mots de passe**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que contient le [**presse-papiers**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les [**informations** **réseau** **actuelles**](windows-local-privilege-escalation/index.html#network)
- [ ] Vérifier les **services locaux cachés** restreints depuis l’extérieur

### [Processus en cours d’exécution](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permissions sur les fichiers et dossiers**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) des binaires de processus
- [ ] [**Recherche de mots de passe en mémoire**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des credentials avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Pouvez-vous **modifier** le **binaire** **exécuté** par un **service** ?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Pouvez-vous **modifier** le **registre** d’un **service** ?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Pouvez-vous tirer parti du **path** d’un binaire de **service non quoté** ?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers : énumérer et déclencher des services privilégiés](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permissions d’écriture** sur les [**applications installées**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applications au démarrage**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers** vulnérables](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier du PATH** ?
- [ ] Existe-t-il un binaire de service connu qui **tente de charger une DLL inexistante** ?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
- [ ] Examiner en particulier les services réseau en écoute sur localhost (127.0.0.1)

### [Credentials Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Des credentials [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que vous pourriez utiliser ?
- [ ] [**Credentials DPAPI**](windows-local-privilege-escalation/index.html#dpapi) intéressants ?
- [ ] Mots de passe des [**réseaux Wifi**](windows-local-privilege-escalation/index.html#wifi) enregistrés ?
- [ ] Informations intéressantes dans les [**connexions RDP enregistrées**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ?
- [ ] Mots de passe dans les [**commandes récemment exécutées**](windows-local-privilege-escalation/index.html#recently-run-commands) ?
- [ ] Mots de passe du [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) ?
- [ ] [**AppCmd.exe existe**](windows-local-privilege-escalation/index.html#appcmd-exe) ? Credentials ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) ? DLL Side Loading ?

### [Fichiers et registre (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty :** [**Credentials**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**clés hôtes SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) ?
- [ ] Mots de passe dans les [**fichiers unattended**](windows-local-privilege-escalation/index.html#unattended-files) ?
- [ ] Une sauvegarde [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) ?
- [ ] Si [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) est présent, essayer de lire les volumes bruts pour récupérer `SAM`, `SYSTEM`, le matériel DPAPI et `MachineKeys`
- [ ] [**Credentials Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials) ?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ?
- [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) ?
- [ ] Mot de passe dans le [**fichier de configuration Web IIS**](windows-local-privilege-escalation/index.html#iis-web-config) ?
- [ ] Informations intéressantes dans les [**logs** **web**](windows-local-privilege-escalation/index.html#logs) ?
- [ ] Voulez-vous [**demander les credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l’utilisateur ?
- [ ] [**Fichiers intéressants dans la Corbeille**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ?
- [ ] Autres [**clés de registre contenant des credentials**](windows-local-privilege-escalation/index.html#inside-the-registry) ?
- [ ] Dans les [**données du navigateur**](windows-local-privilege-escalation/index.html#browsers-history) (bases de données, historique, favoris, ...) ?
- [ ] [**Recherche générique de mots de passe**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Outils**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour rechercher automatiquement les mots de passe

### [Gestionnaires leaked](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès au gestionnaire d’un processus exécuté par un administrateur ?

### [Impersonation de client de pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifier si vous pouvez en abuser

## Références

- [1] [Project Zero - Contourner Administrator Protection en abusant de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
