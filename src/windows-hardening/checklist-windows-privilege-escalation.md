# Checklist - Élévation de privilèges Windows locale

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher les vecteurs d'élévation de privilèges Windows locale :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir les [**informations système**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des [**exploits du kernel à l'aide de scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Utiliser **Google pour rechercher** des **exploits du kernel**
- [ ] Utiliser **searchsploit pour rechercher** des **exploits du kernel**
- [ ] Des informations intéressantes dans les [**env vars**](windows-local-privilege-escalation/index.html#environment) ?
- [ ] Des mots de passe dans l'[**historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) ?
- [ ] Des informations intéressantes dans les [**paramètres Internet**](windows-local-privilege-escalation/index.html#internet-settings) ?
- [ ] Des [**lecteurs**](windows-local-privilege-escalation/index.html#drives) ?
- [ ] Un [**exploit WSUS**](windows-local-privilege-escalation/index.html#wsus) ?
- [ ] [**Auto-updaters d'agents tiers / abus d'IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) ?

### [Énumération de la journalisation/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)et [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)est actif
- [ ] [**Protection LSA**](windows-local-privilege-escalation/index.html#lsa-protection) ?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Identifiants mis en cache**](windows-local-privilege-escalation/index.html#cached-credentials) ?
- [ ] Vérifier si un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) est présent
- [ ] [**Stratégie AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) ?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Protection de l'administrateur / élévation silencieuse UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md) ?<sup>[[1]](#references)</sup>
- [ ] [**Propagation du registre d'accessibilité du Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md) ?<sup>[[2]](#references)</sup>
- [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les [**privilèges**](windows-local-privilege-escalation/index.html#users-and-groups) de l'utilisateur **actuel**
- [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups) ?
- [ ] Vérifier si l'un de ces tokens est activé [](windows-local-privilege-escalation/index.html#token-manipulation) : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Vérifier si vous avez [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) pour lire les volumes bruts et contourner les ACL des fichiers
- [ ] [**Sessions utilisateur**](windows-local-privilege-escalation/index.html#logged-users-sessions) ?
- [ ] Vérifier les[ **répertoires personnels des utilisateurs**](windows-local-privilege-escalation/index.html#home-folders) (accès ?)
- [ ] Vérifier la [**stratégie de mots de passe**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que contient[ **le presse-papiers**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les **informations** **réseau** [**actuelles**](windows-local-privilege-escalation/index.html#network)
- [ ] Vérifier les **services locaux cachés** restreints depuis l'extérieur

### [Processus en cours d'exécution](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permissions des fichiers et dossiers**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) des binaires des processus
- [ ] [**Recherche de mots de passe en mémoire**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des identifiants avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Pouvez-vous **modifier** le **binaire** **exécuté** par un **service** ?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Pouvez-vous **modifier** le **registre** d'un **service** ?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Pouvez-vous tirer parti d'un **chemin** de binaire de **service non quoté** ?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Déclencheurs de service : énumérer et déclencher des services privilégiés](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permissions d'écriture** sur les [**applications installées**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applications au démarrage**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Pilotes**](windows-local-privilege-escalation/index.html#drivers) **vulnérables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier à l'intérieur de PATH** ?
- [ ] Existe-t-il un binaire de service connu qui **essaie de charger une DLL inexistante** ?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
- [ ] Examiner particulièrement les services réseau en écoute sur localhost (127.0.0.1)

### [Identifiants Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Identifiants [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Des identifiants de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que vous pourriez utiliser ?
- [ ] Des [**identifiants DPAPI**](windows-local-privilege-escalation/index.html#dpapi) intéressants ?
- [ ] Mots de passe des [**réseaux Wifi**](windows-local-privilege-escalation/index.html#wifi) enregistrés ?
- [ ] Des informations intéressantes dans les [**connexions RDP enregistrées**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ?
- [ ] Des mots de passe dans les [**commandes récemment exécutées**](windows-local-privilege-escalation/index.html#recently-run-commands) ?
- [ ] Mots de passe du [**Gestionnaire d'identifiants Remote Desktop**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) ?
- [ ] [**AppCmd.exe existe**](windows-local-privilege-escalation/index.html#appcmd-exe) ? Des identifiants ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) ? DLL Side Loading ?

### [Fichiers et registre (identifiants)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty :** [**identifiants**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**clés d'hôte SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) ?
- [ ] Des mots de passe dans les [**fichiers unattended**](windows-local-privilege-escalation/index.html#unattended-files) ?
- [ ] Une sauvegarde [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) ?
- [ ] Si [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) est présent, essayer de lire les volumes bruts pour rechercher `SAM`, `SYSTEM`, le matériel DPAPI et `MachineKeys`
- [ ] Des [**identifiants Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials) ?
- [ ] Un fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ?
- [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) ?
- [ ] Un mot de passe dans le [**fichier de configuration Web IIS**](windows-local-privilege-escalation/index.html#iis-web-config) ?
- [ ] Des informations intéressantes dans les [**logs** **Web**](windows-local-privilege-escalation/index.html#logs) ?
- [ ] Voulez-vous [**demander des identifiants**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l'utilisateur ?
- [ ] Des [**fichiers intéressants dans la Corbeille**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ?
- [ ] D'autres [**clés de registre contenant des identifiants**](windows-local-privilege-escalation/index.html#inside-the-registry) ?
- [ ] Dans les [**données du navigateur**](windows-local-privilege-escalation/index.html#browsers-history) (bases de données, historique, favoris, ...) ?
- [ ] [**Recherche générique de mots de passe**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Outils**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour rechercher automatiquement les mots de passe

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès à un handler d'un processus exécuté par un administrateur ?

### [Impersonation d'un client de named pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifier si vous pouvez en abuser

## References

- [1] [Project Zero - Contourner la protection de l'administrateur en abusant de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
