# Checklist - Élévation de privilèges locale sous Windows

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d’élévation de privilèges locale sous Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir les [**informations système**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des [**exploits à l’aide de scripts**](windows-local-privilege-escalation/index.html#version-exploits) pour le **kernel**
- [ ] Utiliser **Google pour rechercher** des **exploits** de kernel
- [ ] Utiliser **searchsploit pour rechercher** des **exploits** de kernel
- [ ] Informations intéressantes dans les [**variables d’environnement**](windows-local-privilege-escalation/index.html#environment) ?
- [ ] Mots de passe dans l’[**historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) ?
- [ ] Informations intéressantes dans les [**paramètres Internet**](windows-local-privilege-escalation/index.html#internet-settings) ?
- [ ] [**Lecteurs**](windows-local-privilege-escalation/index.html#drives) ?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus) ?
- [ ] [**Mise à jour automatique d’agents tiers / abus d’IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) ?

### [Énumération de la journalisation et des antivirus](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)et [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)est actif
- [ ] [**Protection LSA**](windows-local-privilege-escalation/index.html#lsa-protection) ?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Identifiants mis en cache**](windows-local-privilege-escalation/index.html#cached-credentials) ?
- [ ] Vérifier la présence d’un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Stratégie AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) ?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Protection administrateur / élévation silencieuse UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md) ?<sup>[[1]](#references)</sup>
- [ ] [**Propagation du registre d’accessibilité du Bureau sécurisé (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md) ?<sup>[[2]](#references)</sup>
- [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les [**privilèges**](windows-local-privilege-escalation/index.html#users-and-groups) de l’utilisateur **actuel**
- [ ] Êtes-vous [**membre d’un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups) ?
- [ ] Vérifier si les [privilèges suivants sont présents dans le jeton actuel](windows-local-privilege-escalation/access-tokens.md), même s’ils apparaissent comme **Disabled** : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Un privilège désactivé ne peut être activé que s’il est déjà présent dans le jeton.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Vérifier la présence de [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), un droit de maintenance des volumes. À lui seul, il ne donne pas accès en lecture brute au volume ; l’ouverture d’un disque ou d’un volume est également soumise à des exigences d’accès distinctes.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Sessions utilisateur**](windows-local-privilege-escalation/index.html#logged-users-sessions) ?
- [ ] Vérifier les [**dossiers personnels des utilisateurs**](windows-local-privilege-escalation/index.html#home-folders) (accès ?)
- [ ] Vérifier la [**stratégie de mots de passe**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que trouve-t-on[ **dans le presse-papiers**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les [**informations** **réseau**](windows-local-privilege-escalation/index.html#network) **actuelles**
- [ ] Vérifier les **services locaux masqués** inaccessibles depuis l’extérieur

### [Processus en cours d’exécution](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissions sur les [**fichiers et dossiers**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) des binaires des processus
- [ ] [**Extraction de mots de passe de la mémoire**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des identifiants à l’aide de **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Pouvez-vous **modifier** le **binaire** **exécuté** par un **service** ?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Pouvez-vous **modifier** le **registre** d’un **service** ?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Pouvez-vous exploiter le **chemin** d’un binaire de **service non entre guillemets** ?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Déclencheurs de service : énumérer et déclencher les services privilégiés](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] Permissions d’[**écriture sur les applications installées**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applications au démarrage**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Pilotes**](windows-local-privilege-escalation/index.html#drivers) **vulnérables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier du PATH** ?
- [ ] Existe-t-il un binaire de service connu qui **tente de charger une DLL inexistante** ?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
- [ ] Examiner particulièrement les services réseau en écoute sur localhost (127.0.0.1)

### [Identifiants Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Identifiants [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Identifiants du [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que vous pourriez utiliser ?
- [ ] [**Identifiants DPAPI**](windows-local-privilege-escalation/index.html#dpapi) intéressants ?
- [ ] Mots de passe des [**réseaux Wifi**](windows-local-privilege-escalation/index.html#wifi) enregistrés ?
- [ ] Informations intéressantes dans les [**connexions RDP enregistrées**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ?
- [ ] Mots de passe dans les [**commandes récemment exécutées**](windows-local-privilege-escalation/index.html#recently-run-commands) ?
- [ ] Mots de passe du [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) ?
- [ ] [**AppCmd.exe est présent**](windows-local-privilege-escalation/index.html#appcmd-exe) ? Des identifiants ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) ? DLL Side Loading ?

### [Fichiers et registre (identifiants)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty :** [**Identifiants**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**clés d’hôte SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) ?
- [ ] Mots de passe dans les [**fichiers de configuration sans assistance**](windows-local-privilege-escalation/index.html#unattended-files) ?
- [ ] Une sauvegarde de [**SAM et SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) ?
- [ ] Si l’accès à un handle de volume brut lisible est autorisé indépendamment, évaluer l’exposition possible de `SAM`, `SYSTEM`, du matériel DPAPI et de `MachineKeys` ; ne pas déduire cet accès de **SeManageVolumePrivilege** seul.<sup>[[5]](#references)</sup>
- [ ] [**Identifiants cloud**](windows-local-privilege-escalation/index.html#cloud-credentials) ?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ?
- [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) ?
- [ ] Mot de passe dans le [**fichier de configuration Web IIS**](windows-local-privilege-escalation/index.html#iis-web-config) ?
- [ ] Informations intéressantes dans les [**journaux** **Web**](windows-local-privilege-escalation/index.html#logs) ?
- [ ] Voulez-vous [**demander les identifiants**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l’utilisateur ?
- [ ] [**Fichiers intéressants dans la Corbeille**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ?
- [ ] Autres [**clés de registre contenant des identifiants**](windows-local-privilege-escalation/index.html#inside-the-registry) ?
- [ ] [**Données du navigateur**](windows-local-privilege-escalation/index.html#browsers-history) (bases de données, historique, favoris, ...) ?
- [ ] [**Recherche générique de mots de passe**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Outils**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès à un handle d’un processus exécuté par un administrateur ?

### [Usurpation d’identité d’un client de canal nommé](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifier si vous pouvez l’exploiter



## References

- [1] [Project Zero - Contourner la protection de l’administrateur en abusant de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privilèges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Modification des privilèges dans un jeton](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile : disques physiques et volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Gestion des privilèges dans un système de fichiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
