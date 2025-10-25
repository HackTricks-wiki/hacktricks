# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Info système](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir [**informations système**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Utiliser **Google** pour chercher des **kernel exploits**
- [ ] Utiliser **searchsploit** pour chercher des **kernel exploits**
- [ ] Infos intéressantes dans les [**env vars**](windows-local-privilege-escalation/index.html#environment) ?
- [ ] Mots de passe dans l'[**historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) ?
- [ ] Infos intéressantes dans les [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings) ?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) ?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) ?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) ?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres d'**Audit** et de **WEF**
- [ ] Vérifier **LAPS**
- [ ] Vérifier si **WDigest** est actif
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) ?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard) [?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) ?
- [ ] Vérifier la présence de tout **AV** (https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) ?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les **privileges** de l'utilisateur **actuel** (current) (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups) ?
- [ ] Vérifier si vous avez l'un de ces tokens activés : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) ?
- [ ] Vérifier les [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (accès ?)
- [ ] Vérifier la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que contient le [**Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les **informations réseau** **actuelles** (current) (windows-local-privilege-escalation/index.html#network)
- [ ] Vérifier les **services locaux cachés** restreints à l'extérieur

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissions des fichiers et dossiers des binaires des processus [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des credentials via des processus intéressants avec `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Pouvez-vous **modifier un service** quelconque ? (windows-local-privilege-escalation/index.html#permissions)
- [ ] Pouvez-vous **modifier** le **binaire** exécuté par un **service** ? (windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Pouvez-vous **modifier** le **registre** d'un **service** ? (windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Pouvez-vous tirer parti d'un chemin de binaire de service **non quoted** (unquoted service binary path) ? (windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] Service Triggers : énumérer et déclencher des services privilégiés (windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** des [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier du PATH** ?
- [ ] Existe-t-il un binaire de service connu qui **essaie de charger une DLL inexistante** ?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (shares, interfaces, routes, neighbours, ...)
- [ ] Porter une attention particulière aux services réseau écoutant sur localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials utilisables ?
- [ ] DPAPI credentials intéressants ? (windows-local-privilege-escalation/index.html#dpapi)
- [ ] Mots de passe des réseaux Wifi sauvegardés ? (windows-local-privilege-escalation/index.html#wifi)
- [ ] Infos intéressantes dans les [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ?
- [ ] Mots de passe dans les [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) ?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) mots de passe ?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe) ? Credentials ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) ? DLL Side Loading ?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty :** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) ?
- [ ] Mots de passe dans des [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) ?
- [ ] Une sauvegarde **SAM & SYSTEM** ? (windows-local-privilege-escalation/index.html#sam-and-system-backups)
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials) ?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) ?
- [ ] Mot de passe dans le [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config) ?
- [ ] Infos intéressantes dans les [**web logs**](windows-local-privilege-escalation/index.html#logs) ?
- [ ] Voulez-vous [**demander des credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l'utilisateur ?
- [ ] Fichiers intéressants dans la [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) ?
- [ ] Autres [**registry contenant des credentials**](windows-local-privilege-escalation/index.html#inside-the-registry) ?
- [ ] À l'intérieur des [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...) ?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour chercher automatiquement des mots de passe

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès à un handle d'un process exécuté par un administrateur ?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifier si vous pouvez l'abuser

{{#include ../banners/hacktricks-training.md}}
