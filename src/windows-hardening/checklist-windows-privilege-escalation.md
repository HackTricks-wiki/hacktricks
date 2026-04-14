# Checklist - Élévation de privilèges locale Windows

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locale Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des [**exploits** kernel à l'aide de [**scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Utiliser **Google pour rechercher** des **exploits** kernel
- [ ] Utiliser **searchsploit pour rechercher** des **exploits** kernel
- [ ] Infos intéressantes dans les [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Des mots de passe dans l'**historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Infos intéressantes dans les [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)et [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)est actif
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Vérifier s'il y a un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les **privilèges** de l'**utilisateur actuel**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Vérifier si vous avez l'un de ces tokens activés](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Vérifier si vous avez [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) pour lire les volumes bruts et contourner les ACL des fichiers
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Vérifier les [**home folders**](windows-local-privilege-escalation/index.html#home-folders) des utilisateurs (access ?)
- [ ] Vérifier la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que contient [**le Presse-papiers**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) ?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les [**network** **information**](windows-local-privilege-escalation/index.html#network) actuelles
- [ ] Vérifier les **services locaux cachés** restreints depuis l'extérieur

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Binaires des processus [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des identifiants avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Pouvez-vous **modifier** le **binaire** **exécuté** par un **service** ?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Pouvez-vous **modifier** le **registre** d'un **service** ?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Pouvez-vous exploiter un **unquoted service** binary **path** ?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulnérables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier داخل PATH** ?
- [ ] Existe-t-il un binaire de service connu qui **essaie de charger une DLL inexistante** ?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (shares, interfaces, routes, neighbours, ...)
- [ ] Regarder particulièrement les services réseau à l'écoute sur localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials que vous pourriez utiliser ?
- [ ] [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) intéressants ?
- [ ] Mots de passe des [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) enregistrés ?
- [ ] Infos intéressantes dans les [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections) ?
- [ ] Mots de passe dans les [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands) ?
- [ ] Mots de passe du [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) ?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe) ? Credentials ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading ?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Mots de passe dans des [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files) ?
- [ ] Une sauvegarde [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) ?
- [ ] Si [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) est présent, essayez des lectures de volumes bruts pour `SAM`, `SYSTEM`, DPAPI material, et `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) ?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Mot de passe dans le fichier de config [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Infos intéressantes dans les [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Voulez-vous [**demander des identifiants**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l'utilisateur ?
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) intéressants ?
- [ ] D'autres [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry) ?
- [ ] Dans les [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...) ?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès à un handler d'un processus exécuté par un administrateur ?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifier si vous pouvez en abuser



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
