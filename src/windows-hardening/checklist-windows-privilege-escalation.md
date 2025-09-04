# Lista di controllo - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottenere [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cercare **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usa **Google per cercare** exploit del kernel
- [ ] Usa **searchsploit** per cercare exploit del kernel
- [ ] Informazioni interessanti nelle [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password nella [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informazioni interessanti nelle [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controlla le impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controlla [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verifica se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)è attivo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controlla se c'è qualche [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controlla i [**privilegi**] utente **correnti** (current) (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sei [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verifica se hai abilitati uno di questi token: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controlla i[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controlla la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c'è [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Controlla le **informazioni di rete** **correnti** (windows-local-privilege-escalation/index.html#network)
- [ ] Controlla **servizi locali nascosti** esposti verso l'esterno

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permessi su file e cartelle dei processi (binaries) [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Rubare credenziali con **interesting processes** tramite `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Puoi **modificare qualche service**? (Can you **modify any service**?)
- [ ] Puoi **modificare** la **binary** eseguita da qualche **service**? (Can you **modify** the **binary** that is **executed** by any **service**?)
- [ ] Puoi **modificare** il **registry** di qualche **service**? (Can you **modify** the **registry** of any **service**?)
- [ ] Puoi sfruttare qualche **unquoted service** binary **path**? (Can you take advantage of any **unquoted service** binary **path**?)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **scrivere in qualche cartella dentro PATH**?
- [ ] Esiste qualche servizio noto che **prova a caricare una DLL non-esistente**?
- [ ] Puoi **scrivere** in qualche **cartella di binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumera la rete (shares, interfaces, routes, neighbours, ...)
- [ ] Dai particolare attenzione ai servizi di rete che ascoltano su localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credenziali che potresti usare?
- [ ] Interessanti [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Password delle reti [**Wifi**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Informazioni interessanti nelle [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informazioni interessanti nei [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**chiedere credenziali**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] File interessanti dentro il [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altri [**registry contenenti credenziali**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro i [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in file e registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente password

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche handler di un processo eseguito dall'amministratore?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verifica se puoi abusarne

{{#include ../banners/hacktricks-training.md}}
