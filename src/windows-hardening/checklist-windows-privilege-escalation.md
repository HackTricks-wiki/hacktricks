# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per individuare vettori di privilege escalation locali su Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottenere [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cercare **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usare **Google** per cercare **kernel exploits**
- [ ] Usare **searchsploit** per cercare **kernel exploits**
- [ ] Informazioni interessanti in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password nella [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informazioni interessanti in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controllare impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controllare [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificare se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) è attivo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controllare se è presente qualche [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controllare i [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sei [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificare se hai abilitato uno di questi token: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controllare [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controllare la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c'è [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Controllare le [**current** **network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Controllare **hidden local services** accessibili dall'esterno

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permessi su file e cartelle dei processi binari [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Rubare credenziali da processi interessanti usando **ProcDump.exe** ? (firefox, chrome, ecc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Puoi **modify any service**? (modificare qualche servizio)
- [ ] Puoi **modify** il **binary** eseguito da qualche **service**? (modificare il percorso del binary) [**modify the binary that is executed by any service?**](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Puoi **modify** il **registry** di qualche **service**? [**services-registry-modify-permissions**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Puoi sfruttare qualche **unquoted service** binary **path**? [**unquoted-service-paths**](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] Service Triggers: enumerare e triggerare servizi privilegiati (privileged services) [windows-local-privilege-escalation/service-triggers.md]

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** permessi su applicazioni installate [**Write permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **write in any folder inside PATH**?
- [ ] Esiste qualche service binary noto che **tries to load any non-existant DLL**?
- [ ] Puoi **write** in qualche **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerare la rete (shares, interfaces, routes, neighbours, ...)
- [ ] Prestare particolare attenzione ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenziali di [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che potresti usare?
- [ ] Informazioni interessanti in [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Password delle reti [**Wifi**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Informazioni interessanti in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password di [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
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
- [ ] Password in file di configurazione [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informazioni interessanti nei [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] File interessanti nel [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altri [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro i dati del [**Browser**](windows-local-privilege-escalation/index.html#browsers-history) (db, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in file e registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente password

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche handler di un processo eseguito da administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verificare se puoi abusarne

{{#include ../banners/hacktricks-training.md}}
