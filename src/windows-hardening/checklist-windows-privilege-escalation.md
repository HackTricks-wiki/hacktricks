# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottieni [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cerca [**exploit** del **kernel** usando [**script**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usa **Google to search** per cercare exploit del **kernel**
- [ ] Usa **searchsploit** per cercare exploit del **kernel**
- [ ] Info interessante nelle [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password in [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Info interessante in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controlla le impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controlla [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Controlla se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)è attivo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controlla se c’è qualche [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controlla i **privileges** dell’utente **current**
- [ ] Sei [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Controlla se hai [attivi uno di questi token](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Controlla se hai [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) per leggere i volumi raw e bypassare gli ACL dei file
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controlla le [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controlla [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c’è [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Controlla le [**network information**](windows-local-privilege-escalation/index.html#network) **current**
- [ ] Controlla i servizi locali nascosti limitati verso l’esterno

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permessi di [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dei binari dei processi
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ruba credenziali con **interesting processes** tramite `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Puoi **modify** any service?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Puoi **modify** il **binary** che viene **executed** da qualche **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Puoi **modify** il **registry** di qualche **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Puoi sfruttare qualche **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumera e attiva servizi privilegiati](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] [**Write**](windows-local-privilege-escalation/index.html#write-permissions) **permissions sulle applicazioni installate**
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulnerable**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **write** in qualche folder dentro PATH?
- [ ] Esiste qualche service binary noto che **tries to load any non-existant DLL**?
- [ ] Puoi **write** in qualche cartella di **binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumera la rete (share, interfacce, route, neighbor, ...)
- [ ] Dai un’occhiata speciale ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenziali [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che potresti usare?
- [ ] [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) interessanti?
- [ ] Password delle reti [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Info interessante nelle [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Esiste [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se è presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), prova a leggere i volumi raw per `SAM`, `SYSTEM`, materiale DPAPI e `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password nel file di configurazione web di [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Info interessante nei [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) all’utente?
- [ ] File interessanti dentro il [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altri [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro i [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (db, history, bookmark, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in file e registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente le password

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche handler di un processo eseguito da administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Controlla se puoi abusarne



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
