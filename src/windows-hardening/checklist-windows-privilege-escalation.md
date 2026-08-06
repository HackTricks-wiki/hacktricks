# Checklist - Privilege Escalation locale su Windows

{{#include ../banners/hacktricks-training.md}}

### **Miglior tool per cercare vettori di privilege escalation locale su Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottenere le [**informazioni di sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cercare [**exploit usando script**](windows-local-privilege-escalation/index.html#version-exploits) per il **kernel**
- [ ] Usare **Google per cercare** **exploit** per il kernel
- [ ] Usare **searchsploit per cercare** **exploit** per il kernel
- [ ] Sono presenti informazioni interessanti nelle [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Sono presenti informazioni interessanti nelle [**impostazioni Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumerazione di logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controllare le impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controllare [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Controllare se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)è attivo
- [ ] [**Protezione LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenziali memorizzate nella cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controllare se è presente qualche [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Policy di AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegi degli utenti**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controllare i [**privilegi** dell'utente **attuale**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Controllare se sono abilitati [alcuni di questi token](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Controllare se si dispone di [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) per leggere i volumi raw e bypassare le ACL dei file
- [ ] [**Sessioni degli utenti**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controllare le[ **home degli utenti**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controllare la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa si trova[ **negli appunti**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Controllare le [**informazioni** di **rete** **attuali**](windows-local-privilege-escalation/index.html#network)
- [ ] Controllare i **servizi locali nascosti** con accesso limitato dall'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permessi di file e cartelle**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dei binari dei processi
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**App GUI insicure**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Rubare credenziali con **processi interessanti** tramite `ProcDump.exe`? (firefox, chrome, ecc. ...)

### [Servizi](windows-local-privilege-escalation/index.html#services)

- [ ] [È possibile **modificare qualche servizio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [È possibile **modificare** il **binario** **eseguito** da qualche **servizio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [È possibile **modificare** il **registro** di qualche **servizio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [È possibile sfruttare qualche **percorso** del binario di un **servizio non quotato**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerare e attivare servizi privilegiati](windows-local-privilege-escalation/service-triggers.md)

### [**Applicazioni**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permessi di scrittura** sulle [**applicazioni installate**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applicazioni all'avvio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Driver** **vulnerabili**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] È possibile **scrivere in qualche cartella all'interno di PATH**?
- [ ] È presente qualche binario di servizio noto che **tenta di caricare una DLL non esistente**?
- [ ] È possibile **scrivere** in qualche **cartella di binari**?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerare la rete (share, interfacce, route, vicini, ...)
- [ ] Prestare particolare attenzione ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali di [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Sono presenti credenziali di [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che si potrebbero usare?
- [ ] [**Credenziali DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interessanti?
- [ ] Password delle [**reti Wifi**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Sono presenti informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe esiste**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [File e registro (credenziali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password nei [**file unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Qualche backup di [**SAM e SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se è presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), provare a leggere i volumi raw per `SAM`, `SYSTEM`, materiale DPAPI e `MachineKeys`
- [ ] [**Credenziali Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password nel [**file di configurazione web IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informazioni interessanti nei [**log** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**richiedere le credenziali**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] [**File interessanti nel Cestino**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altre [**chiavi di registro contenenti credenziali**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Nei [**dati del Browser**](windows-local-privilege-escalation/index.html#browsers-history) (db, cronologia, segnalibri, ...)?
- [ ] [**Ricerca generica di password**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) nei file e nel registro
- [ ] [**Tool**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente le password

### [Handler in leak](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche handler di un processo eseguito da un amministratore?

### [Impersonation del client di una pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Controllare se è possibile abusarne

## Riferimenti

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
