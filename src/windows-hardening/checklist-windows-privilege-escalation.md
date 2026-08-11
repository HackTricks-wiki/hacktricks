# Checklist - Escalation locale dei privilegi Windows

{{#include ../banners/hacktricks-training.md}}

### **Miglior tool per cercare vettori di escalation locale dei privilegi Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottenere le [**informazioni di sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cercare [**exploit usando script**](windows-local-privilege-escalation/index.html#version-exploits) per il **kernel**
- [ ] Usare **Google per cercare** **exploit** per il kernel
- [ ] Usare **searchsploit per cercare** **exploit** per il kernel
- [ ] Informazioni interessanti nelle [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informazioni interessanti nelle [**impostazioni Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-updater di agent di terze parti / abuso di IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumerazione di logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controllare le impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controllare [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Controllare se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)è attivo
- [ ] [**Protezione LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenziali memorizzate nella cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controllare se è presente qualche [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Policy AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Protezione amministratore / elevazione silenziosa tramite UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagazione del registro di accessibilità del Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegi utente**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controllare i [**privilegi**](windows-local-privilege-escalation/index.html#users-and-groups) dell'utente **corrente**
- [ ] Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Controllare se hai [uno di questi token abilitati](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Controllare se hai [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) per leggere i volumi raw e bypassare le ACL dei file
- [ ] [**Sessioni utente**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controllare le[ **home degli utenti**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controllare la [**Policy delle password**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c'è[ **negli Appunti**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Controllare le **informazioni** di **rete** [**correnti**](windows-local-privilege-escalation/index.html#network)
- [ ] Controllare i **servizi locali nascosti** limitati dall'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permessi su file e cartelle**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dei binari dei processi
- [ ] [**Password mining dalla memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**App GUI insicure**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Rubare credenziali con **processi interessanti** tramite `ProcDump.exe` ? (firefox, chrome, ecc. ...)

### [Servizi](windows-local-privilege-escalation/index.html#services)

- [ ] [Puoi **modificare qualche servizio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Puoi **modificare** il **binario** **eseguito** da qualche **servizio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Puoi **modificare** il **registro** di qualche **servizio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Puoi sfruttare qualche **path** di binario di **servizio non quotato**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerare e attivare servizi privilegiati](windows-local-privilege-escalation/service-triggers.md)

### [**Applicazioni**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permessi di scrittura** sulle [**applicazioni installate**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applicazioni all'avvio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Driver**](windows-local-privilege-escalation/index.html#drivers) **vulnerabili**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **scrivere in qualche cartella all'interno di PATH**?
- [ ] Esiste qualche binario di servizio noto che **tenta di caricare una DLL inesistente**?
- [ ] Puoi **scrivere** in qualche **cartella di binari**?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerare la rete (share, interfacce, route, vicini, ...)
- [ ] Prestare particolare attenzione ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenziali di [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che potresti usare?
- [ ] [**Credenziali DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interessanti?
- [ ] Password delle [**reti Wifi**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** esiste](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [File e registro (credenziali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password nei [**file unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se è presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), provare a leggere i volumi raw per `SAM`, `SYSTEM`, materiale DPAPI e `MachineKeys`
- [ ] [**Credenziali Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Password GPP memorizzata nella cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password nel [**file di configurazione web IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informazioni interessanti nei [**log** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**chiedere le credenziali**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] [**File interessanti nel Cestino**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altri [**elementi del registro contenenti credenziali**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Nei [**dati del Browser**](windows-local-privilege-escalation/index.html#browsers-history) (db, cronologia, segnalibri, ...)?
- [ ] [**Ricerca generica delle password**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) nei file e nel registro
- [ ] [**Tool**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente le password

### [Handler in leak](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche handler di un processo eseguito dall'amministratore?

### [Impersonation del client di una pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Controllare se puoi abusarne

## References

- [1] [Project Zero - Bypassare la protezione dell'amministratore abusando di UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
