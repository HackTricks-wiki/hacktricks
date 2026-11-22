# Checklist - Escalazione dei privilegi locali di Windows

{{#include ../banners/hacktricks-training.md}}

### **Miglior tool per individuare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottieni le [**informazioni di sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cerca [**exploit del kernel usando script**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usa **Google per cercare** **exploit** del kernel
- [ ] Usa **searchsploit per cercare** **exploit** del kernel
- [ ] Ci sono informazioni interessanti nelle [**variabili d'ambiente**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Ci sono password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Ci sono informazioni interessanti nelle [**impostazioni Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Unità**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Updater automatici di agent di terze parti / abuso di IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumerazione di logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controlla le impostazioni di [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Controlla [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verifica se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)è attivo
- [ ] [**Protezione LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenziali memorizzate nella cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controlla se è presente un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Criteri AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Protezione amministratore / elevazione silenziosa UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagazione del registro di accessibilità di Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegi utente**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controlla i [**privilegi** dell'utente **corrente**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Fai [**parte di un gruppo privilegiato**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Controlla se questi [privilegi sono presenti nel token corrente](windows-local-privilege-escalation/access-tokens.md), anche se risultano **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Un privilegio disabilitato può essere abilitato solo se è già presente nel token.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Controlla la presenza di [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), un diritto di manutenzione dei volumi. Da solo non garantisce l'accesso in lettura ai volumi raw; l'apertura di un disco o di un volume richiede anche permessi specifici.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Sessioni utente**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controlla[ le **home directory degli utenti**](windows-local-privilege-escalation/index.html#home-folders) (accessibili?)
- [ ] Controlla i [**criteri delle password**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c'è[ **negli appunti**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Controlla le [**informazioni di rete** **correnti**](windows-local-privilege-escalation/index.html#network)
- [ ] Controlla i **servizi locali nascosti** non accessibili dall'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permessi su [**file e cartelle**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dei binari dei processi
- [ ] [**Ricerca di password in memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**App GUI non sicure**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ruba credenziali da **processi interessanti** con `ProcDump.exe`? (firefox, chrome, ecc...)

### [Servizi](windows-local-privilege-escalation/index.html#services)

- [ ] [Puoi **modificare un servizio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Puoi **modificare** il **binario** **eseguito** da un **servizio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Puoi **modificare** il **registro** di un **servizio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Puoi sfruttare il **percorso** di un binario di **servizio non racchiuso tra virgolette**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Trigger dei servizi: enumerare e attivare servizi privilegiati](windows-local-privilege-escalation/service-triggers.md)

### [**Applicazioni**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permessi di scrittura** sulle [**applicazioni installate**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applicazioni all'avvio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Driver**](windows-local-privilege-escalation/index.html#drivers) **vulnerabili**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **scrivere in una cartella qualsiasi inclusa in PATH**?
- [ ] C'è un binario di servizio noto che **tenta di caricare una DLL inesistente**?
- [ ] Puoi **scrivere** in una **cartella di binari**?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Enumera la rete (share, interfacce, route, host vicini, ...)
- [ ] Presta particolare attenzione ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali di [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Ci sono credenziali del [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che potresti usare?
- [ ] Ci sono [**credenziali DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interessanti?
- [ ] Password delle [**reti Wi-Fi**](windows-local-privilege-escalation/index.html#wifi) salvate?
- [ ] Ci sono informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe è presente**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [File e registro (credenziali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**credenziali**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password nei [**file unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Ci sono backup di [**SAM e SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se l'accesso in lettura a un handle di volume raw è consentito separatamente, valuta la possibile esposizione di `SAM`, `SYSTEM`, materiale DPAPI e `MachineKeys`; non dedurre questo accesso dalla sola presenza di **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] [**Credenziali cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Password GPP memorizzata nella cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password nel [**file di configurazione Web IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ci sono informazioni interessanti nei [**log** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**richiedere le credenziali**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] Ci sono [**file interessanti nel Cestino**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altre [**chiavi di registro contenenti credenziali**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Nei [**dati del browser**](windows-local-privilege-escalation/index.html#browsers-history) (database, cronologia, segnalibri, ...)?
- [ ] [**Ricerca generica di password**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in file e registro
- [ ] [**Strumenti**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente le password

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a un handler qualsiasi di un processo eseguito da un amministratore?

### [Impersonificazione del client di una pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Controlla se puoi abusarne



## References

- [1] [Project Zero - Elusione di Administrator Protection tramite abuso di UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privilegi](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Modifica dei privilegi in un token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile: dischi e volumi fisici](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Gestione dei privilegi in un file system](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
