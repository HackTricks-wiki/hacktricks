# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Ottenere [**Informazioni di sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Cercare **exploit del kernel** [**utilizzando script**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usare **Google per cercare** exploit del kernel
- [ ] Usare **searchsploit per cercare** exploit del kernel
- [ ] Informazioni interessanti in [**variabili d'ambiente**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informazioni interessanti nelle [**impostazioni di Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Unità**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumerazione di Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Controllare le impostazioni di [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) e [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Controllare [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Controllare se [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) è attivo
- [ ] [**Protezione LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenziali memorizzate**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Controllare se ci sono [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Politica AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilegi utente**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Controllare i [**privilegi**] dell'utente [**corrente**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Controllare se hai [alcuni di questi token abilitati](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sessioni utenti**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Controllare [**le home degli utenti**](windows-local-privilege-escalation/index.html#home-folders) (accesso?)
- [ ] Controllare la [**Politica delle password**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Cosa c'è [**nella Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Controllare le **informazioni di rete** [**correnti**](windows-local-privilege-escalation/index.html#network)
- [ ] Controllare i **servizi locali nascosti** riservati all'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permessi [**file e cartelle dei binari dei processi**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Estrazione password dalla memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**App GUI insicure**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Rubare credenziali con **processi interessanti** tramite `ProcDump.exe` ? (firefox, chrome, ecc ...)

### [Servizi](windows-local-privilege-escalation/index.html#services)

- [ ] [Puoi **modificare qualche servizio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Puoi **modificare** il **binario** che viene **eseguito** da qualche **servizio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Puoi **modificare** il **registro** di qualche **servizio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Puoi approfittare di qualche **percorso di binario di servizio non quotato**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applicazioni**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Scrivere** [**permessi sulle applicazioni installate**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applicazioni di avvio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Driver vulnerabili** [**Driver**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Puoi **scrivere in qualche cartella dentro PATH**?
- [ ] Esiste qualche binario di servizio noto che **cerca di caricare qualche DLL inesistente**?
- [ ] Puoi **scrivere** in qualche **cartella di binari**?

### [Rete](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerare la rete (condivisioni, interfacce, rotte, vicini, ...)
- [ ] Dare un'occhiata speciale ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali di Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenziali di [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenziali di [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) che potresti usare?
- [ ] Credenziali [**DPAPI**] interessanti](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Password delle [**reti Wifi salvate**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Password del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Esiste [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [File e Registro (Credenziali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenziali**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Password in [**file non presidiati**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Credenziali cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Password GPP memorizzate**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password nel [**file di configurazione IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informazioni interessanti nei [**log web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Vuoi [**chiedere credenziali**](windows-local-privilege-escalation/index.html#ask-for-credentials) all'utente?
- [ ] File interessanti [**dentro il Cestino**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Altro [**registro contenente credenziali**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro i [**dati del browser**](windows-local-privilege-escalation/index.html#browsers-history) (db, cronologia, segnalibri, ...)?
- [ ] [**Ricerca generica di password**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in file e registro
- [ ] [**Strumenti**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) per cercare automaticamente le password

### [Gestori di leak](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hai accesso a qualche gestore di un processo eseguito da amministratore?

### [Impersonificazione del client Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Controlla se puoi abusarne

{{#include ../banners/hacktricks-training.md}}
