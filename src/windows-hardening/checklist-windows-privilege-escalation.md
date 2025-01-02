# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informazioni di sistema](windows-local-privilege-escalation/#system-info)

- [ ] Ottenere [**Informazioni di sistema**](windows-local-privilege-escalation/#system-info)
- [ ] Cercare **exploit del kernel** [**utilizzando script**](windows-local-privilege-escalation/#version-exploits)
- [ ] Usare **Google per cercare** exploit del kernel
- [ ] Usare **searchsploit per cercare** exploit del kernel
- [ ] Informazioni interessanti in [**variabili d'ambiente**](windows-local-privilege-escalation/#environment)?
- [ ] Password nella [**cronologia di PowerShell**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Informazioni interessanti nelle [**impostazioni di Internet**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Unità**](windows-local-privilege-escalation/#drives)?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumerazione di Logging/AV](windows-local-privilege-escalation/#enumeration)

- [ ] Controllare le impostazioni di [**Audit**](windows-local-privilege-escalation/#audit-settings) e [**WEF**](windows-local-privilege-escalation/#wef)
- [ ] Controllare [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Controllare se [**WDigest**](windows-local-privilege-escalation/#wdigest) è attivo
- [ ] [**Protezione LSA**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Credenziali memorizzate**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Controllare se ci sono [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Politica AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilegi utente**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Controllare i [**privilegi**] dell'utente [**corrente**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Sei [**membro di qualche gruppo privilegiato**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Controllare se hai [alcuni di questi token abilitati](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
- [ ] [**Sessioni utenti**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Controllare [**le home degli utenti**](windows-local-privilege-escalation/#home-folders) (accesso?)
- [ ] Controllare la [**Politica delle password**](windows-local-privilege-escalation/#password-policy)
- [ ] Cosa c'è [**dentro il Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Rete](windows-local-privilege-escalation/#network)

- [ ] Controllare le **informazioni di rete** [**correnti**](windows-local-privilege-escalation/#network)
- [ ] Controllare i **servizi locali nascosti** riservati all'esterno

### [Processi in esecuzione](windows-local-privilege-escalation/#running-processes)

- [ ] Permessi sui [**file e cartelle dei processi**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Estrazione password dalla memoria**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**App GUI insicure**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Rubare credenziali con **processi interessanti** tramite `ProcDump.exe`? (firefox, chrome, ecc...)

### [Servizi](windows-local-privilege-escalation/#services)

- [ ] [Puoi **modificare qualche servizio**?](windows-local-privilege-escalation/#permissions)
- [ ] [Puoi **modificare** il **binario** che viene **eseguito** da qualche **servizio**?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Puoi **modificare** il **registro** di qualche **servizio**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Puoi approfittare di qualche **percorso di binario di servizio non quotato**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applicazioni**](windows-local-privilege-escalation/#applications)

- [ ] **Scrivere** [**permessi sulle applicazioni installate**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Applicazioni di avvio**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Driver vulnerabili** [**Driver**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Puoi **scrivere in qualche cartella dentro PATH**?
- [ ] Esiste qualche binario di servizio noto che **cerca di caricare qualche DLL non esistente**?
- [ ] Puoi **scrivere** in qualche **cartella di binari**?

### [Rete](windows-local-privilege-escalation/#network)

- [ ] Enumerare la rete (condivisioni, interfacce, rotte, vicini, ...)
- [ ] Dare un'occhiata speciale ai servizi di rete in ascolto su localhost (127.0.0.1)

### [Credenziali di Windows](windows-local-privilege-escalation/#windows-credentials)

- [ ] Credenziali di [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
- [ ] Credenziali di [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) che potresti usare?
- [ ] Credenziali [**DPAPI**](windows-local-privilege-escalation/#dpapi) interessanti?
- [ ] Password delle [**reti Wifi salvate**](windows-local-privilege-escalation/#wifi)?
- [ ] Informazioni interessanti nelle [**connessioni RDP salvate**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Password nei [**comandi eseguiti di recente**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] Password nel [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
- [ ] Esiste [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Credenziali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [File e Registro (Credenziali)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Credenziali**](windows-local-privilege-escalation/#putty-creds) **e** [**chiavi host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**Chiavi SSH nel registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Password in [**file non presidiati**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Qualche backup di [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
- [ ] [**Credenziali cloud**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] File [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
- [ ] [**Password GPP memorizzate**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Password nel [**file di configurazione IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Informazioni interessanti nei [**log web**](windows-local-privilege-escalation/#logs)?
- [ ] Vuoi [**chiedere credenziali**](windows-local-privilege-escalation/#ask-for-credentials) all'utente?
- [ ] File [**interessanti dentro il Cestino**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Altri [**registri contenenti credenziali**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Dentro i [**dati del browser**](windows-local-privilege-escalation/#browsers-history) (db, cronologia, segnalibri, ...)?
- [ ] [**Ricerca generica di password**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in file e registro
- [ ] [**Strumenti**](windows-local-privilege-escalation/#tools-that-search-for-passwords) per cercare automaticamente password

### [Gestori di leak](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Hai accesso a qualche gestore di un processo eseguito da amministratore?

### [Impersonificazione del client Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Controlla se puoi abusarne

{{#include ../banners/hacktricks-training.md}}
