# Privilege Escalation mit Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kann verwendet werden, um Programme beim **Start** auszuführen. Mit folgendem Befehl siehst du, welche Binärdateien beim Start ausgeführt werden:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Geplante Aufgaben

**Aufgaben** können so geplant werden, dass sie mit einer **bestimmten Häufigkeit** ausgeführt werden. Mit den folgenden Befehlen können Sie sehen, welche Binärdateien zur Ausführung geplant sind:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Eine mit `/sc ONLOGON /rl HIGHEST` erstellte Aufgabe fordert die höchste Ausführungsstufe an, **die für ihren registrierten Prinzipal verfügbar ist**; der Schalter allein ändert weder diesen Prinzipal noch umgeht er UAC. Ein Prozess mit niedrigen Privilegien kann keine Aufgabe mit höchster Ausführungsstufe registrieren oder SYSTEM als Aufgabenidentität festlegen. Betrachte das obige Beispiel als Aktion für einen bereits erhöhten aufrufenden Prozess, nicht als Weg von einem Standardbenutzer zu SYSTEM.<sup>[[8]](#references)</sup>

Eine aktivierte Aufgabe, die als SYSTEM ausgeführt wird, sollte überprüft werden, auch wenn ihre Aufgabendefinition und Aktionsdatei geschützt sind. [Task Scheduler erfordert Ausführungsberechtigungen für die Aufgabe, damit sie bei Bedarf gestartet werden kann](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Wenn ein Benutzer mit niedrigen Privilegien diese Berechtigung hat, überprüfe die genaue Aktion, insbesondere PowerShell-Skripte, die Active Directory-ACLs ändern oder Kontoschutzeinstellungen zurücksetzen. Prüfe die Einstellung `AllowDemandStart` der Aufgabe und verifiziere die Eingaben und Auswirkungen des Skripts; die Berechtigung, eine festgelegte Aufgabe zu starten, bedeutet allein keine beliebige Codeausführung.

## Ordner

Alle Binärdateien in den **Autostartordnern werden beim Systemstart ausgeführt**. Die üblichen Autostartordner sind im Folgenden aufgeführt, aber der Autostartordner wird in der Registry angegeben. [Hier erfährst du, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Ein Startup-Eintrag eines Benutzers mit höheren Rechten kann ein geschütztes Skript starten, das wiederholt Dateien aus einem Verzeichnis öffnet, in das ein anderer Benutzer schreiben kann. Überprüfe den **tatsächlichen Anmeldekontext**, das Eingabeverzeichnis des Skripts und dessen ACLs sowie die genaue Aktion, bevor du das Verzeichnis als möglichen Pfad zur Rechteausweitung einstufst. Insbesondere öffnet [`hh.exe` kompilierte HTML-Help-Dateien (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); ein Skript, das vom Aufrufer bereitgestellte Dateien an das Programm übergibt, überschreitet eine Content-Trust-Grenze, selbst wenn es den Dateinamen oder die ersten Bytes überprüft. [HTML-Help-Richtlinien können ausführbare Verknüpfungen einschränken](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands). Prüfe daher die installierte Richtlinie und das Verhalten bei erreichbaren Inhalten. Eine `.chm`-Erweiterung oder Magic Bytes allein belegen keine Codeausführung mit höheren Rechten. Untersuche den Autorun-Eintrag, die Prozessbefehlszeile und die Pfadberechtigungen, ohne die nicht vertrauenswürdige Datei während der Bestandsaufnahme zu öffnen.

Dieselbe Content-Grenze besteht, wenn eine Person mit höheren Rechten eine `.chm` aus einem Dokumentationsordner **manuell öffnet**, den ein anderer Benutzer ersetzen kann. Prüfe die Schreibrechte für die genaue Datei und das übergeordnete Verzeichnis, die tatsächliche Identität des Viewers und das Öffnungsereignis sowie die wirksame HTML-Help-Richtlinie. Ein beschreibbarer Ordner oder die Aufforderung, Dokumentation zu prüfen, belegt nicht, dass die Person mit höheren Rechten vom Angreifer kontrollierte Inhalte geöffnet hat.

> **FYI**: Schwachstellen durch *Path Traversal* bei der Archivextraktion (wie die vor WinRAR 7.13 ausgenutzte Schwachstelle – CVE-2025-8088) können dazu verwendet werden, **Payloads während der Dekomprimierung direkt in diesen Startup-Ordnern abzulegen**, was beim nächsten Benutzer-Logon zur Codeausführung führt. Eine ausführliche Beschreibung dieser Technik findest du hier:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Hinweis von hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der Registry-Eintrag **Wow6432Node** weist darauf hin, dass du eine 64-Bit-Version von Windows verwendest. Das Betriebssystem nutzt diesen Schlüssel, um für 32-Bit-Anwendungen, die unter 64-Bit-Windows laufen, eine separate Ansicht von HKEY_LOCAL_MACHINE\SOFTWARE bereitzustellen.

### Runs

**Allgemein bekannte** AutoRun-Registry-Schlüssel:

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

Registry-Schlüssel namens **Run** und **RunOnce** sind dafür vorgesehen, bei jeder Anmeldung eines Benutzers am System automatisch Programme auszuführen. Die einer Taste als Datenwert zugewiesene Befehlszeile ist auf höchstens 260 Zeichen begrenzt.<sup>[[2]](#references)</sup>

**Service-Runs** (können den automatischen Start von Services während des Bootvorgangs steuern):

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

Unter Windows Vista und späteren Versionen werden die Registry-Schlüssel **Run** und **RunOnce** nicht automatisch erstellt. Einträge in diesen Schlüsseln können Programme entweder direkt starten oder als Abhängigkeiten festlegen. Um beispielsweise beim Logon eine DLL-Datei zu laden, kann man den Registry-Schlüssel **RunOnceEx** zusammen mit einem „Depend“-Schlüssel verwenden. Dies wird demonstriert, indem ein Registry-Eintrag hinzugefügt wird, der beim Systemstart „C:\temp\evil.dll“ ausführt:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Wenn du in einen der erwähnten Registry-Schlüssel innerhalb von **HKLM** schreiben kannst, kannst du deine Rechte erweitern, sobald sich ein anderer Benutzer anmeldet.

> [!TIP]
> **Exploit 2**: Wenn du eine der Binärdateien überschreiben kannst, auf die in einem der Registry-Schlüssel innerhalb von **HKLM** verwiesen wird, kannst du diese Datei mit einer Backdoor versehen. Sobald sich ein anderer Benutzer anmeldet, kannst du so deine Rechte erweitern.

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

Verknüpfungen im **Startup**-Ordner lösen automatisch den Start von Diensten oder Anwendungen bei der Benutzeranmeldung oder beim Neustart des Systems aus. Der Speicherort des **Startup**-Ordners ist für den Bereich **Local Machine** und **Current User** in der Registry festgelegt. Das bedeutet, dass jede Verknüpfung, die an diesen angegebenen **Startup**-Speicherorten hinzugefügt wird, dafür sorgt, dass der verknüpfte Dienst oder das Programm nach der Anmeldung oder dem Neustart gestartet wird. Dies ist eine einfache Methode, um Programme so zu planen, dass sie automatisch ausgeführt werden.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Wenn du einen beliebigen \[User] Shell Folder unter **HKLM** überschreiben kannst, kannst du ihn auf einen von dir kontrollierten Ordner verweisen lassen und dort eine backdoor platzieren, die jedes Mal ausgeführt wird, wenn sich ein Benutzer am System anmeldet, wodurch deine Berechtigungen erhöht werden.

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

Dieser benutzerspezifische Registrierungswert kann auf ein Skript oder einen Befehl verweisen, der ausgeführt wird, wenn sich der Benutzer anmeldet. Er dient hauptsächlich als **persistence**-Primitive, da er nur im Kontext des betroffenen Benutzers ausgeführt wird. Dennoch sollte er bei Post-Exploitation- und Autoruns-Prüfungen berücksichtigt werden.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Wenn du diesen Wert für den aktuellen Benutzer ändern kannst, kannst du die Ausführung bei der nächsten interaktiven Anmeldung erneut auslösen, ohne Administratorrechte zu benötigen. Wenn du ihn im Hive eines anderen Benutzers ändern kannst, erhältst du möglicherweise Codeausführung, sobald sich dieser Benutzer anmeldet.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Hinweise:

- Bevorzuge vollständige Pfade zu `.bat`-, `.cmd`-, `.ps1`- oder anderen Launcher-Dateien, auf die der Zielbenutzer bereits Zugriff hat.
- Dies bleibt bis zum Entfernen des Werts auch nach Abmeldung oder Neustart bestehen.
- Anders als `HKLM\...\Run` gewährt dies nicht von selbst erhöhte Rechte; es handelt sich um Persistenz im Benutzerkontext.

### Winlogon-Schlüssel

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalerweise ist der Schlüssel **Userinit** auf **userinit.exe** gesetzt. Wird dieser Schlüssel jedoch geändert, startet **Winlogon** die angegebene ausführbare Datei ebenfalls bei der Benutzeranmeldung. Ebenso soll der Schlüssel **Shell** auf **explorer.exe** verweisen, der Standardshell von Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Wenn Sie den Registrierungswert oder die Binärdatei überschreiben können, können Sie Ihre Rechte ausweiten.

### Richtlinieneinstellungen

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Überprüfen Sie den **Run**-Schlüssel.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Ändern der Eingabeaufforderung im abgesicherten Modus

In der Windows-Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` ist standardmäßig der Wert **`AlternateShell`** auf `cmd.exe` gesetzt. Das bedeutet, dass `cmd.exe` verwendet wird, wenn du beim Start „Abgesicherter Modus mit Eingabeaufforderung“ auswählst (durch Drücken von F8). Es ist jedoch möglich, den Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass du F8 drücken und die Option manuell auswählen musst.

So erstellst du eine Startoption, mit der automatisch „Abgesicherter Modus mit Eingabeaufforderung“ gestartet wird:<sup>[[5]](#references)</sup>

1. Ändere die Attribute der Datei `boot.ini`, um die Kennzeichen für schreibgeschützt, System und versteckt zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffne `boot.ini` zum Bearbeiten.
3. Füge eine Zeile wie diese ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichere die Änderungen an `boot.ini`.
5. Wende die ursprünglichen Dateiattribute erneut an: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Durch Ändern des Registrierungsschlüssels **AlternateShell** lässt sich eine benutzerdefinierte Command Shell einrichten, was potenziell unbefugten Zugriff ermöglicht.
- **Exploit 2 (PATH-Schreibberechtigungen):** Schreibberechtigungen für einen beliebigen Teil der Systemvariablen **PATH**, insbesondere vor `C:\Windows\system32`, ermöglichen die Ausführung einer benutzerdefinierten `cmd.exe`, die als Backdoor dienen könnte, wenn das System im abgesicherten Modus gestartet wird.
- **Exploit 3 (PATH- und boot.ini-Schreibberechtigungen):** Schreibzugriff auf `boot.ini` ermöglicht den automatischen Start im abgesicherten Modus und damit unbefugten Zugriff beim nächsten Neustart.

Verwende die folgenden Befehle, um die aktuelle Einstellung von **AlternateShell** zu überprüfen:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Installierte Komponente

Active Setup ist eine Windows-Funktion, die **gestartet wird, bevor die Desktopumgebung vollständig geladen ist**. Sie priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor die Benutzeranmeldung fortgesetzt wird. Dieser Vorgang findet sogar vor dem Auslösen anderer Starteinträge statt, etwa solcher in den Registrierungsschlüsseln Run oder RunOnce.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

In diesen Schlüsseln gibt es verschiedene Unterschlüssel, die jeweils einer bestimmten Komponente entsprechen. Besonders relevante Schlüsselwerte sind:

- **IsInstalled:**
  - `0` gibt an, dass der Befehl der Komponente nicht ausgeführt wird.
  - `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird. Dies ist das Standardverhalten, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Legt den von Active Setup auszuführenden Befehl fest. Dies kann eine beliebige gültige Befehlszeile sein, etwa zum Starten von `notepad`.

**Sicherheitshinweise:**

- Das Ändern oder Schreiben in einen Schlüssel, bei dem **`IsInstalled`** auf `"1"` gesetzt ist und ein bestimmter **`StubPath`** angegeben ist, kann zur nicht autorisierten Befehlsausführung führen, möglicherweise auch zur Privilegienerweiterung.
- Auch das Ändern der in einem beliebigen **`StubPath`**-Wert referenzierten Binärdatei kann bei ausreichenden Berechtigungen eine Privilegienerweiterung ermöglichen.

Mit den folgenden Befehlen lassen sich die **`StubPath`**-Konfigurationen aller Active-Setup-Komponenten überprüfen:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Übersicht über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsoft Internet Explorer zusätzliche Funktionen hinzufügen. Sie werden bei jedem Start in Internet Explorer und Windows Explorer geladen. Ihre Ausführung kann jedoch blockiert werden, indem der Schlüssel **NoExplorer** auf 1 gesetzt wird. Dadurch wird verhindert, dass sie mit Windows-Explorer-Instanzen geladen werden.<sup>[[1]](#references)</sup>

BHOs sind über Internet Explorer 11 mit Windows 10 kompatibel, werden aber von Microsoft Edge, dem Standardbrowser in neueren Windows-Versionen, nicht unterstützt.

Um die auf einem System registrierten BHOs zu untersuchen, kannst du die folgenden Registrierungsschlüssel prüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird in der Registrierung durch seine **CLSID** dargestellt, die als eindeutiger Bezeichner dient. Detaillierte Informationen zu jeder CLSID findest du unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Zum Abfragen von BHOs in der Registrierung können folgende Befehle verwendet werden:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer-Erweiterungen

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachte, dass die Registry für jede DLL einen neuen Eintrag enthält, der durch die **CLSID** dargestellt wird. Die CLSID-Informationen findest du unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Schriftarttreiber

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Befehl zum Öffnen

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM-Handler für Kontextmenüs

Explorer-Handler für Kontextmenüs sind Shell-Erweiterungen, die unter Schlüsseln wie `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` und `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` registriert sind. Der Standardwert eines Handlers oder manchmal sein Schlüsselname ist eine CLSID. Folgen Sie dieser CLSID zu `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; der Standardwert dort gibt die DLL an, die beim Aufruf des Handlers geladen wird.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Prüfe sowohl die 32-Bit- als auch die 64-Bit-Registrierungsansicht. `HKCR` führt benutzerspezifische und systemweite Klassenregistrierungen zusammen. Prüfe daher, welchen zugrunde liegenden Schlüssel ein Prozess auflöst. Eine Identität mit niedrigen Berechtigungen, die einen systemweiten `InprocServer32`-Wert ändern kann, könnte einen Prozess mit höheren Berechtigungen zu einer anderen DLL umleiten. Für eine Rechteausweitung muss dieser Prozess jedoch den Handler aufrufen. Ein beschreibbarer DLL-Pfad kann ein ähnliches Risiko darstellen, selbst wenn der Registrierungswert selbst geschützt ist.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Beachte, dass alle Orte, an denen du Autoruns finden kannst, bereits von [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) durchsucht werden. Für eine **umfassendere Liste automatisch ausgeführter** Dateien kannst du jedoch [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von Sysinternals verwenden:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Mehr

**Finde weitere Autoruns wie Registrierungen unter** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Häufige Malware-Persistenzmechanismen](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart-Kategorien (Fehlerbehebung mit den Windows Sysinternals Tools, 2. Auflage)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Wie kann ich eine Bootoption hinzufügen, die eine alternative Shell startet?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit – Rückblick vom 04.03.2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Sicherheitskontexte für Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
