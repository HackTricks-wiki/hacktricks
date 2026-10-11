# Privilege Escalation kwa kutumia Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa kuwasha. Angalia ni binaries zipi zimepangwa kuendeshwa wakati wa kuwasha kwa kutumia:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Kazi Zilizopangwa

**Kazi** zinaweza kuratibiwa ili ziendeshwe kwa **masafa maalum**. Tumia amri zifuatazo kuona ni binaries zipi zimepangwa kuendeshwa:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Kazi iliyowezeshwa inayoendeshwa kama SYSTEM inastahili kukaguliwa hata kama ufafanuzi wake na faili ya kitendo imelindwa. [Task Scheduler inahitaji ruhusa ya kutekeleza kazi ili kuiendesha unapohitaji](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Ikiwa mtumiaji mwenye ruhusa za chini ana ruhusa hiyo, kagua kitendo halisi, hasa hati za PowerShell zinazobadilisha ACL za Active Directory au kuweka upya mipangilio ya ulinzi wa akaunti. Angalia mpangilio wa kazi wa `AllowDemandStart` na uhakiki ingizo na athari za hati; ruhusa ya kuanzisha kazi isiyobadilika pekee haimaanishi uwezo wa kutekeleza msimbo wowote.

## Folda

Binaries zote zilizo kwenye **folda za Startup zitatekelezwa wakati wa kuwasha**. Folda za kawaida za Startup ni zile zilizoorodheshwa hapa chini, lakini folda ya Startup imeonyeshwa kwenye registry. [Soma hapa ili ujue ilipo.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Ingizo la Startup la mtumiaji mwenye privileges za juu linaweza kuanzisha script iliyolindwa ambayo hufungua tena na tena faili kutoka kwenye directory ambayo mtumiaji mwingine anaweza kuandika. Kagua **utambulisho halisi wa akaunti wakati wa logon** ya ingizo hilo, directory ya ingizo ya script pamoja na ACL zake, na kitendo halisi kabla ya kuchukulia directory hiyo kama njia ya kupata privileges za juu. Hasa, [`hh.exe` hufungua faili za HTML Help zilizokusanywa (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); script inayopitisha faili zilizotolewa na caller kwa programu hiyo huvuka mpaka wa uaminifu wa maudhui hata kama hukagua jina la faili au byte zake za mwanzo. [Sera za HTML Help zinaweza kuzuia njia za mkato zinazotekelezeka](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), kwa hiyo thibitisha sera iliyosakinishwa na tabia ya maudhui yanayoweza kufikiwa. Kiendelezi cha `.chm` au magic bytes pekee havithibitishi utekelezaji wa code wenye privileges za juu. Kagua autorun, command line ya process, na ruhusa za path bila kufungua faili isiyoaminika wakati wa kuorodhesha.

Mpaka huohuo wa maudhui upo wakati mtu mwenye privileges za juu **anafungua mwenyewe** faili ya `.chm` kutoka kwenye folder ya nyaraka ambayo mtumiaji mwingine anaweza kubadilisha. Thibitisha faili husika na ruhusa za kuandika za directory yake mama, utambulisho halisi wa mtazamaji na tukio la kufungua faili, pamoja na sera ya HTML Help inayotumika. Folder inayoweza kuandikwa au ombi la kukagua nyaraka halithibitishi kwamba utambulisho wenye privileges za juu ulifungua maudhui yanayodhibitiwa na mshambulizi.

> **FYI**: Vulnerability za *path traversal* za uchimbuaji wa archive (kama ile iliyotumiwa katika WinRAR kabla ya 7.13 – CVE-2025-8088) zinaweza kutumiwa **kuweka payload moja kwa moja ndani ya folder hizi za Startup wakati wa uchimbuaji**, na hivyo kusababisha code execution mtumiaji atakapoingia tena. Kwa maelezo ya kina kuhusu mbinu hii, tazama:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Dokezo kuanzia hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Ingizo la Registry la **Wow6432Node** linaonyesha kuwa unatumia toleo la Windows la 64-bit. Mfumo wa uendeshaji hutumia key hii kuonyesha mwonekano tofauti wa HKEY_LOCAL_MACHINE\SOFTWARE kwa applications za 32-bit zinazoendeshwa kwenye matoleo ya Windows ya 64-bit.

### Runs

**AutoRun zinazojulikana kwa kawaida**:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry keys zinazojulikana kama **Run** na **RunOnce** zimeundwa kuendesha programs kiotomatiki kila mtumiaji anapoingia kwenye mfumo. Command line iliyowekwa kama thamani ya data ya key ina kikomo cha herufi 260 au chini.<sup>[[2]](#references)</sup>

**Service runs** (zinaweza kudhibiti uanzishaji wa kiotomatiki wa services wakati wa boot):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Katika Windows Vista na matoleo ya baadaye, Registry keys za **Run** na **RunOnce** hazitengenezwi kiotomatiki. Ingizo kwenye keys hizi zinaweza kuanzisha programs moja kwa moja au kuzibainisha kama dependencies. Kwa mfano, ili kupakia faili ya DLL wakati wa logon, mtu anaweza kutumia Registry key ya **RunOnceEx** pamoja na key ya "Depend". Hili linaonyeshwa kwa kuongeza ingizo la Registry la kutekeleza "C:\temp\evil.dll" wakati wa kuwasha mfumo:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Ikiwa unaweza kuandika ndani ya registry yoyote iliyotajwa ndani ya **HKLM**, unaweza kuongeza privileges mtumiaji mwingine anapoingia.

> [!TIP]
> **Exploit 2**: Ikiwa unaweza kuandika juu ya binaries zozote zilizoonyeshwa kwenye registry yoyote ndani ya **HKLM**, unaweza kurekebisha binary hiyo na kuweka backdoor mtumiaji mwingine anapoingia, kisha kuongeza privileges.

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Njia za mkato zilizowekwa kwenye folda ya **Startup** zitasababisha huduma au programu zianze kiotomatiki mtumiaji anapoingia au mfumo unapowashwa upya. Mahali pa folda ya **Startup** hufafanuliwa kwenye registry kwa scope za **Local Machine** na **Current User**. Hii inamaanisha kuwa njia yoyote ya mkato iliyoongezwa kwenye maeneo haya maalum ya **Startup** itahakikisha huduma au programu iliyounganishwa nayo inaanza baada ya mchakato wa kuingia au kuwasha upya, na hivyo kuwa njia rahisi ya kupanga programu ziendeshwe kiotomatiki.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ikiwa unaweza kubatilisha Shell Folder yoyote ya \[User] chini ya **HKLM**, utaweza kuielekeza kwenye folda unayodhibiti na kuweka backdoor itakayoendeshwa kila mtumiaji anapoingia kwenye mfumo, na hivyo kupandisha marupurupu.

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Thamani hii ya registry ya kila mtumiaji inaweza kuelekeza kwenye script au command inayotekelezwa mtumiaji huyo anapoingia. Hutumika hasa kama primitive ya **persistence** kwa sababu huendeshwa tu katika muktadha wa mtumiaji aliyeathiriwa, lakini bado inafaa kuikagua wakati wa mapitio ya post-exploitation na autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ukiweza kuandika thamani hii kwa mtumiaji wa sasa, unaweza kusababisha utekelezaji uanze tena mtumiaji atakapoingia kwa njia shirikishi wakati ujao bila kuhitaji haki za admin. Ukiweza kuiandika kwenye hive ya mtumiaji mwingine, unaweza kupata utekelezaji wa code mtumiaji huyo atakapoingia.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Vidokezo:

- Pendelea kutumia njia kamili za faili za `.bat`, `.cmd`, `.ps1` au faili nyingine za launcher ambazo tayari zinaweza kusomwa na mtumiaji lengwa.
- Hii itaendelea kufanya kazi baada ya kutoka kwenye akaunti au kuwasha upya kompyuta, hadi thamani hiyo iondolewe.
- Tofauti na `HKLM\...\Run`, hii haitoi ruhusa za elevation yenyewe; ni persistence ya kiwango cha mtumiaji.

### Funguo za Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, ufunguo wa **Userinit** huwekwa kuwa **userinit.exe**. Hata hivyo, ufunguo huu ukibadilishwa, faili inayotekelezeka iliyobainishwa pia itazinduliwa na **Winlogon** mtumiaji anapoingia. Vilevile, ufunguo wa **Shell** unakusudiwa kuelekeza kwenye **explorer.exe**, ambayo ndiyo shell chaguomsingi ya Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Ikiwa unaweza kubadilisha thamani ya registry au binary, utaweza kuongeza privileges.

### Mipangilio ya Sera

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Angalia key ya **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Kubadilisha Safe Mode Command Prompt

Katika Windows Registry chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** ambayo kwa chaguo-msingi imewekwa kuwa `cmd.exe`. Hii inamaanisha kuwa unapochagua "Safe Mode with Command Prompt" wakati wa kuwasha kompyuta (kwa kubonyeza F8), `cmd.exe` hutumika. Hata hivyo, unaweza kusanidi kompyuta yako ianze kiotomatiki katika hali hii bila kuhitaji kubonyeza F8 na kuichagua mwenyewe.

Hatua za kuunda chaguo la kuwasha kompyuta ili ianze kiotomatiki katika "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Badilisha sifa za faili ya `boot.ini` ili kuondoa alama za read-only, system na hidden: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` ili kuihariri.
3. Ingiza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rejesha sifa za awali za faili: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha registry key ya **AlternateShell** huruhusu usanidi wa custom command shell, jambo linaloweza kuwezesha ufikiaji usioidhinishwa.
- **Exploit 2 (PATH Write Permissions):** Kuwa na ruhusa za kuandika kwenye sehemu yoyote ya system **PATH** variable, hasa kabla ya `C:\Windows\system32`, hukuwezesha kutekeleza `cmd.exe` maalum, ambayo inaweza kuwa backdoor ikiwa mfumo utaanzishwa katika Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Ruhusa ya kuandika kwenye `boot.ini` huwezesha mfumo kuanza kiotomatiki katika Safe Mode, na hivyo kurahisisha ufikiaji usioidhinishwa wakati wa kuwasha upya kunakofuata.

Ili kuangalia mpangilio wa sasa wa **AlternateShell**, tumia amri hizi:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Kipengele Kilichosakinishwa

Active Setup ni kipengele cha Windows ambacho **huanza kabla mazingira ya desktop hayajapakiwa kikamilifu**. Huweka kipaumbele katika utekelezaji wa amri fulani, ambazo lazima zikamilike kabla mchakato wa kuingia kwa mtumiaji haujaendelea. Mchakato huu hufanyika hata kabla maingizo mengine ya kuanzisha, kama yaliyo katika sehemu za registry za Run au RunOnce, hayajaanzishwa.

Active Setup inadhibitiwa kupitia funguo hizi za registry:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya funguo hizi kuna subkeys mbalimbali, kila moja ikiwakilisha kipengele maalum. Thamani za funguo zinazovutia hasa ni pamoja na:

- **IsInstalled:**
  - `0` huashiria kuwa amri ya kipengele haitatekelezwa.
  - `1` humaanisha kuwa amri itatekelezwa mara moja kwa kila mtumiaji; huu ndio mwenendo wa kawaida ikiwa thamani ya `IsInstalled` haipo.
- **StubPath:** Hufafanua amri itakayotekelezwa na Active Setup. Inaweza kuwa amri yoyote halali, kama vile kufungua `notepad`.

**Maelezo ya Usalama:**

- Kurekebisha au kuandika kwenye ufunguo ambao **`IsInstalled`** yake imewekwa kuwa `"1"` na una **`StubPath`** maalum kunaweza kusababisha utekelezaji wa amri bila idhini, na huenda kukatumika kuongeza mamlaka.
- Kubadilisha faili ya binary inayorejelewa katika thamani yoyote ya **`StubPath`** kunaweza pia kuongeza mamlaka, iwapo una ruhusa za kutosha.

Ili kukagua mipangilio ya **`StubPath`** katika vipengele vya Active Setup, unaweza kutumia amri hizi:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Muhtasari wa Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni moduli za DLL zinazoongeza vipengele vya ziada kwenye Internet Explorer ya Microsoft. Hupakiwa kwenye Internet Explorer na Windows Explorer kila zinapoanzishwa. Hata hivyo, utekelezaji wake unaweza kuzuiwa kwa kuweka ufunguo wa **NoExplorer** kuwa 1, na kuwazuia kupakiwa pamoja na matukio ya Windows Explorer.<sup>[[1]](#references)</sup>

BHOs zinaoana na Windows 10 kupitia Internet Explorer 11, lakini hazitumiki kwenye Microsoft Edge, kivinjari chaguomsingi katika matoleo mapya zaidi ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua funguo zifuatazo za registry:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake kwenye registry, inayotumika kama kitambulisho cha kipekee. Maelezo ya kina kuhusu kila CLSID yanaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Ili kuulizia BHOs kwenye registry, unaweza kutumia amri hizi:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Viendelezi vya Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kuwa registry itakuwa na ingizo jipya la registry kwa kila DLL, na litawakilishwa na **CLSID**. Unaweza kupata maelezo ya CLSID kwenye `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Viendeshi vya Fonti

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Amri ya Open

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM handlers za menyu ya muktadha

Handlers za menyu ya muktadha za Explorer ni shell extensions zilizosajiliwa chini ya keys kama `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` na `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Thamani chaguomsingi ya handler, au wakati mwingine jina la key yake, ni CLSID. Fuata CLSID hiyo hadi `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; thamani yake chaguomsingi hutaja DLL inayopakiwa handler inapoendeshwa.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Angalia mitazamo ya registry ya 32-bit na 64-bit. `HKCR` huunganisha usajili wa madarasa wa mtumiaji na wa mfumo mzima, kwa hivyo hakikisha ni ufunguo upi wa msingi ambao mchakato utatumia. Utambulisho wenye ruhusa ndogo unaoweza kubadilisha thamani ya `InprocServer32` ya mfumo mzima unaweza kuelekeza mchakato wenye ruhusa za juu zaidi kwenye DLL nyingine, lakini kupandisha ruhusa kunahitaji mchakato huo uitumie handler. Njia ya DLL inayoweza kuandikwa inaweza kusababisha hatari kama hiyo hata kama thamani ya registry yenyewe imelindwa.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Kumbuka kwamba maeneo yote ambako unaweza kupata autoruns **tayari yamekaguliwa na**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, ili kupata **orodha pana zaidi ya faili zinazoendeshwa kiotomatiki**, unaweza kutumia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kutoka systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Zaidi

**Pata Autoruns zaidi kama vile registry kwenye** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mbinu za kawaida za malware kujidumisha](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Utekelezaji wa kujiendesha wakati wa kuwasha au kuingia: Funguo za Registry Run / Folda ya Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Skripti za uanzishaji wakati wa kuwasha au kuingia: Skripti ya kuingia (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Aina za autostart (Utatuzi wa matatizo kwa kutumia Zana za Windows Sysinternals, Toleo la 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Ninawezaje kuongeza chaguo la kuwasha linaloanzisha shell mbadala?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Muhtasari wa Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
