# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa **startup**. Angalia ni **binaries** zipi zimepangwa kuendeshwa wakati wa **startup** kwa kutumia:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Kazi Zilizopangwa

**Kazi** zinaweza kupangwa zitekelezwe kwa **marudio maalum**. Tumia amri zifuatazo kuona ni binaries zipi zimepangwa kutekelezwa:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folda

Binaries zote zilizo katika **Startup folders zitatekelezwa wakati wa startup**. Startup folders za kawaida ni zile zilizoorodheshwa hapa chini, lakini startup folder inaonyeshwa kwenye registry. [Soma hapa ili ujifunze ilipo.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Udhaifu wa *path traversal* wakati wa kutoa archive (kama ule uliotumiwa vibaya katika WinRAR kabla ya 7.13 – CVE-2025-8088) unaweza kutumiwa **kuweka payload moja kwa moja ndani ya folda hizi za Startup wakati wa decompression**, na kusababisha code execution mtumiaji atakapoingia kwenye mfumo mara inayofuata. Kwa uchambuzi wa kina wa technique hii tazama:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Dokezo kutoka hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Ingizo la registry la **Wow6432Node** linaonyesha kuwa unatumia toleo la Windows la 64-bit. Mfumo wa uendeshaji hutumia key hii kuonyesha mwonekano tofauti wa HKEY_LOCAL_MACHINE\SOFTWARE kwa applications za 32-bit zinazoendeshwa kwenye matoleo ya Windows ya 64-bit.

### Runs

**AutoRun zinazojulikana kwa kawaida** za registry:

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

Registry keys zinazojulikana kama **Run** na **RunOnce** zimeundwa ili ku-execute programs automatically kila wakati mtumiaji anapoingia kwenye mfumo. Command line iliyowekwa kama data value ya key ina kikomo cha characters 260 au chini.<sup>[[2]](#references)</sup>

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

Kwenye Windows Vista na matoleo ya baadaye, registry keys za **Run** na **RunOnce** hazitengenezwi automatically. Entries katika keys hizi zinaweza kuanzisha programs moja kwa moja au kuzibainisha kama dependencies. Kwa mfano, ili kupakia DLL file wakati wa logon, mtu anaweza kutumia registry key ya **RunOnceEx** pamoja na key ya "Depend". Hili linaonyeshwa kwa kuongeza registry entry ya ku-execute "C:\temp\evil.dll" wakati wa system start-up:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Ikiwa unaweza kuandika katika registry yoyote iliyotajwa ndani ya **HKLM**, unaweza kufanya privilege escalation mtumiaji mwingine anapoingia.

> [!TIP]
> **Exploit 2**: Ikiwa unaweza ku-overwrite binary yoyote iliyoonyeshwa katika registry yoyote ndani ya **HKLM**, unaweza kurekebisha binary hiyo kwa backdoor mtumiaji mwingine anapoingia na kufanya privilege escalation.
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

Shortcuts zilizowekwa kwenye folda ya **Startup** zitaanzisha kiotomatiki services au applications wakati wa user logon au system reboot. Mahali ilipo folda ya **Startup** pamefafanuliwa kwenye registry kwa scope za **Local Machine** na **Current User**. Hii inamaanisha kuwa shortcut yoyote iliyoongezwa kwenye maeneo haya maalum ya **Startup** itahakikisha service au program iliyounganishwa inaanza baada ya mchakato wa logon au reboot, hivyo kutoa njia rahisi ya kupanga programs ziendeshe kiotomatiki.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ikiwa unaweza ku-overwrite \[User] Shell Folder yoyote chini ya **HKLM**, utaweza kuielekeza kwenye folda unayoidhibiti na kuweka backdoor itakayo-executewa kila mtumiaji anapoingia kwenye mfumo, na hivyo kuongeza privileges.
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

Thamani hii ya registry ya kila mtumiaji inaweza kuelekeza kwenye script au command inayotekelezwa mtumiaji huyo anapoingia. Hasa ni primitive ya **persistence** kwa sababu hutekelezwa tu katika context ya mtumiaji aliyeathiriwa, lakini bado inafaa kukaguliwa wakati wa post-exploitation na ukaguzi wa autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ikiwa unaweza kuandika thamani hii kwa mtumiaji wa sasa, unaweza kuanzisha tena utekelezaji mtumiaji atakapoingia tena kwa njia ya interactive bila kuhitaji haki za admin. Ikiwa unaweza kuiandika kwenye hive ya mtumiaji mwingine, unaweza kupata code execution mtumiaji huyo anapoingia.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Vidokezo:

- Pendelea paths kamili za `.bat`, `.cmd`, `.ps1`, au launcher files nyingine ambazo tayari zinaweza kusomwa na user anayelengwa.
- Hii hudumu baada ya logoff/reboot hadi value iondolewe.
- Tofauti na `HKLM\...\Run`, hii **haitoi elevation** yenyewe; ni user-scope persistence.

### Funguo za Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, key ya **Userinit** huwekwa kuwa **userinit.exe**. Hata hivyo, key hii ikibadilishwa, executable iliyobainishwa pia itazinduliwa na **Winlogon** wakati wa user logon. Vivyo hivyo, key ya **Shell** imekusudiwa kuelekeza kwenye **explorer.exe**, ambayo ndiyo default shell ya Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Ikiwa unaweza kuandika upya thamani ya registry au binary, utaweza kufanya privilege escalation.

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

Katika Windows Registry kwenye `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna value ya **`AlternateShell`** iliyowekwa kwa default kuwa `cmd.exe`. Hii inamaanisha kwamba unapochagua "Safe Mode with Command Prompt" wakati wa startup (kwa kubonyeza F8), `cmd.exe` hutumika. Hata hivyo, inawezekana kusanidi computer yako ianze kiotomatiki katika mode hii bila kuhitaji kubonyeza F8 na kuichagua mwenyewe.

Hatua za kuunda boot option ya kuanza kiotomatiki katika "Safe Mode with Command Prompt":<sup>[[5]](#references)</sup>

1. Badilisha attributes za faili la `boot.ini` ili kuondoa flags za read-only, system, na hidden: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa ajili ya ku-edit.
3. Ingiza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rejesha file attributes za awali: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha **AlternateShell** registry key huruhusu usanidi wa custom command shell, ambao unaweza kutumika kupata access isiyoidhinishwa.
- **Exploit 2 (PATH Write Permissions):** Kuwa na write permissions kwenye sehemu yoyote ya system **PATH** variable, hasa kabla ya `C:\Windows\system32`, hukuruhusu ku-execute custom `cmd.exe`, ambayo inaweza kuwa backdoor ikiwa mfumo utaanzishwa katika Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Kuwa na write access kwenye `boot.ini` huwezesha kuanzisha Safe Mode kiotomatiki, na hivyo kurahisisha access isiyoidhinishwa wakati wa reboot inayofuata.

Ili kuangalia setting ya sasa ya **AlternateShell**, tumia commands hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Kipengele Kilichosakinishwa

Active Setup ni feature ya Windows ambayo **huanzishwa kabla ya desktop environment kupakiwa kikamilifu**. Huweka kipaumbele katika kutekeleza commands fulani, ambazo lazima zikamilike kabla ya mchakato wa user logon kuendelea. Mchakato huu hutokea hata kabla ya startup entries nyingine, kama zile zilizo katika sehemu za Run au RunOnce za registry, kuanzishwa.

Active Setup inadhibitiwa kupitia registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya keys hizi kuna subkeys mbalimbali, kila moja ikiwa inahusishwa na component maalum. Key values muhimu ni pamoja na:

- **IsInstalled:**
- `0` inaonyesha kuwa command ya component haitatekelezwa.
- `1` inamaanisha kuwa command itatekelezwa mara moja kwa kila user; hii ndiyo tabia ya kawaida ikiwa value ya `IsInstalled` haipo.
- **StubPath:** Hufafanua command itakayotekelezwa na Active Setup. Inaweza kuwa command line yoyote halali, kama vile kuanzisha `notepad`.

**Security Insights:**

- Kurekebisha au kuandika kwenye key ambayo **`IsInstalled`** imewekwa kuwa `"1"` pamoja na **`StubPath`** maalum kunaweza kusababisha command execution isiyoidhinishwa, na hivyo uwezekano wa privilege escalation.
- Kubadilisha binary file inayorejelewa na value yoyote ya **`StubPath`** kunaweza pia kufanikisha privilege escalation, ikiwa kuna permissions za kutosha.

Ili kukagua configurations za **`StubPath`** katika Active Setup components, commands hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Muhtasari wa Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni DLL modules zinazoongeza vipengele vya ziada kwenye Internet Explorer ya Microsoft. Hupakiwa kwenye Internet Explorer na Windows Explorer kila vinapoanzishwa. Hata hivyo, utekelezaji wake unaweza kuzuiwa kwa kuweka key ya **NoExplorer** kuwa 1, hivyo kuzuia kupakiwa pamoja na instances za Windows Explorer.<sup>[[1]](#references)</sup>

BHOs zinaoana na Windows 10 kupitia Internet Explorer 11, lakini hazitumiki katika Microsoft Edge, browser chaguo-msingi kwenye matoleo mapya ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake kwenye registry, unaotumika kama kitambulisho cha kipekee. Taarifa za kina kuhusu kila CLSID zinaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Kwa kuuliza BHOs kwenye registry, commands hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kuwa registry itakuwa na registry 1 mpya kwa kila dll na itawakilishwa na **CLSID**. Unaweza kupata maelezo ya CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Amri ya Kufungua

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Chaguo za Utekelezaji wa Faili za Picha
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Kumbuka kwamba tovuti zote unazoweza kupata autoruns tayari zimesearchiwa na [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, kwa ajili ya kupata orodha pana zaidi ya faili zinazotekelezwa kiotomatiki, unaweza kutumia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)kutoka systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Zaidi

**Pata Autoruns zaidi kama registries katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Mbinu za kawaida za persistence za malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategorien za Autostart (Troubleshooting with the Windows Sysinternals Tools, Toleo la 2)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Ninawezaje kuongeza boot option inayoanzisha alternate shell?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
