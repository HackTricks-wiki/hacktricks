# Misbruik van Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy voortgaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Miskien kan jy bevoegdhede eskaleer deur die tokens wat jy reeds het te misbruik**

### SeImpersonatePrivilege

Hierdie privilege, as dit deur 'n proses besit word, laat die impersonasie (maar nie die skepping nie) van enige token toe, mits 'n handle daarop verkry kan word. 'n Bevoorregte token kan van 'n Windows-diens (DCOM) verkry word deur dit te dwing om NTLM-authentisering teen 'n exploit uit te voer, wat daarna die uitvoering van 'n proses met SYSTEM-bevoegdhede moontlik maak. Hierdie kwesbaarheid kan uitgebuit word met verskeie gereedskap, soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat winrm gedeaktiveer is), [SweetPotato](https://github.com/CCob/SweetPotato), en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**; dit sal die **selfde metode** gebruik om 'n bevoorregte token te kry.\
Vervolgens laat hierdie privilege toe om **'n primêre token toe te ken** aan 'n nuwe/opgeskorte proses. Met die bevoorregte impersonation token kan jy 'n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy 'n **nuwe proses** skep met 'CreateProcessAsUser' of 'n proses skep wat opgeskort is en die token toewys (in die algemeen kan jy nie die primêre token van 'n lopende proses wysig nie).

### SeTcbPrivilege

As jy hierdie privilege geaktiveer het, kan jy **KERB_S4U_LOGON** gebruik om 'n **impersonation token** vir enige ander gebruiker te kry sonder om die credentials te ken, **'n arbitraire groep** (admins) by die token voeg, die **integriteitsvlak** van die token op "**medium**" stel, en hierdie token aan die **huidige thread** toewys (SetThreadToken).

### SeBackupPrivilege

Hierdie privilege veroorsaak dat die stelsel **alle lees-toegang** tot enige lêer toeken (beperk tot leesbewerkings). Dit word gebruik om die wagwoord-hashes van plaaslike Administrator-rekeninge uit die register te lees, waarna gereedskap soos "**psexec**" of "**wmiexec**" met die hash gebruik kan word (Pass-the-Hash-tegniek). Hierdie tegniek faal egter onder twee toestande: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer 'n beleid in plek is wat administratiewe regte van Local Administrators wat op afstand koppel, verwyder.\
Jy kan **hierdie privilege misbruik** met:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Hierdie privilege verskaf toestemming vir **skryftoegang** tot enige stelsel-lêer, ongeag die lêer se Access Control List (ACL). Dit bied verskeie moontlikhede vir eskalasie, insluitend die vermoë om **dienste te wysig**, DLL Hijacking uit te voer, en **debuggers** via Image File Execution Options te stel, onder ander tegnieke.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens te impersonate, maar ook bruikbaar sonder SeImpersonatePrivilege. Hierdie vermoë berus op die vermoë om 'n token te impersonate wat dieselfde gebruiker verteenwoordig en se integriteitsvlak nie hoër is as dié van die huidige proses nie.

**Belangrike punte:**

- **Impersonation sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege te benut vir EoP deur tokens te impersonate onder spesifieke voorwaardes.
- **Voorwaardes vir token-impersonasie:** Suksesvolle impersonasie vereis dat die teiken-token aan dieselfde gebruiker behoort en 'n integriteitsvlak het wat minder of gelyk is aan die integriteitsvlak van die proses wat impersonasie probeer uitvoer.
- **Skepping en wysiging van impersonation tokens:** Gebruikers kan 'n impersonation token skep en dit verbeter deur 'n bevoorregte groep se SID (Security Identifier) by te voeg.

### SeLoadDriverPrivilege

Hierdie privilege laat toe om device drivers te load en unload deur die skepping van 'n registerinskrywing met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte skryftoegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, moet `HKCU` (HKEY_CURRENT_USER) in plaas daarvan gebruik word. Om egter `HKCU` deur die kernel herkenbaar te maak vir driver-konfigurasie, moet 'n spesifieke pad gevolg word.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die huidige gebruiker is. Binne `HKCU` moet hierdie hele pad geskep word, en twee waardes moet gestel word:

- `ImagePath`, wat die pad is na die binary wat uitgevoer moet word
- `Type`, met 'n waarde van `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te volg:**

1. Toegang tot `HKCU` in plaas van `HKLM` weens beperkte skryftoegang.
2. Skep die pad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die Relative Identifier van die huidige gebruiker is.
3. Stel die `ImagePath` op die uitvoerpad van die binary.
4. Stel die `Type` op `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Meer maniere om hierdie privilege te misbruik in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie laat 'n proses toe om **eienaarskap van 'n objek te verkry**, en omseil die vereiste vir eksplisiete discretionary access deur die verskaffing van WRITE_OWNER toegangregte. Die proses behels eers om eienaarskap van die beoogde registry key vir skryfdoeleindes te verkry, en daarna die DACL te wysig om skryfoperasies toe te laat.
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

Hierdie voorreg laat toe om **debug ander prosesse**, insluitend om in die geheue te lees en te skryf. Verskeie strategieë vir geheue-inspuiting, wat die meeste antivirus- en host intrusion prevention-oplossings kan omseil, kan met hierdie voorreg gebruik word.

#### Dump geheue

You could use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) to **vang die geheue van 'n proses**. Specifically, this can apply to the **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process, which is responsible for storing user credentials once a user has successfully logged into a system.

You can then load this dump in mimikatz to obtain passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

As jy 'n `NT SYSTEM` shell wil kry, kan jy die volgende gebruik:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Hierdie reg (Perform volume maintenance tasks) maak dit moontlik om rou volume-toestelhandvatsels (bv. \\.\C:) oop te maak vir direkte skyf I/O wat NTFS ACLs omseil. Daarmee kan jy bytes van enige lêer op die volume kopieer deur die onderliggende blokke te lees, wat arbitrêre lêerlesing van sensitiewe materiaal moontlik maak (bv. masjien private sleutels in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Dit is veral impakvol op CA servers waar die eksfiltrasie van die CA private sleutel die vervalsing van 'n Golden Certificate moontlik maak om enige prinsipaal te imiteer.

Sien gedetailleerde tegnieke en mitigasies:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kontroleer privilegies
```
whoami /priv
```
Die **tokens wat as Disabled verskyn** kan geaktiveer word; jy kan eintlik beide _Enabled_ en _Disabled_ tokens misbruik.

### Aktiveer al die tokens

As jy tokens het wat as Disabled gemerk is, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **script** geïntegreer in hierdie [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabel

Volledige token privileges cheatsheet by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), onderstaande opsomming sal slegs direkte maniere lys om die privilege te benut om 'n admin-sessie te verkry of sensitiewe lêers te lees.

| Privilege                  | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                    | Opmerkings                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Dankie [Aurélien Chalot](https://twitter.com/Defte_) vir die opdatering. Ek sal binnekort probeer om dit na iets meer resep-agtig te herformuleer.                                                                                                                                                                                   |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Lees sensitiewe lêers met `robocopy /b`                                                                                                                                                                                                                                                                                                          | <p>- Mag meer interessant wees as jy %WINDIR%\MEMORY.DMP kan lees<br><br>- <code>SeBackupPrivilege</code> (en robocopy) is nie helpvol wanneer dit by oop lêers kom nie.<br><br>- Robocopy vereis beide SeBackup en SeRestore om met die /b parameter te werk.</p>                                                                            |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Skep arbitrêre token insluitend plaaslike admin-regte met `NtCreateToken`.                                                                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                 |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliceer die `lsass.exe` token.                                                                                                                                                                                                                                                                                                                  | Script is te vinde by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                              |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Laai 'n foutiewe kernel driver soos <code>szkg64.sys</code><br>2. Ontgin die driver se kwetsbaarheid<br><br>Alternatief kan die privilege gebruik word om sekuriteitsverwante drivers uit te laai met die <code>ftlMC</code> ingeboude opdrag. bv.: <code>fltMC sysmondrv</code></p>                                              | <p>1. Die <code>szkg64</code> kwesbaarheid is gelys as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Die <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> is geskep deur <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE terwyl die SeRestore privilege teenwoordig is.<br>2. Skakel die privilege aan met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Slot die konsole en druk Win+U</p> | <p>Aanval mag deur sekere AV-sagteware opgespoor word.</p><p>Alternatiewe metode staatmaak op die vervanging van service-binaries wat in "Program Files" gestoor is met dieselfde privilege</p>                                                                                                    |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Slot die konsole en druk Win+U</p>                                                                                                                                      | <p>Aanval mag deur sekere AV-sagteware opgespoor word.</p><p>Alternatiewe metode staatmaak op die vervanging van service-binaries wat in "Program Files" gestoor is met dieselfde privilege.</p>                                                                                                                            |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuleer tokens sodat plaaslike admin-regte ingesluit is. Mag SeImpersonate vereis.</p><p>Om te verifieer.</p>                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                 |

## Verwysing

- Kyk na hierdie tabel wat Windows tokens definieer: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Kyk na [**hierdie paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) oor privesc met tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
