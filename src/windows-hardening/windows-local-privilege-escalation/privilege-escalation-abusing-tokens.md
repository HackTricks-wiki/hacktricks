# Misbruik van Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie** lees hierdie bladsy voordat jy voortgaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Mag wees jy kan voorregte verhoog deur die tokens wat jy reeds het te misbruik**

### SeImpersonatePrivilege

Dit is 'n privilege wat deur enige proses gehou word en wat die impersonation (maar nie die creation nie) van enige token toelaat, mits 'n handle daarop verkry kan word. 'n Bevoorregte token kan verkry word vanaf 'n Windows-diens (DCOM) deur dit te veroorsaak om NTLM authentication teen 'n exploit uit te voer, wat daarna die uitvoering van 'n proses met SYSTEM-voorregte moontlik maak. Hierdie kwesbaarheid kan uitgebuit word met verskeie gereedskap, soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat winrm gedeaktiveer is), [SweetPotato](https://github.com/CCob/SweetPotato), en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**; dit sal dieselfde metode gebruik om 'n bevoorregte token te kry.\
Hierna laat hierdie voorreg toe om **'n primary token toe te ken** aan 'n nuwe/gesuspendeerde proses. Met die bevoorregte impersonation token kan jy 'n primary token aflei (DuplicateTokenEx).\
Met die token kan jy 'n **nuwe proses** skep met 'CreateProcessAsUser' of 'n proses geskep in gesuspendeerde toestand en die token stel (in die algemeen kan jy nie die primary token van 'n lopende proses verander nie).

### SeTcbPrivilege

As jy hierdie token geaktiveer het kan jy **KERB_S4U_LOGON** gebruik om 'n **impersonation token** vir enige ander gebruiker te kry sonder om die credentials te ken, **'n arbitraire groep** (admins) by die token voeg, die **integrity level** van die token op "**medium**" stel, en hierdie token aan die **huidige thread** toeken (SetThreadToken).

### SeBackupPrivilege

Hierdie voorreg laat die stelsel toe om **alle lees-toegangsbeheer** tot enige lêer te verleen (beperk tot leesoperasies). Dit word gebruik om die wagwoord-hashs van plaaslike Administrator-rekeninge uit die register te lees, waarna gereedskap soos "**psexec**" of "**wmiexec**" met die hash gebruik kan word (Pass-the-Hash tegniek). Hierdie tegniek faal egter onder twee voorwaardes: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer 'n beleid toegepas is wat administratiewe regte van Local Administrators wat op afstand verbind, verwyder.\
Jy kan **hierdie voorreg misbruik** met:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Hierdie voorreg gee toestemming vir **skryf-toegang** tot enige stelsel-lêer, ongeag die lêer se Access Control List (ACL). Dit bied talle moontlikhede vir eskalasie, insluitend die vermoë om **services te wysig**, DLL Hijacking uit te voer, en **debuggers** via Image File Execution Options in te stel, onder verskeie ander tegnieke.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens te impersonate, maar ook in die afwesigheid van SeImpersonatePrivilege. Hierdie vermoë berus op die vermoë om 'n token te impersonate wat dieselfde gebruiker verteenwoordig en waarvan die integrity level nie hoër is as dié van die huidige proses nie.

**Belangrike punte:**

- **Impersonation sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege te gebruik vir EoP deur tokens te impersonate onder spesifieke voorwaardes.
- **Voorwaardes vir token impersonation:** Suksesvolle impersonation vereis dat die teiken-token aan dieselfde gebruiker behoort en 'n integrity level het wat minder of gelyk is aan die integrity level van die proses wat die impersonation probeer uitvoer.
- **Skepping en wysiging van impersonation tokens:** Gebruikers kan 'n impersonation token skep en dit verbeter deur die SID van 'n bevoorregte groep by te voeg.

### SeLoadDriverPrivilege

Hierdie voorreg laat toe om device drivers te load en unload deur die skepping van 'n register-inskrywing met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte skryf-toegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, moet `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. Om egter `HKCU` herkenbaar aan die kernel te maak vir driver-konfigurasie, moet 'n spesifieke pad gevolg word.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die huidige gebruiker is. Binne `HKCU` moet hierdie hele pad geskep word, en twee waardes gestel word:

- `ImagePath`, wat die pad na die binêre lêer is wat uitgevoer moet word
- `Type`, met 'n waarde van `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Meer maniere om hierdie voorreg te misbruik by [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie maak dit vir 'n proses moontlik om **eienaarskap van 'n objek aan te neem**, en sodoende die vereiste vir eksplisiete diskresionêre toegang te omseil deur die toekenning van WRITE_OWNER-toegangsregte. Die proses behels eers die verkryging van eienaarskap oor die beoogde registersleutel vir skryfdoeleindes, en daarna die aanpassing van die DACL om skryfoperasies toe te laat.
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

Hierdie voorreg maak dit moontlik om die **debug other processes**, insluitend om in die geheue te lees en te skryf. Verskeie strategieë vir memory injection, wat die meeste antivirus- en host intrusion prevention solutions kan omseil, kan met hierdie voorreg aangewend word.

#### Aftap van geheue

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) van die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om **capture the memory of a process**. Dit is veral van toepassing op die **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**-proses, wat verantwoordelik is vir die stoor van gebruikerscredentials sodra 'n gebruiker suksesvol by 'n stelsel aangemeld het.

Jy kan dan hierdie dump in mimikatz laai om wagwoorde te bekom:
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

Hierdie reg (Perform volume maintenance tasks) maak dit moontlik om raw volume device handles (bv. \\.\C:) te open vir direkte disk I/O wat NTFS ACLs omseil. Daarmee kan jy bytes van enige lêer op die volume kopieer deur die onderliggende blocks te lees, wat arbitrêre lêerlesing van sensitiewe materiaal moontlik maak (bv. machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Dit is besonders ernstig op CA-bedieners waar die exfiltratie van die CA private key die vervalsing van 'n Golden Certificate moontlik maak om enige prinsipaal te imiteer.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kontroleer regte
```
whoami /priv
```
Die **tokens wat as Disabled verskyn** kan aangeskakel word; jy kan eintlik beide _Enabled_ en _Disabled_ tokens misbruik.

### Skakel al die tokens aan

As jy tokens as Disabled het, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **script** ingesluit in hierdie [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabel

Volle token-privileges cheatsheet by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die opsomming hieronder lys slegs direkte maniere om die privilege uit te buiten om 'n admin-sessie te verkry of sensitiewe lêers te lees.

| Privilege                  | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Aantekeninge                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Dankie aan [Aurélien Chalot](https://twitter.com/Defte_) vir die opdatering. Ek sal dit binnekort probeer herformuleer in 'n meer resep-agtige vorm.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitiewe lêers met `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Kan meer interessant wees as jy %WINDIR%\MEMORY.DMP kan lees<br><br>- <code>SeBackupPrivilege</code> (en robocopy) is nie nuttig wanneer dit by oop lêers kom nie.<br><br>- Robocopy vereis beide SeBackup en SeRestore om met die /b parameter te werk.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Skep 'n ewekansige token insluitend plaaslike admin-regte met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliceer die `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Die script is te vind by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Laai 'n foutiewe kernel driver soos <code>szkg64.sys</code><br>2. Benut die driver se kwesbaarheid<br><br>Alternatiewelik kan die privilege gebruik word om sekuriteit-verwante drivers te ontlaai met die ingeboude opdrag <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die <code>szkg64</code> kwesbaarheid is gelys as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Die <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> is geskep deur <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Start PowerShell/ISE met die SeRestore-privilege teenwoordig.<br>2. Skakel die privilege aan met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Sluit die konsole en druk Win+U</p> | <p>Aanval kan deur sekere AV-sagteware opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diens-binaries wat in "Program Files" gestoor word met dieselfde privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Sluit die konsole en druk Win+U</p>                                                                                                                                       | <p>Aanval kan deur sekere AV-sagteware opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diens-binaries wat in "Program Files" gestoor word met dieselfde privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuleer tokens sodat plaaslike admin-regte ingesluit is. Mag SeImpersonate vereis.</p><p>Om te verifieer.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Verwysing

- Kyk na hierdie tabel wat Windows-tokens definieer: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Kyk na [**hierdie artikel**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) oor privesc met tokens.
- Microsoft – Voer volume onderhoudstake uit (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Sertifikaat (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
