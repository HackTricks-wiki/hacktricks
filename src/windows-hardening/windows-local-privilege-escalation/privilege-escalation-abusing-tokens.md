# Kutumia Vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Kama **haufahamu ni nini Windows Access Tokens** soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa kutumia tokens uliyonayo tayari**

### SeImpersonatePrivilege

Hii ni privilege ambayo ikishikika na mchakato wowote inaruhusu impersonation (lakini si uundaji) wa token yoyote, kwa sharti kuwa handle yake inaweza kupatikana. Token yenye privilege inaweza kupatikana kutoka kwa service ya Windows (DCOM) kwa kuifanya ifanye NTLM authentication dhidi ya exploit, na baadaye kuruhusu utekelezaji wa mchakato kwa privileges za SYSTEM. Udhaifu huu unaweza kutumika kwa zana mbalimbali, kama [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji winrm kuzimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata privileged token.\
Kisha, privilege hii inaruhusu **kumuongezea primary token** mchakato mpya/uliokatizwa. Ukiwa na impersonation token yenye privilege unaweza kuunda primary token (DuplicateTokenEx).\
Kwa token hiyo, unaweza kuunda **mchakato mpya** kwa kutumia 'CreateProcessAsUser' au kuunda mchakato uliokatizwa na **kuweka token** (kwa ujumla, huwezi kubadilisha primary token ya mchakato unaoendelea).

### SeTcbPrivilege

Kama umewezesha token hii unaweza kutumia **KERB_S4U_LOGON** kupata **impersonation token** ya mtumiaji mwingine bila kujua nywila, **kuongeza group yoyote** (admins) kwa token, kuweka **integrity level** ya token kuwa "**medium**", na kuipa token hii **thread ya sasa** (SetThreadToken).

### SeBackupPrivilege

System inasababisha kupewa **read access zote** kwa faili yoyote (imezuiliwa kwa operesheni za kusoma) kwa kutumia privilege hii. Inatumiwa kusoma hashes za nywila za akaunti za local Administrator kutoka registry, kisha zana kama "**psexec**" au "**wmiexec**" zinaweza kutumika na hash (tekniki ya Pass-the-Hash). Hata hivyo, tekniki hii inashindwa katika hali mbili: wakati akaunti ya Local Administrator imezimwa, au wakati sera inapoweka kuondoa haki za usimamizi kwa Local Administrators wanaoingiliana kwa mbali.\
Unaweza **kunyanyasa privilege hii** kwa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuatilia **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Privilege hii inatoa ruhusa ya **write access** kwa faili yoyote ya mfumo, bila kuzingatia Access Control List (ACL) ya faili. Hii inafungua fursa nyingi za escalation, ikijumuisha uwezo wa **kubadilisha services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options pamoja na mbinu nyingine mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa ku-impersonate tokens, lakini pia inaweza kutumika hata bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa ku-impersonate token inayowakilisha mtumiaji yule yule na ambayo integrity level yake haizidi ile ya mchakato wa sasa.

**Mambo Muhimu:**

- **Impersonation bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa ku-impersonate tokens chini ya vigezo fulani.
- **Vigezo vya Impersonation ya Token:** Impersonation itafanikiwa ikiwa token inayolengwa ni ya mtumiaji yule yule na ina integrity level ambayo ni ndogo au sawa na ile ya mchakato unaojaribu ku-impersonate.
- **Uundaji na Uboreshaji wa Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID ya kundi lenye privilege.

### SeLoadDriverPrivilege

Privilege hii inaruhusu **ku-load na ku-unload device drivers** kwa kuunda entry ya registry yenye values maalum kwa `ImagePath` na `Type`. Kwa kuwa uandishi wa moja kwa moja kwa `HKLM` (HKEY_LOCAL_MACHINE) umezuiliwa, lazima utumie `HKCU` (HKEY_CURRENT_USER) badala yake. Hata hivyo, ili kufanya `HKCU` ijulikane na kernel kwa ajili ya usanidi wa driver, njia maalum inapaswa kufuatwa.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, njia yote hii lazima iundwe, na values mbili lazima ziwe set:

- `ImagePath`, ambayo ni path ya binary itakayotekelezwa
- `Type`, ikiwa na value ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuatwa:**

1. Tumia `HKCU` badala ya `HKLM` kutokana na uandishi uliwekewa vikwazo.
2. Unda path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` kuwa path ya utekelezaji ya binary.
4. Weka `Type` kama `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Njia zaidi za kutumia vibaya ruhusa hii ziko katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu inaruhusu mchakato **kuchukua umiliki wa kitu**, kuepuka hitaji la ufikiaji wa hiari ulio wazi kwa kutoa haki za ufikiaji WRITE_OWNER. Mchakato unahusisha kwanza kupata umiliki wa registry key inayokusudiwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha shughuli za kuandika.
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

Ruhusa hii inatoa uwezo wa **debug other processes**, ikiwa ni pamoja na kusoma na kuandika katika memory. Mikakati mbalimbali ya memory injection, zenye uwezo wa kukwepa antivirus na host intrusion prevention solutions nyingi, zinaweza kutumika kwa ruhusa hii.

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwa [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **capture the memory of a process**. Hasa, hili linaweza kutumika kwa mchakato wa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambao una jukumu la kuhifadhi user credentials mara mtumiaji anapofanikiwa kuingia kwenye mfumo.

Baada yake unaweza kisha kupakia dump hii katika mimikatz ili kupata nywila:
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

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (mfano: \\.\C:) kwa ajili ya I/O ya diski ya moja kwa moja ambayo inapita NTFS ACLs. Kwa kutumia haki hii unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma blocks za chini ya mfumo, kuruhusu kusoma faili yoyote yenye taarifa nyeti (mfano: funguo binafsi za mashine katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Hii ni hatari hasa kwenye CA servers ambapo kuhamisha CA private key kunaruhusu kutengeneza Golden Certificate ili kuiga mhusika yeyote.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kagua vibali
```
whoami /priv
```
Tokens zinazojitokeza kama **Disabled** zinaweza kuwezeshwa; unaweza kwa kweli kutumia vibaya tokens _Enabled_ na _Disabled_.

### Washa tokens zote

Ikiwa una tokens zilizo **Disabled**, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha njia za moja kwa moja tu za kutumia ruhusa ili kupata kikao cha admin au kusoma faili nyeti.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | zana za wahusika wa tatu | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa sasisho. Nitajitahidi kuiandika upya kwa muundo wa hatua hivi karibuni.                                                                                                                                                                                           |
| **`SeBackup`**             | **Tishio**  | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Inaweza kuwa ya kuvutia zaidi ikiwa unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) si msaada linapokuja suala la faili zilizo wazi.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | zana za wahusika wa tatu | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | zana za wahusika wa tatu | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha service binaries zilizohifadhiwa katika "Program Files" kwa kutumia ruhusa ile ile</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha service binaries zilizohifadhiwa katika "Program Files" kwa kutumia ruhusa ile ile.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | zana za wahusika wa tatu | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

- Tazama jedwali hili linaloelezea Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Tazama [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) kuhusu privesc na tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
