# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui ni nini Windows Access Tokens** soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kupandisha idhini kwa kutumia vibaya tokens ulizonazo**

### SeImpersonatePrivilege

Hii ni idhini inayomilikiwa na mchakato wowote inayoruhusu impersonation (lakini si uundaji) wa tokeni yoyote, mradi tu kushikilia kwake kupatikane. Tokeni yenye idhini inaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuiamsha ifanye uthibitishaji wa NTLM dhidi ya exploit, na baadaye kuwezesha utekelezaji wa mchakato kwa ruhusa za SYSTEM. Udhaifu huu unaweza kutumika kwa zana mbalimbali, kama vile [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji winrm kuzimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Inafanana sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata tokeni yenye idhini.\
Kisha, idhini hii inaruhusu **kuteua primary token** kwa mchakato mpya/aliyesimamishwa. Kwa tokeni ya impersonation yenye idhini unaweza kupata primary token (DuplicateTokenEx).\
Kwa tokeni hiyo, unaweza kuunda **mchakato mpya** kwa kutumia 'CreateProcessAsUser' au kuunda mchakato uliyesimamishwa na **kuweka tokeni** (kwa ujumla, huwezi kubadilisha primary token ya mchakato unaoendelea).

### SeTcbPrivilege

Ikiwa umewezeshwa idhini hii unaweza kutumia **KERB_S4U_LOGON** kupata tokeni ya impersonation kwa mtumiaji mwingine bila kujua nywila, **kuongeza kikundi chochote** (admins) kwenye tokeni, kuweka kiwango cha integrity cha tokeni kuwa "**medium**", na kuteua tokeni hii kwa **thread ya sasa** (SetThreadToken).

### SeBackupPrivilege

Idhini hii husababisha mfumo kutoa udhibiti wa upatikanaji wa kusoma kwa faili yoyote (ilimwengu kwa operesheni za kusoma). Inatumika kusoma hash za nywila za akaunti za Local Administrator kutoka registry, na baadaye zana kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa na hash (mbinu ya Pass-the-Hash). Hata hivyo, mbinu hii inashindwa katika hali mbili: wakati akaunti ya Local Administrator imezimwa, au wakati sera ipo inayotoa haki za utawala kwa Local Administrators kuunganishwa kwa mbali.\
Unaweza kutumia vibaya idhini hii na:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuatilia **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **escalating privileges with Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Idhini hii inatoa ruhusa ya **kuandika** kwa faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili. Hii inafungua fursa nyingi za kupandisha idhini, ikiwemo uwezo wa **kubadilisha services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options miongoni mwa mbinu nyingine mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa muhimu wakati mtumiaji ana uwezo wa kuiga tokeni, lakini pia inaweza kuwa muhimu hata bila SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa kuiga tokeni inayowakilisha mtumiaji yule yule na ambayo kiwango chake cha integrity hakizidi cha mchakato wa sasa.

Mambo Muhimu:

- **Impersonation bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa kuiga tokeni chini ya masharti maalum.
- **Masharti ya Kuiga Tokeni:** Kuiga kwa mafanikio kunahitaji tokeni lengwa kuwa ya mtumiaji yule yule na kuwa na kiwango cha integrity kilicho ndogo au sawa na cha mchakato unaojaribu kuiga.
- **Kuunda na Kubadilisha Tokeni za Impersonation:** Watumiaji wanaweza kuunda tokeni ya impersonation na kuiboresha kwa kuongeza SID ya kikundi chenye idhini (privileged group's SID).

### SeLoadDriverPrivilege

Idhini hii inaruhusu kupakia na kuondoa device drivers kwa kuunda entry kwenye registry yenye thamani maalum za `ImagePath` na `Type`. Kwa kuwa ufikiaji wa kuandika moja kwa moja kwenye `HKLM` (HKEY_LOCAL_MACHINE) umepunguzwa, lazima utumie `HKCU` (HKEY_CURRENT_USER) badala yake. Hata hivyo, ili kufanya `HKCU` itambulike na kernel kwa usanidi wa driver, njia maalum lazima itumike.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, njia nzima hii lazima iundwe, na thamani mbili ziwawekwa:

- `ImagePath`, ambayo ni njia ya binary itakayotekelezwa
- `Type`, yenye thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

Hatua za Kufuatwa:

1. Tumia `HKCU` badala ya `HKLM` kutokana na ufikiaji wa kuandika uliowekwa.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` kuwa njia ya utekelezaji ya binary.
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

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu inaruhusu mchakato **kuchukua umiliki wa kitu**, kwa kuzunguka hitaji la upatikanaji wa hiari uliobainishwa kwa kutoa haki za upatikanaji WRITE_OWNER. Mchakato unahusisha kwanza kupata umiliki wa kifunguo cha rejista kilichokusudiwa kwa ajili ya kuandika, kisha kubadilisha DACL ili kuwezesha operesheni za kuandika.
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

Utendaji huu unaruhusu **debug other processes**, ikiwemo kusoma na kuandika katika kumbukumbu. Mbinu mbalimbali za kuingiza kumbukumbu, zenye uwezo wa kuepuka antivirus nyingi na suluhisho za host intrusion prevention, zinaweza kutumika kwa ruhusa hii.

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwa [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kuchukua kumbukumbu ya mchakato**. Hii hasa inaweza kutumika kwa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** mchakato, ambao unahusika na kuhifadhi vitambulisho vya watumiaji mara mtumiaji anapofanikiwa kuingia kwenye mfumo.

Baadaye unaweza kupakia dump hii katika mimikatz ili kupata nywila:
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

Haki hii (Perform volume maintenance tasks) inaruhusu kufungua raw volume device handles (mfano, \\.\C:) kwa ajili ya I/O ya diski ya moja kwa moja ambayo inapita NTFS ACLs. Kwa kutumia haki hii unaweza kunakili bytes za faili yoyote kwenye volume kwa kusoma blocks za msingi, na hivyo kuwezesha kusoma faili yoyote ya taarifa nyeti (kwa mfano, machine private keys katika %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Inakuwa hasa na athari kubwa kwenye server za CA ambapo exfiltrating CA private key kunaruhusu kutengeneza Golden Certificate ili kuiga principal yoyote.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Kagua vibali
```
whoami /priv
```
Tokens ambazo zinaonekana kama **Disabled** zinaweza kuamilishwa; unaweza kwa kweli kutumia vibaya token za _Enabled_ na _Disabled_.

### Wezesha tokens zote

Iwapo una tokens disabled, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) ili kuamilisha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Au **script** iliyowekwa katika [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Cheatsheet kamili ya token privileges iko kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), muhtasari hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege ili kupata session ya admin au kusoma faili nyeti.

| Privilege                  | Athari      | Chombo                  | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                 | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | chombo cha mtu wa tatu  | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa sasisho. Nitajaribu kuibadilisha kwa muundo wa hatua hivi karibuni.                                                                                                                                                                                                    |
| **`SeBackup`**             | **Tishio**  | _**Amri za mfumo**_    | Soma faili nyeti kwa kutumia `robocopy /b`                                                                                                                                                                                                                                                                                                        | <p>- Inaweza kuwa ya kuvutia zaidi kama unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (na robocopy) haitumiki pale inapotokea faili wazi.<br><br>- Robocopy inahitaji SeBackup na SeRestore ili kufanya kazi na parametro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | chombo cha mtu wa tatu  | Tunga token yoyote ikijumuisha haki za admin za eneo kwa kutumia <code>NtCreateToken</code>.                                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Nakili token ya <code>lsass.exe</code>.                                                                                                                                                                                                                                                                                                           | Script inaweza kupatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                               |
| **`SeLoadDriver`**         | _**Admin**_ | chombo cha mtu wa tatu  | <p>1. Pakia driver ya kernel yenye hitilafu kama <code>szkg64.sys</code><br>2. Tumia udhaifu wa driver<br><br>Vinginevyo, privilege inaweza kutumika kuondoa drivers zinazohusiana na usalama kwa amri built-in ya <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Udhaifu wa <code>szkg64</code> umeorodheshwa kama <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <a href="https://www.greyhathacker.net/?p=1025">Exploit code</a> ya <code>szkg64</code> ilitengenezwa na <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Anzisha PowerShell/ISE ukiwa na SeRestore privilege ipo.<br>2. Washa privilege kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Badilisha jina la utilman.exe kwenda utilman.old<br>4. Badilisha jina la cmd.exe kwenda utilman.exe<br>5. Funga console na bonyeza Win+U</p> | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha binaries za service zilizohifadhiwa katika "Program Files" kwa kutumia privilege ile ile</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Amri za mfumo**_    | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina la cmd.exe kwenda utilman.exe<br>4. Funga console na bonyeza Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha binaries za service zilizohifadhiwa katika "Program Files" kwa kutumia privilege ile ile.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | chombo cha mtu wa tatu  | <p>Badilisha tokens ili ziwe na haki za admin za eneo. Inaweza kuhitaji SeImpersonate.</p><p>Imepaswa kuthibitishwa.</p>                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |

## Marejeo

- Angalia jedwali hili linalofafanua Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Angalia [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) kuhusu privesc kwa tokens.
- Microsoft – Fanya shughuli za matengenezo ya volume (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
