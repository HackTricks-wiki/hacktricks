# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui ni nini Windows Access Tokens** soma ukurasa huu kabla ya kuendelea:

{{#ref}}
access-tokens.md
{{#endref}}

**Labda unaweza kuwa na uwezo wa kupandisha mamlaka kwa kutumia tokens ulizonazo tayari**

### SeImpersonatePrivilege

Hii ni mamlaka ambayo inashikiliwa na mchakato wowote inayo ruhusu uigaji (lakini si uundaji) wa token yoyote, ikiwa tu mkono wake unaweza kupatikana. Token yenye mamlaka inaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuifanya ifanye uthibitishaji wa NTLM dhidi ya exploit, na hivyo kuwezesha utekelezaji wa mchakato wenye mamlaka ya SYSTEM. Uthibitisho huu unaweza kutumika kwa kutumia zana mbalimbali, kama [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (ambayo inahitaji winrm iwe imezimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Ni sawa sana na **SeImpersonatePrivilege**, itatumia **njia ile ile** kupata token yenye mamlaka.\
Kisha, mamlaka hii inaruhusu **kupewa token ya msingi** kwa mchakato mpya/uliokamatwa. Kwa token ya uigaji yenye mamlaka unaweza kuunda token ya msingi (DuplicateTokenEx).\
Kwa token hiyo, unaweza kuunda **mchakato mpya** kwa 'CreateProcessAsUser' au kuunda mchakato uliokamatwa na **kuiweka token** (kwa ujumla, huwezi kubadilisha token ya msingi ya mchakato unaoendelea).

### SeTcbPrivilege

Ikiwa umewezesha token hii unaweza kutumia **KERB_S4U_LOGON** kupata **token ya uigaji** kwa mtumiaji mwingine yeyote bila kujua nywila, **ongeza kundi lolote** (admins) kwenye token, weka **kiwango cha uaminifu** cha token kuwa "**medium**", na kupewa token hii kwa **thread ya sasa** (SetThreadToken).

### SeBackupPrivilege

Mfumo unalazimishwa **kutoa udhibiti wa ufikiaji wa kusoma** kwa faili yoyote (iliyopunguzwa kwa operesheni za kusoma) kwa mamlaka hii. Inatumika kwa **kusoma hash za nywila za akaunti za Msimamizi wa ndani** kutoka kwenye rejista, baada ya hapo, zana kama "**psexec**" au "**wmiexec**" zinaweza kutumika na hash hiyo (Pass-the-Hash technique). Hata hivyo, mbinu hii inashindwa chini ya hali mbili: wakati akaunti ya Msimamizi wa ndani imezimwa, au wakati sera ipo inayondoa haki za kiutawala kutoka kwa Wasimamizi wa ndani wanaounganisha kwa mbali.\
Unaweza **kuitumia mamlaka hii** kwa:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kufuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **kupandisha mamlaka na Opereta wa Backup** ya:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ruhusa ya **ufikiaji wa kuandika** kwa faili yoyote ya mfumo, bila kujali Orodha ya Udhibiti wa Ufikiaji (ACL) ya faili hiyo, inatolewa na mamlaka hii. Inafungua uwezekano mwingi wa kupandisha mamlaka, ikiwa ni pamoja na uwezo wa **kubadilisha huduma**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Chaguzi za Utekelezaji wa Faili ya Picha kati ya mbinu nyingine mbalimbali.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, hasa inavyofaa wakati mtumiaji ana uwezo wa kuigiza tokens, lakini pia katika ukosefu wa SeImpersonatePrivilege. Uwezo huu unategemea uwezo wa kuigiza token inayowakilisha mtumiaji yule yule na ambayo kiwango chake cha uaminifu hakizidi kile cha mchakato wa sasa.

**Mambo Muhimu:**

- **Uigaji bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa kuigiza tokens chini ya hali maalum.
- **Hali za Uigaji wa Token:** Uigaji wa mafanikio unahitaji token lengwa kuwa ya mtumiaji yule yule na kuwa na kiwango cha uaminifu ambacho ni kidogo au sawa na kiwango cha uaminifu cha mchakato unaojaribu kuigiza.
- **Uundaji na Ubadilishaji wa Tokens za Uigaji:** Watumiaji wanaweza kuunda token ya uigaji na kuiboresha kwa kuongeza SID ya kundi lenye mamlaka (Security Identifier).

### SeLoadDriverPrivilege

Mamlaka hii inaruhusu **kupakia na kuondoa madereva ya vifaa** kwa kuunda kipengee cha rejista chenye thamani maalum za `ImagePath` na `Type`. Kwa kuwa ufikiaji wa moja kwa moja wa kuandika kwenye `HKLM` (HKEY_LOCAL_MACHINE) umepunguzika, `HKCU` (HKEY_CURRENT_USER) lazima itumike badala yake. Hata hivyo, ili kufanya `HKCU` itambulike kwa kernel kwa ajili ya usanidi wa dereva, njia maalum lazima ifuatwe.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Kitambulisho cha Kijamii cha mtumiaji wa sasa. Ndani ya `HKCU`, njia hii yote lazima iundwe, na thamani mbili zinahitaji kuwekwa:

- `ImagePath`, ambayo ni njia ya binary itakayotekelezwa
- `Type`, ikiwa na thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuatia:**

1. Fikia `HKCU` badala ya `HKLM` kutokana na ufikiaji wa kuandika uliozuiliwa.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Kitambulisho cha Kijamii cha mtumiaji wa sasa.
3. Weka `ImagePath` kuwa njia ya utekelezaji wa binary.
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
Zaidi ya njia za kutumia ruhusa hii katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii ni sawa na **SeRestorePrivilege**. Kazi yake kuu inaruhusu mchakato **kuchukua umiliki wa kitu**, ikiepuka hitaji la ufikiaji wa hiari kupitia utoaji wa haki za WRITE_OWNER. Mchakato unahusisha kwanza kupata umiliki wa funguo za rejista zinazokusudiwa kwa madhumuni ya kuandika, kisha kubadilisha DACL ili kuwezesha operesheni za kuandika.
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

Haki hii inaruhusu **kudebug mchakato mingine**, ikiwa ni pamoja na kusoma na kuandika katika kumbukumbu. Mikakati mbalimbali ya kuingiza kumbukumbu, inayoweza kukwepa suluhisho nyingi za antivirus na uzuiaji wa uvamizi wa mwenyeji, zinaweza kutumika na haki hii.

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwa [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kukamata kumbukumbu ya mchakato**. Kwa hakika, hii inaweza kutumika kwa mchakato wa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambao unawajibika kuhifadhi akidi za mtumiaji mara tu mtumiaji anapofanikiwa kuingia kwenye mfumo.

Kisha unaweza kupakia dump hii katika mimikatz ili kupata nywila:
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
## Angalia mamlaka
```
whoami /priv
```
The **tokens that appear as Disabled** zinaweza kuwezeshwa, unaweza kweli kutumia _Enabled_ na _Disabled_ tokens.

### Wezesha Tokens Zote

Ikiwa una tokens zilizozuiliwa, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha tokens zote:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Soma faili nyeti kwa kutumia `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Inaweza kuwa ya kuvutia zaidi ikiwa unaweza kusoma %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (na robocopy) si ya msaada linapokuja suala la kufungua faili.<br><br>- Robocopy inahitaji SeBackup na SeRestore kufanya kazi na /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Unda token isiyo na mipaka ikiwa ni pamoja na haki za admin za ndani kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Nakili token ya `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script inapatikana katika [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Pakia dereva wa kernel wenye makosa kama <code>szkg64.sys</code><br>2. Fanya matumizi ya udhaifu wa dereva<br><br>Vinginevyo, haki hiyo inaweza kutumika kuondoa madereva yanayohusiana na usalama kwa kutumia amri ya ndani <code>ftlMC</code>. yaani: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Udhaifu wa <code>szkg64</code> umeorodheshwa kama <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">kanuni ya udhaifu</a> iliundwa na <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Anzisha PowerShell/ISE ikiwa na haki ya SeRestore.<br>2. Wezesha haki hiyo kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha utilman.exe kuwa utilman.old<br>4. Badilisha cmd.exe kuwa utilman.exe<br>5. Funga konso na bonyeza Win+U</p> | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha binaries za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha cmd.exe kuwa utilman.exe<br>4. Funga konso na bonyeza Win+U</p>                                                                                                                                       | <p>Shambulio linaweza kugunduliwa na baadhi ya programu za AV.</p><p>Njia mbadala inategemea kubadilisha binaries za huduma zilizohifadhiwa katika "Program Files" kwa kutumia haki hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens ili kuwa na haki za admin za ndani. Inaweza kuhitaji SeImpersonate.</p><p>Kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.

{{#include ../../banners/hacktricks-training.md}}
