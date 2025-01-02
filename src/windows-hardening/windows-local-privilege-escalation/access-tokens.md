# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Kila **mtumiaji aliyeingia** kwenye mfumo **ana tokeni ya ufikiaji yenye taarifa za usalama** kwa ajili ya kikao hicho cha kuingia. Mfumo huunda tokeni ya ufikiaji wakati mtumiaji anapoingia. **Kila mchakato unaotekelezwa** kwa niaba ya mtumiaji **una nakala ya tokeni ya ufikiaji**. Tokeni inatambulisha mtumiaji, vikundi vya mtumiaji, na ruhusa za mtumiaji. Tokeni pia ina SID ya kuingia (Identifier ya Usalama) inayotambulisha kikao cha sasa cha kuingia.

Unaweza kuona taarifa hii ukitekeleza `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
au kutumia _Process Explorer_ kutoka Sysinternals (chagua mchakato na ufikia "Security" tab):

![](<../../images/image (772).png>)

### Msimamizi wa ndani

Wakati msimamizi wa ndani anapoingia, **tokeni mbili za ufikiaji zinaundwa**: Moja ikiwa na haki za msimamizi na nyingine ikiwa na haki za kawaida. **Kwa default**, wakati mtumiaji huyu anatekeleza mchakato, ile yenye **haki za kawaida** (zisizo za msimamizi) **inatumika**. Wakati mtumiaji huyu anajaribu **kutekeleza** chochote **kama msimamizi** ("Run as Administrator" kwa mfano) **UAC** itatumika kuomba ruhusa.\
Ikiwa unataka [**kujifunza zaidi kuhusu UAC soma ukurasa huu**](../authentication-credentials-uac-and-efs/#uac)**.**

### Ujanja wa utambulisho wa mtumiaji

Ikiwa una **uthibitisho halali wa mtumiaji mwingine yeyote**, unaweza **kuunda** **sehemu mpya ya kuingia** kwa kutumia uthibitisho huo:
```
runas /user:domain\username cmd.exe
```
**access token** pia ina **reference** ya vikao vya kuingia ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kufikia vitu fulani vya mtandao.\
Unaweza kuzindua mchakato ambao **unatumia akidi tofauti za kufikia huduma za mtandao** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
Hii ni muhimu ikiwa una akreditif muhimu za kufikia vitu katika mtandao lakini akreditif hizo si halali ndani ya mwenyeji wa sasa kwani zitakuwa zinatumika tu katika mtandao (katika mwenyeji wa sasa, ruhusa za mtumiaji wako wa sasa zitatumika).

### Aina za tokeni

Kuna aina mbili za tokeni zinazopatikana:

- **Tokeni Kuu**: Inatumika kama uwakilishi wa akreditif za usalama za mchakato. Uundaji na uhusiano wa tokeni kuu na michakato ni vitendo vinavyohitaji ruhusa za juu, ikisisitiza kanuni ya kutenganisha ruhusa. Kwa kawaida, huduma ya uthibitishaji inawajibika kwa uundaji wa tokeni, wakati huduma ya kuingia inashughulikia uhusiano wake na shell ya mfumo wa uendeshaji wa mtumiaji. Inafaa kutajwa kwamba michakato inarithi tokeni kuu ya mchakato wake mzazi wakati wa uundaji.
- **Tokeni ya Kuiga**: Inamuwezesha programu ya seva kuchukua kitambulisho cha mteja kwa muda ili kufikia vitu salama. Mekanismu hii imegawanywa katika ngazi nne za uendeshaji:
- **Kujulikana**: Inatoa ufikiaji wa seva kama wa mtumiaji asiyejulikana.
- **Utambulisho**: Inaruhusu seva kuthibitisha kitambulisho cha mteja bila kukitumia kwa ufikiaji wa vitu.
- **Kuiga**: Inamwezesha seva kufanya kazi chini ya kitambulisho cha mteja.
- **Delegation**: Kama Kuiga lakini inajumuisha uwezo wa kupanua dhana hii ya kitambulisho kwa mifumo ya mbali ambayo seva inawasiliana nayo, kuhakikisha uhifadhi wa akreditif.

#### Tokeni za Kuiga

Kwa kutumia moduli ya _**incognito**_ ya metasploit ikiwa una ruhusa za kutosha unaweza kwa urahisi **orodhesha** na **kuiga** tokeni nyingine **. Hii inaweza kuwa muhimu kufanya **vitendo kana kwamba wewe ni mtumiaji mwingine**. Unaweza pia **kuinua ruhusa** kwa kutumia mbinu hii.

### Ruhusa za Tokeni

Jifunze ni zipi **ruhusa za tokeni zinaweza kutumika vibaya ili kuinua ruhusa:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Angalia [**ruhusa zote zinazowezekana za tokeni na baadhi ya maelezo kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).

## Marejeo

Jifunze zaidi kuhusu tokeni katika mafunzo haya: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) na [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
