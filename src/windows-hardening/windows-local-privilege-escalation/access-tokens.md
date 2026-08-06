# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Kila **user aliyeingia** kwenye mfumo **ana access token yenye taarifa za usalama** kwa ajili ya session hiyo ya kuingia. Mfumo huunda access token user anapoingia. **Kila process inayotekelezwa** kwa niaba ya user **ina nakala ya access token hiyo**. Token hiyo humtambua user, groups za user, na privileges za user. Pia token ina logon SID (Security Identifier) inayotambua session ya sasa ya kuingia.

Unaweza kuona taarifa hizi kwa kutekeleza `whoami /all`
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
au kwa kutumia _Process Explorer_ kutoka Sysinternals (chagua process kisha ufikie kichupo cha"Security"):

![Access Tokens - Access Tokens: au kwa kutumia Process Explorer kutoka Sysinternals (chagua process kisha ufikie kichupo cha"Security")](<../../images/image (772).png>)

### Msimamizi wa ndani

Msimamizi wa ndani anapo-login, **access tokens mbili huundwa**: Moja yenye admin rights na nyingine yenye rights za kawaida. **Kwa default**, mtumiaji huyu anapotekeleza process, ile yenye **regular** (non-administrator) **rights hutumiwa**. Mtumiaji huyu anapojaribu **kutekeleza** kitu chochote **kama administrator** ("Run as Administrator", kwa mfano), **UAC** itatumika kuomba ruhusa.\
Ikiwa ungependa [**kujifunza zaidi kuhusu UAC, soma ukurasa huu**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Kwa vitendo, hii inamaanisha kuwa **admin shell isiyo-elevated kwa kawaida huendeshwa kwa filtered token**. Ndiyo sababu `whoami /groups` mara nyingi huonyesha **`BUILTIN\Administrators` kama `Deny only`** hadi process iwe elevated. Kwa ndani, Windows huhifadhi **linked elevated token** (`TokenLinkedToken`) na kufuatilia hali hiyo kwa fields kama vile `TokenElevationType`.

### Credentials user impersonation

Ikiwa una **credentials halali za mtumiaji mwingine yeyote**, unaweza **kuunda** **new logon session** kwa kutumia credentials hizo:
```
runas /user:domain\username cmd.exe
```
**access token** pia ina **reference** ya **logon sessions** ndani ya **LSASS**; hii ni muhimu ikiwa process inahitaji kufikia baadhi ya objects za network.\
Unaweza kuanzisha process inayotumia **credentials tofauti kwa ajili ya kufikia network services** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
Hii ni muhimu ikiwa una credentials muhimu za kufikia objects zilizo kwenye network, lakini credentials hizo si valid ndani ya host ya sasa kwa sababu zitatumika kwenye network pekee (kwenye host ya sasa privileges za current user zitatumika).

#### Maelezo ya `runas /netonly`

`runas /netonly` (pamoja na C2 helpers kama vile `make_token`) huunda token ya **`LOGON32_LOGON_NEW_CREDENTIALS`**. Hii ni muhimu sana kuielewa wakati wa lateral movement kwa sababu:<sup>[[3]](#references)</sup>

- **Kwenye local**, process mpya hubaki na **local identity** ileile, groups, integrity level, na access decisions nyingi zilezile kutoka kwenye current token.
- **Kwenye remote**, outbound authentication inaweza kutumia **credentials** zilizotolewa kwa SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Kwa hiyo `whoami` bado inaweza kuonyesha **original local user**, huku network access ikifanyika kama **alternate account**.

Hii ni option nzuri wakati credentials ni valid kwenye domain au kwenye host nyingine, lakini user **hawezi au hapaswi kufanya log on locally** kwenye machine ya sasa.

### Aina za tokens

Kuna aina mbili za tokens zinazopatikana:

- **Primary Token**: Hutumika kama representation ya security credentials za process. Uundaji na uhusishaji wa primary tokens na processes ni actions zinazohitaji elevated privileges, jambo linalosisitiza principle ya privilege separation. Kwa kawaida, authentication service huhusika na uundaji wa token, huku logon service ikishughulikia uhusishaji wake na operating system shell ya user. Ni muhimu kutambua kwamba processes hurithi primary token ya parent process yao wakati wa kuundwa.
- **Impersonation Token**: Huwawezesha server application kutumia identity ya client kwa muda ili kufikia secure objects. Mechanism hii imegawanywa katika levels nne za operation:
- **Anonymous**: Humpa server access inayofanana na ya user asiyejulikana.
- **Identification**: Huruhusu server kuthibitisha identity ya client bila kuitumia kufikia objects.
- **Impersonation**: Huwawezesha server kufanya kazi kwa kutumia identity ya client.
- **Delegation**: Inafanana na Impersonation, lakini pia huwezesha server kuendeleza matumizi ya identity hii kwenye remote systems inazowasiliana nazo, huku ikihakikisha credential preservation.

#### Impersonate Tokens

Ukitumia module ya _**incognito**_ ya metasploit na ukiwa na privileges za kutosha, unaweza kwa urahisi **kuorodhesha** na **ku-impersonate** **tokens** nyingine. Hii inaweza kuwa muhimu kufanya **actions kana kwamba wewe ni user mwingine**. Pia unaweza **ku-escalate privileges** kwa kutumia technique hii.

Baadhi ya practical notes ambazo ni rahisi kusahau wakati wa operation:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** inahitaji **`SeImpersonatePrivilege`** kwa caller, na process mpya itaendeshwa kwenye **session ya caller**.
- **`CreateProcessAsUserW`** ndiyo fallback ya kawaida wakati `CreateProcessWithTokenW` inashindwa kwa `1314`, au unapohitaji kuanzisha process kwenye **session iliyoainishwa na token**.
- Ikiwa token imetoka kwenye **`LogonUser(LOGON32_LOGON_NETWORK)`**, kwa kawaida huwa ni **impersonation token**, hivyo unahitaji **`DuplicateTokenEx(..., TokenPrimary, ...)`** kabla ya kujaribu kuanzisha process nayo.
- Si kila impersonation token ina usefulness sawa: **`SecurityIdentification`** hukuruhusu kumchunguza user lakini **si kutenda kama yeye**. Ikiwa coercion primitive au pipe/RPC client inakupa token ya identification-level pekee, kagua **`TokenImpersonationLevel`** na utumie primitive inayotoa **`SecurityImpersonation`** au kiwango cha juu zaidi.

#### Token theft without touching LSASS

Ikiwa tayari una context ya **service** au **SYSTEM**, na **privileged user ameingia**, kuiba au kuduplicate token ya user huyo mara nyingi huwa quieter kuliko kudump **LSASS**. Katika intrusions nyingi halisi, hii inatosha kufanya:<sup>[[2]](#references)</sup>

- kuendesha local actions kama user huyo
- kufikia remote resources kama user huyo
- kufanya AD operations bila kwanza kutoa reusable credentials

Kwa mifano ya **session/user token hijacking** kutoka kwenye privileged context, angalia [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Kumbuka kwamba APIs kama vile **`WTSQueryUserToken`** zilikusudiwa kwa **highly trusted services** na kwa kawaida zinahitaji **`LocalSystem` + `SeTcbPrivilege`**, kwa hiyo huwa muhimu hasa mara tu unapokuwa tayari unadhibiti context ya service-level. Kwa njia za kupata **SYSTEM** kwanza kulingana na privilege, angalia pages zilizo hapa chini.

### Token Privileges

Jifunze ni **token privileges zipi zinaweza kutumiwa vibaya ku-escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Angalia [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
