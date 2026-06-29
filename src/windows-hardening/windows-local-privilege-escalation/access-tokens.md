# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Kila **mtumiaji aliyeingia** kwenye mfumo **anashikilia access token yenye taarifa za security** kwa ajili ya logon session hiyo. Mfumo huunda access token wakati mtumiaji anaingia. **Kila process iliyotekelezwa** kwa niaba ya mtumiaji **ina nakala ya access token**. Token hutambulisha mtumiaji, groups za mtumiaji, na privileges za mtumiaji. Token pia ina logon SID (Security Identifier) inayotambulisha current logon session.

Unaweza kuona taarifa hii kwa kutekeleza `whoami /all`
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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Wakati local administrator anaingia, **access token mbili zinaundwa**: Moja ikiwa na admin rights na nyingine ikiwa na rights za kawaida. **By default**, mtumiaji huyu anapotekeleza process, ile iliyo na **regular** (non-administrator) **rights hutumika**. Mtumiaji huyu anapojaribu **execute** kitu chochote **as administrator** (kwa mfano "Run as Administrator"), **UAC** itatumika kuomba ruhusa.\
Kama unataka [**kujifunza zaidi kuhusu UAC soma ukurasa huu**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

Kwa vitendo, hii maana yake ni kwamba **non-elevated admin shell kwa kawaida huendeshwa na filtered token**. Ndiyo sababu `whoami /groups` mara nyingi huonyesha **`BUILTIN\Administrators` kama `Deny only`** hadi process ipandishwe kiwango. Ndani kwa ndani, Windows huhifadhi **linked elevated token** (`TokenLinkedToken`) na hufuatilia hali kwa fields kama `TokenElevationType`.

### Credentials user impersonation

Ukisasa **valid credentials za mtumiaji mwingine yeyote**, unaweza **create** **new logon session** na credentials hizo :
```
runas /user:domain\username cmd.exe
```
The **access token** pia ina **reference** ya logon sessions ndani ya **LSASS**, hii ni muhimu ikiwa mchakato unahitaji kufikia baadhi ya objects za network.\
Unaweza kuanzisha mchakato unaotumia **different credentials for accessing network services** kwa kutumia:
```
runas /user:domain\username /netonly cmd.exe
```
Hii ni muhimu ikiwa una credentials muhimu za kufikia objects kwenye network lakini credentials hizo si valid ndani ya host ya sasa kwa sababu zitatumika tu kwenye network (ndani ya host ya sasa, privileges za user wako wa sasa zitatumika).

#### `runas /netonly` details

`runas /netonly` (na C2 helpers kama `make_token`) huunda token ya **`LOGON32_LOGON_NEW_CREDENTIALS`**. Hii ni muhimu sana kuielewa wakati wa lateral movement kwa sababu:

- **Locally**, process mpya huhifadhi **same local identity**, groups, integrity level, na sehemu kubwa ya access decisions zilezile kama current token.
- **Remotely**, outbound authentication inaweza kutumia **supplied credentials** kwa SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Kwa hiyo `whoami` huenda ikaonyesha bado **original local user** huku network access ikifanyika kama **alternate account**.

Hili ni chaguo zuri sana wakati credentials ni valid ndani ya domain au kwenye host nyingine, lakini user **hawezi au hapaswi ku-log on locally** kwenye machine ya sasa.

### Types of tokens

Kuna aina mbili za tokens zinazopatikana:

- **Primary Token**: Hutumika kama uwakilishi wa security credentials za process. Uundaji na uhusishaji wa primary tokens na processes ni actions zinazohitaji elevated privileges, zikisisitiza kanuni ya privilege separation. Kwa kawaida, authentication service inawajibika kwa kuunda token, huku logon service ikishughulikia uhusishaji wake na shell ya operating system ya user. Ni muhimu kutambua kuwa processes hurithi primary token ya parent process yao wakati wa kuundwa.
- **Impersonation Token**: Huipa server application uwezo wa kuchukua identity ya client kwa muda ili kufikia secure objects. Utaratibu huu umegawanywa katika levels nne za operation:
- **Anonymous**: Hutoa access ya server sawa na ile ya unidentified user.
- **Identification**: Huruhusu server kuthibitisha identity ya client bila kuitumia kwa object access.
- **Impersonation**: Huwezesha server kufanya kazi chini ya identity ya client.
- **Delegation**: Sawa na Impersonation lakini huongeza uwezo wa kuendeleza kuchukua identity hii hadi kwenye remote systems ambazo server inashirikiana nazo, ikihakikisha credential preservation.

#### Impersonate Tokens

Kwa kutumia module ya _**incognito**_ ya metasploit ukiwa na privileges za kutosha unaweza kwa urahisi **kufanya list** na **kuimpersonate** **tokens** za wengine. Hii inaweza kuwa muhimu kufanya **actions kana kwamba wewe ni user mwingine**. Unaweza pia **ku-escalate privileges** kwa technique hii.

Baadhi ya maelezo ya vitendo ambayo ni rahisi kusahau wakati wa operesheni:

- **`CreateProcessWithTokenW`** inahitaji **`SeImpersonatePrivilege`** kwa caller na process mpya itaendeshwa katika **session ya caller**.
- **`CreateProcessAsUserW`** ni fallback ya kawaida wakati `CreateProcessWithTokenW` inaposhindwa na `1314`, au unapohitaji kuanzisha kwenye **session inayorejelewa na token**.
- Ikiwa token inatoka kwenye **`LogonUser(LOGON32_LOGON_NETWORK)`**, kwa kawaida ni **impersonation token**, kwa hiyo unahitaji **`DuplicateTokenEx(..., TokenPrimary, ...)`** kabla ya kujaribu kuanzisha process nayo.
- Sio kila impersonation token ni yenye manufaa sawa: **`SecurityIdentification`** inakuwezesha kukagua user lakini **si kutenda kama yeye**. Ikiwa coercion primitive au pipe/RPC client inakupa tu token ya kiwango cha identification, angalia **`TokenImpersonationLevel`** na badilisha kwenda primitive inayotoa **`SecurityImpersonation`** au bora zaidi.

#### Token theft without touching LSASS

Ikiwa tayari una context ya **service** au **SYSTEM** na **privileged user yuko logged on**, kuiba au ku-d duplicate token ya user huyo mara nyingi ni kimya zaidi kuliko dumping **LSASS**. Katika intrusions nyingi halisi hii inatosha kwa:

- ku-run local actions kama user huyo
- kufikia remote resources kama user huyo
- kufanya AD operations bila kwanza kutoa reusable credentials

Kwa mifano ya **session/user token hijacking** kutoka kwa privileged context, angalia [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Kumbuka kwamba APIs kama **`WTSQueryUserToken`** zimetengenezwa kwa ajili ya **highly trusted services** na kwa kawaida zinahitaji **`LocalSystem` + `SeTcbPrivilege`**, hivyo huwa muhimu zaidi mara tu ukiwa tayari unadhibiti service-level context. Kwa njia mahususi za kupata **SYSTEM** kwanza, angalia kurasa zilizo hapa chini.

### Token Privileges

Jifunze ni **token privileges** zipi zinaweza kutumiwa vibaya ku-escalate privileges:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Angalia [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
