# Tokeni za Ufikiaji

{{#include ../../banners/hacktricks-training.md}}

## Tokeni za Ufikiaji

Kila mchakato una **tokeni ya msingi ya ufikiaji** inayobainisha muktadha wake wa usalama. Kwa kawaida thread hutumia tokeni hiyo, lakini inaweza pia kuwa na **tokeni ya uigaji** kwa muda. Tokeni zina SID ya mtumiaji, SID za vikundi, ruhusa, taarifa za uadilifu, na SID ya kuingia kwa kipindi cha kuingia. Kwa kawaida, michakato hurithi rejeleo la tokeni ya msingi ya mchakato mzazi; haipokei nakala huru ya yaliyomo kwenye tokeni hiyo.<sup>[[4]](#references)</sup>

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

au kutumia _Process Explorer_ kutoka Sysinternals (chagua mchakato na ufungue kichupo cha "Security"):

![Tokeni za Ufikiaji - Tokeni za Ufikiaji: au kutumia Process Explorer kutoka Sysinternals (chagua mchakato na ufungue kichupo cha "Security")](<../../images/image (772).png>)

### Msimamizi wa ndani

Wakati **UAC Admin Approval Mode** inatumika kwa msimamizi, kuingia kwenye mfumo kwa njia ingiliani huunda tokeni kamili ya msimamizi na tokeni iliyochujwa. Explorer na michakato ya kawaida inayozinduliwa na mchakato mwingine hutumia tokeni iliyochujwa kwa chaguomsingi. Ombi la kuinua ruhusa, kama vile **Run as administrator**, huomba UAC ianzishe programu kwa kutumia tokeni kamili. Tabia halisi hutofautiana kwa akaunti ya msimamizi iliyojengewa ndani na wakati Admin Approval Mode imezimwa.<sup>[[5]](#references)</sup>

Soma [**ukurasa maalum wa UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) kwa mbinu za kuikwepa na maelezo ya sera.

Kwa vitendo, hii inamaanisha kuwa **shell ya msimamizi ambayo haijainuliwa kwa kawaida hutumia tokeni iliyochujwa**. Ndiyo sababu `whoami /groups` mara nyingi huonyesha **`BUILTIN\Administrators` kama `Deny only`** hadi mchakato unapoinuliwa. Kwa ndani, Windows huhifadhi **tokeni iliyounganishwa yenye ruhusa zilizoinuliwa** (`TokenLinkedToken`) na kufuatilia hali kwa kutumia sehemu kama vile `TokenElevationType`.

### Uigaji wa mtumiaji kwa kutumia credentials

Ikiwa una **credentials halali za mtumiaji mwingine yeyote**, unaweza **kuunda** **kikao kipya cha kuingia** kwa kutumia credentials hizo :

```
runas /user:domain\username cmd.exe
```

**access token** pia ina **reference** ya **logon sessions** ndani ya **LSASS**. Hii ni muhimu ikiwa process inahitaji kufikia baadhi ya objects za network.\
Unaweza kuzindua process inayotumia **credentials tofauti kufikia network services** kwa kutumia:

```
runas /user:domain\username /netonly cmd.exe
```

Hii ni muhimu ikiwa una credentials zinazoweza kufikia objects kwenye mtandao, lakini credentials hizo si halali ndani ya host ya sasa, kwa kuwa zitatumika tu kwenye mtandao (kwenye host ya sasa zitatumika privileges za mtumiaji wako wa sasa).

#### Maelezo ya `runas /netonly`

`runas /netonly` (na C2 helpers kama `make_token`) huunda token ya **`LOGON32_LOGON_NEW_CREDENTIALS`**. Hii ni muhimu sana kuelewa wakati wa lateral movement kwa sababu:<sup>[[3]](#references)</sup>

- **Ndani ya mashine**, process mpya huhifadhi **utambulisho uleule wa ndani**, groups, integrity level, na maamuzi mengi yale yale ya ufikiaji kama token ya sasa.
- **Kwa mbali**, uthibitishaji wa miunganisho inayotoka unaweza kutumia **credentials zilizotolewa** kwa SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Kwa hiyo, `whoami` bado inaweza kuonyesha **mtumiaji yuleyule wa ndani**, huku ufikiaji wa mtandao ukifanyika kwa kutumia **akaunti mbadala**.

Hii ni chaguo zuri wakati credentials ni halali kwenye domain au host nyingine, lakini mtumiaji **hawezi au hapaswi kuingia ndani ya mashine** ya sasa.

### Aina za token

Kuna aina mbili za token zinazopatikana:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Huonyesha muktadha wa usalama wa process. Kwa kawaida child hurithi primary token ya parent wake, huku API za kuunda process kwa token maalum zikiwa na masharti yake ya ufikiaji wa token na privileges za caller.
- **Impersonation token**: Huruhusu thread ya server kutumia kwa muda muktadha wa usalama wa client kwa ukaguzi wa ufikiaji. Ina viwango vinne:
  - **Anonymous**: Hutoa ufikiaji wa server unaofanana na ule wa mtumiaji asiyejulikana.
  - **Identification**: Huruhusu server kuthibitisha utambulisho wa client bila kuutumia kufikia objects.
  - **Impersonation**: Huruhusu server kufanya kazi kwa kutumia utambulisho wa client.
  - **Delegation**: Huruhusu server kuiga client kwenye mifumo ya mbali wakati utaratibu wa uthibitishaji na usanidi wa akaunti unaruhusu delegation.

#### Chunguza token iliyonaswa kabla ya kuitumia

Usichague token kwa kutegemea username pekee. Akaunti ileile inaweza kuwa na token kadhaa zenye logon sessions, service SIDs, privileges, integrity levels, restrictions, na network credentials tofauti.<sup>[[9]](#references)</sup> Tumia `GetTokenInformation` kuuliza angalau **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, na **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Token yenye restrictions inaweza kuwa na SIDs za deny-only, privileges zilizoondolewa, na restricting SIDs. Ikiwa restricting SIDs zipo, Windows hufanya ukaguzi mmoja wa ufikiaji kwa kutumia SIDs zilizowezeshwa na mwingine kwa kutumia restricting SIDs; **ukaguzi wote wawili lazima uruhusu ufikiaji**. Kwa hiyo, SID ya mtumiaji inayoonekana kuvutia au group iliyowezeshwa kwenye matokeo haithibitishi yenyewe kuwa token inaweza kufikia object lengwa.<sup>[[8]](#references)</sup>

Tumia mtiririko huu wa maamuzi kwa mahitaji yaliyoandikwa ya token na uundaji wa process:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token** inahitaji handle yenye `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` kabla ya kupewa `CreateProcessWithTokenW` au `CreateProcessAsUserW`.
2. Badilisha **impersonation token** kwa kutumia `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Token za kiwango cha Identification zinaweza kufichua data ya utambulisho lakini haziwezi kufanya ukaguzi wa ufikiaji kwa niaba ya client huyo.
3. `CreateProcessWithTokenW` inahitaji `SeImpersonatePrivilege` na huanzisha child kwenye session ya caller. Badala yake, `CreateProcessAsUserW` hutumia session ya token, lakini kwa kawaida inahitaji `SeIncreaseQuotaPrivilege` na inaweza kuhitaji `SeAssignPrimaryTokenPrivilege`. Ikiwa credentials zinapatikana lakini privileges hizi hazipo, `CreateProcessWithLogonW` ndiyo mbadala ulioandikwa.

#### Tafuta handles za token, si wamiliki wa process pekee

Kufungua primary token ya kila process kunaweza kukosa **impersonation tokens zilizohifadhiwa kama handles za kawaida** ndani ya services na broker processes. Njia ya kutumia tena jedwali la handles ni kuorodhesha system handles, kuchuja token objects, kufungua kila owner kwa `PROCESS_DUP_HANDLE`, kunakili handle inayoshukiwa hadi kwenye process ya sasa, kisha kuuliza sehemu zilizo hapo juu. Hakikisha handle iliyonakiliwa ina `TOKEN_QUERY` na `TOKEN_DUPLICATE`; kuona handle ya token hakumaanishi kuwa inaweza kunakiliwa na kutumika kama primary token. Process zilizolindwa na process DACLs bado zinaweza kuzuia handle ya owner-process.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` huendesha kiotomatiki uorodheshaji wa process-primary-token na retained-token-handle. `list_token` huhifadhi mgombea mmoja anayopendelewa kwa kila username, huku `list_all_token` ikichapisha kila mgombea. PID huweka kikomo cha uorodheshaji kwa process moja ya owner.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Kwa ukaguzi wa mikono na uthibitishaji wa ufikiaji, **TokenUniverse** inaweza kufungua token za process/thread, kutafuta handle za token zilizopo, kukagua vizuizi na logon sessions, kunakili token, na kujaribu mbinu kadhaa za kuunda process.<sup>[[13]](#references)</sup> Kwa primitive ya msingi ya handle kati ya process, tazama:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Tafuta token za impersonation za thread zilizo hai

Thread ya service inaweza kuiga client kwa muda hata kama **process primary token** yake ni ya akaunti ya service; kwa hiyo, ukaguzi wa wamiliki wa process unaweza kukosa muktadha wa client.<sup>[[4]](#references)</sup> TokenUniverse inaweza kuorodhesha token za process/thread zinazofikika; katika System Informer, kagua kichupo cha **Threads** cha process na safu yake ya **Impersonation** ili kupata thread zinazoweza kufaa.<sup>[[13]](#references)[[14]](#references)</sup>

Kwa ukaguzi unaolenga API, tengeneza snapshot ya `TH32CS_SNAPTHREAD`, chuja `THREADENTRY32.th32OwnerProcessID` ili ilingane na PID ya service, kisha kwa kila thread inayofikika, ita `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` na `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` hufanya ukaguzi wa ufikiaji wa kufungua token utumie muktadha wa **process** ya caller; hili ni muhimu ikiwa scanner yenyewe inaiga katika kiwango cha identification.<sup>[[17]](#references)</sup> Uliza token kuhusu mtumiaji wake, aina, kiwango cha impersonation na logon ID kabla ya kujaribu mtiririko wa kunakili token/kuunda process ulioelezwa hapo juu.<sup>[[7]](#references)</sup> Thread inaweza kuacha kuiga kati ya kuorodhesha na kufungua; kutokuwepo kwa token, token za anonymous, thread zilizolindwa, thread DACL na token DACL vinaweza kuzuia ukusanyaji.<sup>[[16]](#references)[[17]](#references)</sup> Tofauti na kuchanganua handle za token zilizohifadhiwa na service, njia hii hukagua **token ya thread iliyokabidhiwa kwa sasa**.

Kwa njia ya mashambulizi inayopata token ya thread kwa kumfanya client mwenye upendeleo aunganishe kwenye pipe yako badala ya kuchanganua thread zilizopo, tazama [named-pipe client impersonation](named-pipe-client-impersonation.md).

#### Impersonate Tokens

Ukitumia moduli ya _**incognito**_ ya metasploit na una upendeleo wa kutosha, unaweza kwa urahisi **kuorodhesha** na **kuiga** **token** za wengine. Hii inaweza kukusaidia kutekeleza **vitendo kana kwamba wewe ni mtumiaji mwingine**. Unaweza pia **kuongeza upendeleo** kwa kutumia mbinu hii.

Mambo kadhaa ya vitendo ambayo ni rahisi kusahau unapofanya kazi:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** inahitaji caller awe na **`SeImpersonatePrivilege`**, na process mpya itaendeshwa katika **session ya caller**.
- **`CreateProcessAsUserW`** ni njia mbadala inayowezekana wakati `CreateProcessWithTokenW` inashindwa kwa `1314`, lakini tu ikiwa caller anakidhi masharti yake ya upendeleo. Pia ndiyo chaguo sahihi wakati child inapaswa kuendeshwa katika **session inayorejelewa na token**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** hurejesha **impersonation token**. Ibadilishe kwa `DuplicateTokenEx(..., TokenPrimary, ...)` kabla ya kuunda process. Hata baada ya kubadilishwa, process inayotokana haiwezi kutumia logon hiyo ya network kufikia share au printer za mbali zinazohitaji uthibitishaji: aina hii ya logon haihifadhi credentials. Tumia logon ya interactive au network-cleartext ikiwa una credentials na unahitaji ufikiaji zaidi wa network; usichanganye hili na `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), ambayo huhifadhi utambulisho wa ndani huku ikitoa credentials za kutoka nje.<sup>[[18]](#references)</sup>
- Si kila impersonation token ina manufaa sawa: **`SecurityIdentification`** hukuruhusu kukagua mtumiaji lakini **si kutenda kama yeye**. Ikiwa primitive ya coercion au client wa pipe/RPC anakupa token ya kiwango cha identification pekee, kagua **`TokenImpersonationLevel`** na utumie primitive inayotoa **`SecurityImpersonation`** au kiwango cha juu zaidi.

#### Wizi wa token bila kugusa LSASS

Ikiwa tayari una muktadha wa **service** au **SYSTEM**, na **mtumiaji mwenye upendeleo ameingia**, kuiba au kunakili token ya mtumiaji huyo mara nyingi ni tulivu zaidi kuliko kutupa **LSASS**. Katika uvamizi mwingi wa kweli, hatua hii inatosha:<sup>[[2]](#references)</sup>

- kutekeleza vitendo vya ndani kama mtumiaji huyo
- kufikia rasilimali za mbali kama mtumiaji huyo
- kutekeleza shughuli za AD bila kwanza kutoa credentials zinazoweza kutumika tena

Kwa mifano ya **session/user token hijacking** kutoka kwenye muktadha wenye upendeleo, angalia [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Kumbuka kwamba API kama **`WTSQueryUserToken`** zimekusudiwa kwa **service zinazoaminika sana** na kwa kawaida zinahitaji **`LocalSystem` + `SeTcbPrivilege`**; kwa hiyo, huwa na manufaa hasa pale ambapo tayari unadhibiti muktadha wa kiwango cha service. Kwa njia zinazohusiana na upendeleo za kupata **SYSTEM** kwanza, angalia kurasa zilizo hapa chini.

### Token Privileges

Jifunze ni **token privileges zipi zinaweza kutumiwa vibaya kuongeza upendeleo:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Tazama [**token privileges zote zinazowezekana na baadhi ya ufafanuzi kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Kuelewa na Kutumia Vibaya Access Tokens — Sehemu ya II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Kutumia vibaya token za Windows kuhatarisha Active Directory bila kugusa LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Kufafanua Amri ya "make_token" ya Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Jinsi User Account Control inavyofanya kazi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Viwango vya Impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Orodhesho la TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Token Zilizowekewa Vizuizi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Kitendakazi cha CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Kitendakazi cha CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Kitendakazi cha DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Ombi la kipengele cha thread-token katika System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Kupitia orodha ya thread - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
