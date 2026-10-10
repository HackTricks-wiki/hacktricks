# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Kila process ina **primary access token** inayofafanua muktadha wake wa usalama. Thread kwa kawaida hutumia token hiyo, lakini inaweza pia kuwa na **impersonation token** kwa muda. Tokens huwa na SID ya mtumiaji, SIDs za makundi, privileges, taarifa za integrity, na logon SID ya kipindi cha logon. Kwa kawaida, processes hurithi marejeleo ya primary token ya process mzazi; hazipokei nakala huru ya maudhui yake.<sup>[[4]](#references)</sup>

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

au kutumia _Process Explorer_ kutoka Sysinternals (chagua process na ufungue kichupo cha "Security"):

![Access Tokens - Access Tokens: au kutumia Process Explorer kutoka Sysinternals (chagua process na ufungue kichupo cha "Security")](<../../images/image (772).png>)

### Msimamizi wa ndani

Wakati **UAC Admin Approval Mode** inatumika kwa msimamizi, logon shirikishi huunda tokeni kamili ya msimamizi na tokeni iliyochujwa. Explorer na michakato ya kawaida ya child hutumia tokeni iliyochujwa kwa chaguomsingi. Ombi la kupata ruhusa za juu, kama vile **Run as administrator**, huomba UAC ianzishe programu kwa kutumia tokeni kamili. Tabia halisi hutofautiana kwa akaunti ya Administrator iliyojengewa ndani na wakati Admin Approval Mode imezimwa.<sup>[[5]](#references)</sup>

Soma [**ukurasa wa UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) maalum kwa mbinu za kukwepa na maelezo ya sera.

Kwa vitendo, hii inamaanisha kuwa **admin shell isiyo na ruhusa za juu kwa kawaida hutumia tokeni iliyochujwa**. Ndiyo sababu `whoami /groups` mara nyingi huonyesha **`BUILTIN\Administrators` kama `Deny only`** hadi process ipandishwe ruhusa. Kwa ndani, Windows huhifadhi **tokeni iliyounganishwa yenye ruhusa za juu** (`TokenLinkedToken`) na kufuatilia hali kwa sehemu kama `TokenElevationType`.

### Kuiga mtumiaji kwa kutumia credentials

Ikiwa una **credentials halali za mtumiaji mwingine yeyote**, unaweza **kuunda** **logon session** mpya kwa kutumia credentials hizo:

```
runas /user:domain\username cmd.exe
```

**access token** pia ina **rejea** ya vipindi vya kuingia vilivyo ndani ya **LSASS**; hii ni muhimu ikiwa mchakato unahitaji kufikia baadhi ya vitu vya mtandao.\
Unaweza kuanzisha mchakato **unaotumia vitambulisho tofauti kufikia huduma za mtandao** kwa kutumia:

```
runas /user:domain\username /netonly cmd.exe
```

Hii ni muhimu ikiwa una credentials zinazofaa kufikia objects kwenye mtandao, lakini credentials hizo si halali ndani ya host ya sasa, kwa kuwa zitatumika tu kwenye mtandao (kwenye host ya sasa, privileges za mtumiaji wako wa sasa zitatumika).

#### Maelezo ya `runas /netonly`

`runas /netonly` (na zana saidizi za C2 kama `make_token`) huunda tokeni ya **`LOGON32_LOGON_NEW_CREDENTIALS`**. Ni muhimu sana kuelewa hili wakati wa lateral movement kwa sababu:<sup>[[3]](#references)</sup>

- **Kwenye mashine ya ndani**, process mpya huhifadhi **utambulisho uleule wa ndani**, vikundi, kiwango cha integrity, na maamuzi mengi yale yale ya ufikiaji kama tokeni ya sasa.
- **Kwa mifumo ya mbali**, uthibitishaji wa miunganisho inayotoka unaweza kutumia **credentials zilizotolewa** kwa SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Kwa hiyo `whoami` bado inaweza kuonyesha **mtumiaji wa awali wa ndani** huku ufikiaji wa mtandao ukifanyika kama **akaunti mbadala**.

Hili ni chaguo bora ikiwa credentials ni halali kwenye domain au host nyingine, lakini mtumiaji **hawezi au hapaswi kuingia kwenye mashine ya sasa**.

### Aina za tokeni

Kuna aina mbili za tokeni zinazopatikana:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Huakisi muktadha wa usalama wa process. Kwa kawaida child hurithi primary token ya parent wake, ilhali API za kuunda process zinazotumia tokeni maalum huweka masharti yao ya ufikiaji wa tokeni na privileges za mpigaji.
- **Impersonation token**: Huruhusu thread ya server kutumia kwa muda muktadha wa usalama wa client kwa ajili ya ukaguzi wa ufikiaji. Ina viwango vinne:
  - **Anonymous**: Humpa server ufikiaji unaofanana na wa mtumiaji asiyejulikana.
  - **Identification**: Huruhusu server kuthibitisha utambulisho wa client bila kuutumia kufikia objects.
  - **Impersonation**: Huwezesha server kufanya kazi kwa kutumia utambulisho wa client.
  - **Delegation**: Huruhusu server kumwigiza client kwenye mifumo ya mbali pale ambapo mfumo wa uthibitishaji na usanidi wa akaunti unaunga mkono delegation.

#### Kagua tokeni iliyokamatwa kabla ya kuitumia

Usichague tokeni kwa kuangalia username pekee. Akaunti ileile inaweza kuwa na tokeni kadhaa zenye logon sessions, service SIDs, privileges, viwango vya integrity, vizuizi, na credentials za mtandao tofauti.<sup>[[9]](#references)</sup> Tumia `GetTokenInformation` kuulizia angalau **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`**, na **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Tokeni iliyozuiliwa inaweza kuwa na SIDs za deny-only, privileges zilizoondolewa, na SIDs za vizuizi. SIDs za vizuizi zinapokuwepo, Windows hufanya ukaguzi mmoja wa ufikiaji kwa SIDs zilizowezeshwa na mwingine kwa SIDs za vizuizi; **ukaguzi wote wawili lazima uruhusu ufikiaji**. Kwa hiyo, SID ya mtumiaji inayovutia au kikundi kilichowezeshwa kwenye matokeo haithibitishi peke yake kwamba tokeni inaweza kufikia object inayolengwa.<sup>[[8]](#references)</sup>

Tumia mfuatano huu wa maamuzi kwa mahitaji yaliyoandikwa ya tokeni na uundaji wa process:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token** inahitaji handle yenye `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` kabla ya kutolewa kwa `CreateProcessWithTokenW` au `CreateProcessAsUserW`.
2. Geuza **impersonation token** kwa `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeni za kiwango cha Identification zinaweza kufichua data ya utambulisho, lakini haziwezi kufanya ukaguzi wa ufikiaji kana kwamba ni client huyo.
3. `CreateProcessWithTokenW` inahitaji `SeImpersonatePrivilege` na huanzisha child kwenye session ya mpigaji. Kinyume chake, `CreateProcessAsUserW` hutumia session ya tokeni na kwa kawaida huhitaji `SeIncreaseQuotaPrivilege`; inaweza pia kuhitaji `SeAssignPrimaryTokenPrivilege`. Ikiwa credentials zinapatikana lakini privileges hizi hazipo, `CreateProcessWithLogonW` ndiyo njia mbadala iliyoandikwa.

#### Tafuta handles za tokeni, si wamiliki wa process pekee

Kufungua primary token ya kila process kunaweza kukosa **impersonation tokens zilizohifadhiwa kama handles za kawaida** ndani ya services na broker processes. Utaratibu unaoweza kutumiwa tena wa kuchunguza handle tables ni kuorodhesha handles za mfumo, kuchuja objects za tokeni, kufungua kila mmiliki kwa `PROCESS_DUP_HANDLE`, kunakili handle inayohusika kwenye process ya sasa, kisha kuulizia sehemu zilizotajwa hapo juu. Thibitisha kuwa handle iliyonakiliwa ina `TOKEN_QUERY` na `TOKEN_DUPLICATE`; kuona handle ya tokeni hakumaanishi inaweza kunakiliwa na kuwa primary token inayoweza kutumika. Bado, protected processes na process DACLs zinaweza kuzuia handle ya process ya mmiliki.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` huendesha kiotomatiki uorodheshaji wa primary token za process na handles za tokeni zilizohifadhiwa. `list_token` huhifadhi mgombea mmoja anayopendelewa kwa kila username, huku `list_all_token` ikichapisha kila mgombea. PID hupunguza uorodheshaji kwa process moja ya mmiliki.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Kwa ukaguzi wa mikono na kuthibitisha ufikiaji, **TokenUniverse** inaweza kufungua tokens za process/thread, kutafuta handles za token zilizopo, kukagua vizuizi na vipindi vya kuingia, kunakili tokens, na kujaribu mbinu kadhaa za kuunda process.<sup>[[13]](#references)</sup> Kwa primitive ya msingi ya handle kati ya process, angalia:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Kwa kutumia module ya _**incognito**_ ya metasploit, ukiwa na privileges za kutosha unaweza kwa urahisi **kuorodhesha** na **kuiga** **tokens** za wengine. Hii inaweza kusaidia kufanya **vitendo kana kwamba wewe ni mtumiaji mwingine**. Unaweza pia **kuongeza privileges** kwa kutumia mbinu hii.

Vidokezo vya vitendo ambavyo ni rahisi kusahau unapofanya kazi:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** inahitaji mwitaji awe na **`SeImpersonatePrivilege`**, na process mpya itaendeshwa katika **session ya mwitaji**.
- **`CreateProcessAsUserW`** ni njia mbadala inayowezekana wakati `CreateProcessWithTokenW` inashindwa kwa hitilafu `1314`, lakini tu ikiwa mwitaji anatimiza mahitaji yake ya privileges. Pia ndiyo chaguo sahihi wakati child inapaswa kuendeshwa katika **session iliyorejelewa na token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Ikiwa token imetoka kwa **`LogonUser(LOGON32_LOGON_NETWORK)`**, kwa kawaida huwa **impersonation token**, kwa hiyo unahitaji **`DuplicateTokenEx(..., TokenPrimary, ...)`** kabla ya kujaribu kuanzisha process nayo.
- Si kila impersonation token ina manufaa sawa: **`SecurityIdentification`** hukuruhusu kumkagua mtumiaji lakini **si kutenda kama yeye**. Ikiwa primitive ya coercion au client ya pipe/RPC inakupa token ya kiwango cha identification pekee, kagua **`TokenImpersonationLevel`** na utumie primitive inayotoa **`SecurityImpersonation`** au kiwango cha juu zaidi.

#### Kuiba Token bila kugusa LSASS

Ikiwa tayari una muktadha wa **service** au **SYSTEM**, na **mtumiaji mwenye privileges za juu ameingia**, kuiba au kunakili token ya mtumiaji huyo mara nyingi huvutia umakini mdogo kuliko kudump **LSASS**. Katika uvamizi mwingi wa kweli, hii inatosha:<sup>[[2]](#references)</sup>

- kutekeleza vitendo vya ndani kama mtumiaji huyo
- kufikia rasilimali za mbali kama mtumiaji huyo
- kufanya shughuli za AD bila kwanza kutoa credentials zinazoweza kutumika tena

Kwa mifano ya **kuteka session/token ya mtumiaji** kutoka kwenye muktadha wenye privileges za juu, angalia [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Kumbuka kuwa API kama **`WTSQueryUserToken`** zimekusudiwa **services zinazoaminika sana** na kwa kawaida zinahitaji **`LocalSystem` + `SeTcbPrivilege`**, kwa hiyo zina manufaa hasa pale ambapo tayari unadhibiti muktadha wa kiwango cha service. Kwa mbinu zinazohusiana na privileges za kupata **SYSTEM** kwanza, angalia kurasa zilizo hapa chini.

### Token Privileges

Jifunze ni **token privileges zipi zinaweza kutumiwa vibaya ili kuongeza privileges:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Angalia [**token privileges zote zinazowezekana na baadhi ya ufafanuzi kwenye ukurasa huu wa nje**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Kuelewa na Kutumia Vibaya Access Tokens — Sehemu ya II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Kutumia Vibaya Windows tokens kuhatarisha Active Directory bila kugusa LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Kufafanua Amri ya "make_token" ya Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Jinsi User Account Control inavyofanya kazi - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Viwango vya Impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Hesabu ya TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokens Zilizozuiwa - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Function ya CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Function ya CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Function ya DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
