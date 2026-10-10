# Toegangstokens

{{#include ../../banners/hacktricks-training.md}}

## Toegangstokens

Elke proses het ’n **primêre toegangstoken** wat sy sekuriteitskonteks definieer. ’n Thread gebruik gewoonlik daardie token, maar kan ook tydelik ’n **impersonation token** hê. Tokens bevat die gebruiker se SID, groep-SID’s, regte, integriteitsinligting en ’n logon-SID vir die aanmeldingsessie. Prosesse erf gewoonlik ’n verwysing na die ouerproses se primêre token; hulle ontvang nie ’n onafhanklike kopie van die inhoud daarvan nie.<sup>[[4]](#references)</sup>

Jy kan hierdie inligting sien deur `whoami /all` uit te voer.

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

of deur _Process Explorer_ van Sysinternals te gebruik (kies die proses en gaan na die "Security"-oortjie):

![Access Tokens - Toegangtokens: of deur Process Explorer van Sysinternals te gebruik (kies die proses en gaan na die "Security"-oortjie)](<../../images/image (772).png>)

### Plaaslike administrateur

Wanneer **UAC Admin Approval Mode** op ’n administrateur van toepassing is, skep die interaktiewe aanmelding ’n volledige administrateurtoken en ’n gefiltreerde token. Explorer en gewone kinderprosesse gebruik by verstek die gefiltreerde token. ’n Versoek om te verhoog, soos **Run as administrator**, vra UAC om die program met die volledige token te begin. Die presiese gedrag verskil vir die ingeboude Administrator-rekening en wanneer Admin Approval Mode gedeaktiveer is.<sup>[[5]](#references)</sup>

Lees die toegewyde [**UAC-bladsy**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) vir omseiltegnieke en beleidsbesonderhede.

In die praktyk beteken dit dat ’n **nie-verhoogde administrateurshell gewoonlik met ’n gefiltreerde token loop**. Daarom wys `whoami /groups` dikwels **`BUILTIN\Administrators` as `Deny only`** totdat die proses verhoog word. Intern hou Windows ’n **gekoppelde verhoogde token** (`TokenLinkedToken`) by en volg dit die toestand met velde soos `TokenElevationType`.

### Gebruikersnabootsing met geloofsbriewe

As jy **geldige geloofsbriewe van enige ander gebruiker** het, kan jy ’n **nuwe aanmeldingsessie** met daardie geloofsbriewe **skep**:

```
runas /user:domain\username cmd.exe
```

Die **access token** het ook ’n **verwysing** na die aanmeldsessies binne **LSASS**. Dit is nuttig as die proses toegang tot sekere netwerkobjekte moet kry.\
Jy kan ’n proses begin wat **ander geloofsbriewe gebruik om toegang tot netwerkdienste te verkry** met:

```
runas /user:domain\username /netonly cmd.exe
```

Dit is nuttig as jy bruikbare geloofsbriewe het om toegang tot voorwerpe in die netwerk te kry, maar daardie geloofsbriewe nie geldig is op die huidige gasheer nie, aangesien dit slegs in die netwerk gebruik gaan word (op die huidige gasheer sal jou huidige gebruiker se regte gebruik word).

#### `runas /netonly`-besonderhede

`runas /netonly` (en C2-hulpmiddels soos `make_token`) skep ’n **`LOGON32_LOGON_NEW_CREDENTIALS`**-token. Dit is baie nuttig om tydens laterale beweging te verstaan, omdat:<sup>[[3]](#references)</sup>

- **Plaaslik** behou die nuwe proses **dieselfde plaaslike identiteit**, groepe, integriteitsvlak en die meeste van dieselfde toegangsbesluite as die huidige token.
- **Afgeleë** kan uitgaande verifikasie die **verskafte geloofsbriewe** vir SMB / WinRM / LDAP / HTTP / Kerberos / NTLM gebruik.
- Daarom kan `whoami` steeds die **oorspronklike plaaslike gebruiker** wys terwyl netwerktoegang as die **alternatiewe rekening** plaasvind.

Dit is ’n uitstekende opsie wanneer die geloofsbriewe geldig is in die domein of op ’n ander gasheer, maar die gebruiker **nie plaaslik op die huidige masjien kan of behoort aan te meld nie**.

### Tipes tokens

Daar is twee tipes tokens beskikbaar:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primêre token**: Verteenwoordig ’n proses se sekuriteitskonteks. ’n Kindproses erf normaalweg sy ouer se primêre token, terwyl die API’s vir proseskepping met ’n eksplisiete token hul eie vereistes vir tokentoegang en oproeperregte stel.
- **Nabootsingstoken**: Laat ’n bedienerdraad tydelik ’n kliënt se sekuriteitskonteks vir toegangskontroles gebruik. Dit het vier vlakke:
  - **Anoniem**: Verleen die bediener toegang soortgelyk aan dié van ’n ongeïdentifiseerde gebruiker.
  - **Identifikasie**: Laat die bediener die kliënt se identiteit verifieer sonder om dit vir toegang tot voorwerpe te gebruik.
  - **Nabootsing**: Laat die bediener onder die kliënt se identiteit werk.
  - **Delegasie**: Laat die bediener die kliënt op afgeleë stelsels naboots wanneer die verifikasiemeganisme en rekeningkonfigurasie delegasie ondersteun.

#### Beoordeel ’n vasgelegde token voordat jy dit gebruik

Moenie ’n token slegs op grond van die gebruikersnaam kies nie. Dieselfde rekening kan verskeie tokens hê met verskillende aanmeldsessies, diens-SID’s, regte, integriteitsvlakke, beperkings en netwerkbewyse.<sup>[[9]](#references)</sup> Vra ten minste vir **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** en **`TokenStatistics.AuthenticationId`** met `GetTokenInformation`.<sup>[[7]](#references)</sup>

’n Beperkte token kan SIDs bevat wat slegs vir weiering gebruik word, verwyderde regte en beperkende SIDs. Wanneer beperkende SIDs bestaan, voer Windows een toegangskontrole met die geaktiveerde SIDs uit en nog een met die beperkende SIDs; **albei kontroles moet toegang toelaat**. Daarom bewys ’n aantreklike gebruikers-SID of ’n geaktiveerde groep in die uitvoer op sigself nie dat die token toegang tot die teikenvoorwerp kan kry nie.<sup>[[8]](#references)</sup>

Gebruik hierdie besluitvloeidiagram vir die gedokumenteerde vereistes vir tokens en proseskepping:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. ’n **Primêre token** benodig ’n handvatsel met `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` voordat dit aan `CreateProcessWithTokenW` of `CreateProcessAsUserW` verskaf kan word.
2. Skakel ’n **nabootsingstoken** om met `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokens op identifikasievlak kan identiteitsdata blootstel, maar kan nie toegangskontroles namens daardie kliënt uitvoer nie.
3. `CreateProcessWithTokenW` benodig `SeImpersonatePrivilege` en begin die kindproses in die oproeper se sessie. `CreateProcessAsUserW` gebruik eerder die token se sessie, maar benodig gewoonlik `SeIncreaseQuotaPrivilege` en kan `SeAssignPrimaryTokenPrivilege` benodig. As geloofsbriewe beskikbaar is, maar hierdie regte ontbreek, is `CreateProcessWithLogonW` die gedokumenteerde alternatief.

#### Soek tokenhandvatsels, nie net proseseienaars nie

As jy elke proses se primêre token oopmaak, kan jy **nabootsingstokens wat as gewone handvatsels** binne dienste en makelaarprosesse behou word, miskyk. ’n Herbruikbare handvatseltabel-werkvloei is om stelselhandvatsels op te som, vir tokenvoorwerpe te filter, elke eienaar met `PROCESS_DUP_HANDLE` oop te maak, die kandidaat-handvatsel na die huidige proses te dupliseer en dan die bogenoemde velde te bevraagteken. Bevestig dat die gedupliseerde handvatsel `TOKEN_QUERY` en `TOKEN_DUPLICATE` insluit; die blote teenwoordigheid van ’n tokenhandvatsel beteken nie dat dit na ’n bruikbare primêre token gedupliseer kan word nie. Beskermde prosesse en proses-DACL’s kan steeds toegang tot die eienaarproses se handvatsel blokkeer.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` outomatiseer die opsomming van beide primêre prosestokens en behoue tokenhandvatsels. `list_token` behou een voorkeurkandidaat per gebruikernaam, terwyl `list_all_token` elke kandidaat druk. ’n PID beperk die opsomming tot een eienaarproses.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Vir handmatige inspeksie en toegangsverifikasie kan **TokenUniverse** proses-/thread-tokens oopmaak, bestaande tokenhandles soek, beperkings en aanmeldingsessies inspekteer, tokens dupliseer en verskeie metodes vir proseskepping toets.<sup>[[13]](#references)</sup> Sien die volgende vir die onderliggende primitive vir handles tussen prosesse:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

As jy genoeg voorregte het, kan jy die _**incognito**_-module van metasploit gebruik om maklik ander **tokens** te **lys** en na te **boots**. Dit kan nuttig wees om **aksies uit te voer asof jy die ander gebruiker is**. Jy kan ook **voorregte eskaleer** met hierdie tegniek.

’n Paar praktiese notas wat maklik is om te vergeet terwyl jy werk:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** vereis **`SeImpersonatePrivilege`** van die aanroeper, en die nuwe proses sal in die **aanroeper se sessie** loop.
- **`CreateProcessAsUserW`** is ’n moontlike terugvalopsie wanneer `CreateProcessWithTokenW` met `1314` misluk, maar slegs as die aanroeper aan die voorregvereistes daarvoor voldoen. Dit is ook die korrekte keuse wanneer die child in die **sessie waarna die token verwys** moet loop.<sup>[[9]](#references)[[10]](#references)</sup>
- As ’n token van **`LogonUser(LOGON32_LOGON_NETWORK)`** kom, is dit gewoonlik ’n **impersonation-token**. Jy moet dus **`DuplicateTokenEx(..., TokenPrimary, ...)`** gebruik voordat jy daarmee ’n proses probeer begin.
- Nie elke impersonation-token is ewe bruikbaar nie: **`SecurityIdentification`** laat jou die gebruiker inspekteer, maar **nie namens hulle optree nie**. As ’n coercion-primitive of pipe/RPC-kliënt jou net ’n token op identifikasievlak gee, gaan **`TokenImpersonationLevel`** na en skakel oor na ’n primitive wat **`SecurityImpersonation`** of hoër oplewer.

#### Token theft without touching LSASS

As jy reeds ’n **service**- of **SYSTEM**-konteks het en ’n **bevoorregte gebruiker aangemeld is**, is dit dikwels stiller om daardie gebruiker se token te steel of te dupliseer as om **LSASS** te dump. In baie werklike inbrake is dit genoeg om:<sup>[[2]](#references)</sup>

- plaaslike aksies as daardie gebruiker uit te voer
- toegang tot afgeleë hulpbronne as daardie gebruiker te kry
- AD-bewerkings uit te voer sonder om eers herbruikbare geloofsbriewe te onttrek

Kyk na [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) vir voorbeelde van **sessie-/gebruikertoken-kaping** vanuit ’n bevoorregte konteks. Onthou dat API’s soos **`WTSQueryUserToken`** vir **hoogs vertroude services** bedoel is en normaalweg **`LocalSystem` + `SeTcbPrivilege`** vereis. Daarom is hulle hoofsaaklik nuttig wanneer jy reeds ’n service-vlakkonteks beheer. Kyk na die bladsye hieronder vir metodes om eers **SYSTEM** te verkry wat spesifieke voorregte vereis.

### Token Privileges

Leer watter **tokenvoorregte misbruik kan word om voorregte te eskaleer:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Kyk na [**al die moontlike tokenvoorregte en ’n paar definisies op hierdie eksterne bladsy**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Verstaan en misbruik van Access Tokens — Deel II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Misbruik van Windows-tokens om Active Directory te kompromitteer sonder om aan LSASS te raak](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strike se "make_token"-opdrag ontrafel](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Hoe User Account Control werk - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation-vlakke - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS-enumerasie - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Beperkte tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW-funksie - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW-funksie - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle-funksie - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
