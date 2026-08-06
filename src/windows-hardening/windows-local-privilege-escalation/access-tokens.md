# Toegangtokens

{{#include ../../banners/hacktricks-training.md}}

## Toegangtokens

Elke **gebruiker wat by die stelsel aangemeld is, besit 'n toegangstoken met sekuriteitsinligting** vir daardie aanmeldingsessie. Die stelsel skep 'n toegangstoken wanneer die gebruiker aanmeld. **Elke proses wat** namens die gebruiker **uitgevoer word**, **het 'n kopie van die toegangstoken**. Die token identifiseer die gebruiker, die gebruiker se groepe en die gebruiker se voorregte. 'n Token bevat ook 'n aanmeld-SID (Security Identifier) wat die huidige aanmeldingsessie identifiseer.

Jy kan hierdie inligting sien deur `whoami /all` uit te voer
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
of deur _Process Explorer_ van Sysinternals te gebruik (kies die proses en maak die "Security"-oortjie oop):

![Access Tokens - Access Tokens: of deur Process Explorer van Sysinternals te gebruik (kies proses en maak "Security"-oortjie oop)](<../../images/image (772).png>)

### Plaaslike administrator

Wanneer 'n plaaslike administrator aanmeld, word **twee access tokens geskep**: Een met administrator-regte en die ander een met normale regte. **By verstek**, wanneer hierdie gebruiker 'n proses uitvoer, word die een met **gewone** (nie-administrator-)**regte gebruik**. Wanneer hierdie gebruiker enigiets **as administrator probeer uitvoer** ("Run as Administrator", byvoorbeeld), sal die **UAC** gebruik word om toestemming te vra.\
As jy [**meer oor die UAC wil leer, lees hierdie bladsy**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In praktyk beteken dit dat 'n **nie-verhoogde administrator-shell gewoonlik met 'n gefiltreerde token loop**. Daarom wys `whoami /groups` dikwels **`BUILTIN\Administrators` as `Deny only`** totdat die proses verhoog word. Intern hou Windows 'n **gekoppelde verhoogde token** (`TokenLinkedToken`) en hou dit die toestand dop met velde soos `TokenElevationType`.

### Nabootsing van 'n gebruiker met credentials

As jy **geldige credentials van enige ander gebruiker het**, kan jy 'n **nuwe aanmeldingsessie** met daardie credentials **skep**:
```
runas /user:domain\username cmd.exe
```
Die **access token** bevat ook 'n **reference** na die logon-sessies binne **LSASS**. Dit is nuttig indien die process toegang tot sommige network objects benodig.\
Jy kan 'n process begin wat **verskillende credentials gebruik om toegang tot network services te verkry** deur die volgende te gebruik:
```
runas /user:domain\username /netonly cmd.exe
```
Dit is nuttig as jy geldige credentials het om toegang tot objekte in die netwerk te verkry, maar daardie credentials is nie geldig binne die huidige host nie, omdat hulle slegs in die netwerk gebruik gaan word (op die huidige host sal jou huidige user privileges gebruik word).

#### `runas /netonly` details

`runas /netonly` (en C2 helpers soos `make_token`) skep ’n **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Dit is baie nuttig om tydens lateral movement te verstaan, omdat:<sup>[[3]](#references)</sup>

- **Plaaslik** behou die nuwe proses dieselfde **local identity**, groepe, integrity level en die meeste van dieselfde access decisions as die huidige token.
- **Op afstand** kan outbound authentication die **supplied credentials** vir SMB / WinRM / LDAP / HTTP / Kerberos / NTLM gebruik.
- Daarom kan `whoami` steeds die **oorspronklike local user** wys, terwyl network access as die **alternate account** plaasvind.

Dit is ’n uitstekende opsie wanneer die credentials geldig is in die domain of op ’n ander host, maar die user **nie plaaslik kan of behoort aan te meld** by die huidige machine nie.

### Tipes tokens

Daar is twee tipes tokens beskikbaar:

- **Primary Token**: Dit dien as ’n voorstelling van ’n proses se security credentials. Die skepping en assosiasie van primary tokens met prosesse is aksies wat elevated privileges vereis, wat die beginsel van privilege separation beklemtoon. Gewoonlik is ’n authentication service verantwoordelik vir token-skepping, terwyl ’n logon service die assosiasie daarvan met die user se operating system shell hanteer. Dit is belangrik om daarop te let dat prosesse die primary token van hul parent process by skepping erf.
- **Impersonation Token**: Stel ’n server application in staat om die client se identity tydelik aan te neem om toegang tot secure objects te verkry. Hierdie meganisme word in vier operationele vlakke verdeel:
- **Anonymous**: Verleen die server toegang soortgelyk aan dié van ’n ongeïdentifiseerde user.
- **Identification**: Laat die server toe om die client se identity te verifieer sonder om dit vir object access te gebruik.
- **Impersonation**: Stel die server in staat om onder die client se identity te funksioneer.
- **Delegation**: Soortgelyk aan Impersonation, maar sluit die vermoë in om hierdie identity-aanname uit te brei na remote systems waarmee die server interaksie het, terwyl credential preservation verseker word.

#### Impersonate Tokens

Deur die _**incognito**_ module van metasploit te gebruik, kan jy, indien jy genoeg privileges het, maklik ander **tokens** **list** en **impersonate**. Dit kan nuttig wees om **actions as if you were the other user** uit te voer. Jy kan ook met hierdie tegniek **privileges escalate**.

Sommige praktiese notas wat maklik vergeet word tydens operating:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** vereis **`SeImpersonatePrivilege`** in die caller, en die nuwe proses sal in die **caller's session** loop.
- **`CreateProcessAsUserW`** is die gewone fallback wanneer **`CreateProcessWithTokenW`** met `1314` faal, of wanneer jy in die **session referenced by the token** moet launch.
- As ’n token van **`LogonUser(LOGON32_LOGON_NETWORK)`** afkomstig is, is dit gewoonlik ’n **impersonation token**, dus moet jy **`DuplicateTokenEx(..., TokenPrimary, ...)`** uitvoer voordat jy probeer om ’n proses daarmee te spawn.
- Nie elke impersonation token is ewe nuttig nie: **`SecurityIdentification`** laat jou toe om die user te inspecteer, maar **nie om as die user op te tree nie**. As ’n coercion primitive of pipe/RPC client jou slegs ’n identification-level token gee, kontroleer **`TokenImpersonationLevel`** en skakel oor na ’n primitive wat **`SecurityImpersonation`** of beter lewer.

#### Token theft sonder om LSASS aan te raak

As jy reeds ’n **service**- of **SYSTEM**-context het en ’n **privileged user is logged on**, is dit dikwels stiller om daardie user se token te steel of te duplicate as om **LSASS** te dump. In baie werklike intrusions is dit genoeg om:<sup>[[2]](#references)</sup>

- plaaslike actions as daardie user uit te voer
- toegang tot remote resources as daardie user te verkry
- AD-operations uit te voer sonder om eers reusable credentials te extract

Vir voorbeelde van **session/user token hijacking** vanuit ’n privileged context, kyk na [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Onthou dat APIs soos **`WTSQueryUserToken`** bedoel is vir **highly trusted services** en normaalweg **`LocalSystem` + `SeTcbPrivilege`** vereis, dus is hulle hoofsaaklik nuttig wanneer jy reeds ’n service-level context beheer. Vir privilege-specific maniere om eers **SYSTEM** te verkry, kyk na die bladsye hieronder.

### Token Privileges

Leer watter **token privileges misbruik kan word om privileges te escalate:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Kyk na [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
