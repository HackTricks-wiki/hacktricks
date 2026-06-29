# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Elke **gebruiker aangemeld** by die stelsel **hou ’n access token met sekuriteitsinligting** vir daardie logon session. Die stelsel skep ’n access token wanneer die gebruiker aanmeld. **Elke proses wat uitgevoer word** namens die gebruiker **het ’n kopie van die access token**. Die token identifiseer die gebruiker, die gebruiker se groups, en die gebruiker se privileges. ’n Token bevat ook ’n logon SID (Security Identifier) wat die huidige logon session identifiseer.

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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Plaaslike administrateur

Wanneer 'n plaaslike administrateur aanmeld, **word twee access tokens geskep**: Een met admin regte en 'n ander een met normale regte. **By verstek**, wanneer hierdie gebruiker 'n proses uitvoer, word die een met **gewone** (nie-administrateur) **regte gebruik**. Wanneer hierdie gebruiker probeer om enigiets **as administrator** uit te voer ("Run as Administrator" byvoorbeeld), sal die **UAC** gebruik word om toestemming te vra.\
As jy meer wil [**leer oor die UAC, lees hierdie bladsy**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In die praktyk beteken dit dat 'n **nie-verhoogde admin shell gewoonlik met 'n filtered token loop**. Daarom wys `whoami /groups` dikwels **`BUILTIN\Administrators` as `Deny only`** totdat die proses verhoog is. Intern hou Windows 'n **linked elevated token** (`TokenLinkedToken`) en volg die toestand met velde soos `TokenElevationType`.

### Credentials user impersonation

As jy **geldige credentials van enige ander gebruiker** het, kan jy **'n nuwe aanmeldsessie skep** met daardie credentials :
```
runas /user:domain\username cmd.exe
```
Die **toegangs-token** het ook ’n **verwysing** na die aanmeldsessies binne die **LSASS**, dit is nuttig as die proses toegang tot sommige voorwerpe van die netwerk moet kry.\
Jy kan ’n proses begin wat **verskillende geloofsbriewe gebruik om netwerkdienste te verkry** met:
```
runas /user:domain\username /netonly cmd.exe
```
Dit is nuttig as jy nuttige credentials het om toegang te kry tot objects in die network, maar daardie credentials is nie geldig binne die huidige host nie, aangesien hulle slegs in die network gebruik gaan word (op die huidige host sal jou huidige user privileges gebruik word).

#### `runas /netonly` details

`runas /netonly` (en C2 helpers soos `make_token`) creates a **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Dit is baie nuttig om te verstaan tydens lateral movement omdat:

- **Plaaslik**, die nuwe proses behou dieselfde plaaslike identiteit, groups, integrity level, en die meeste van dieselfde access decisions as die huidige token.
- **Afstand**, outbound authentication kan die **verskafde credentials** gebruik vir SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Daarom kan `whoami` steeds die **oorspronklike local user** wys terwyl network access plaasvind as die **alternatiewe account**.

Dit is ’n goeie opsie wanneer die credentials geldig is in die domain of op ’n ander host, maar die user **kan nie of behoort nie local aan te meld** by die huidige machine.

### Types of tokens

Daar is twee tipes tokens beskikbaar:

- **Primary Token**: Dit dien as ’n voorstelling van ’n process se security credentials. Die creation en association van primary tokens met processes is actions wat elevated privileges vereis, wat die beginsel van privilege separation beklemtoon. Tipies is ’n authentication service verantwoordelik vir token creation, terwyl ’n logon service die association daarvan met die user se operating system shell hanteer. Dit is die moeite werd om daarop te let dat processes die primary token van hul parent process by creation erf.
- **Impersonation Token**: Stel ’n server application in staat om die client se identity tydelik aan te neem vir toegang tot secure objects. Hierdie mechanism is gestratifiseer in vier levels van operation:
- **Anonymous**: Verleen server access soortgelyk aan dié van ’n unidentified user.
- **Identification**: Laat die server toe om die client se identity te verify sonder om dit vir object access te gebruik.
- **Impersonation**: Stel die server in staat om onder die client se identity te operate.
- **Delegation**: Soortgelyk aan Impersonation maar sluit die vermoë in om hierdie identity assumption uit te brei na remote systems waarmee die server interaksie het, en verseker credential preservation.

#### Impersonate Tokens

Deur die _**incognito**_ module van metasploit te gebruik, kan jy, as jy genoeg privileges het, maklik ander **tokens** **list** en **impersonate**. Dit kan nuttig wees om **actions uit te voer asof jy die ander user is**. Jy kan ook **escalate privileges** met hierdie technique.

Sommige praktiese notas wat maklik is om te vergeet terwyl jy werk:

- **`CreateProcessWithTokenW`** vereis **`SeImpersonatePrivilege`** in die caller en die nuwe process sal in die **caller se session** loop.
- **`CreateProcessAsUserW`** is die gewone fallback wanneer `CreateProcessWithTokenW` faal met `1314`, of wanneer jy in die **session waarna die token verwys** wil launch.
- As ’n token van **`LogonUser(LOGON32_LOGON_NETWORK)`** af kom, is dit gewoonlik ’n **impersonation token**, so jy benodig **`DuplicateTokenEx(..., TokenPrimary, ...)`** voordat jy probeer om ’n process daarmee te spawn.
- Nie elke impersonation token is ewe nuttig nie: **`SecurityIdentification`** laat jou die user inspecteer maar **nie as hulle optree nie**. As ’n coercion primitive of pipe/RPC client jou net ’n identification-level token gee, check **`TokenImpersonationLevel`** en skakel oor na ’n primitive wat **`SecurityImpersonation`** of beter lewer.

#### Token theft without touching LSASS

As jy reeds ’n **service** of **SYSTEM** context het en ’n **privileged user is logged on**, is token steel of duplication van daardie user se token dikwels stiller as om **LSASS** te dump. In baie werklike intrusions is dit genoeg om:

- plaaslike actions as daardie user uit te voer
- remote resources as daardie user te access
- AD operations uit te voer sonder om eers reusable credentials uit te trek

Vir voorbeelde van **session/user token hijacking** vanuit ’n privileged context, kyk [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Onthou dat APIs soos **`WTSQueryUserToken`** bedoel is vir **highly trusted services** en normaalweg **`LocalSystem` + `SeTcbPrivilege`** vereis, so hulle is hoofsaaklik nuttig sodra jy reeds ’n service-level context beheer. Vir privilege-specific maniere om eers **SYSTEM** te verkry, kyk die bladsye hieronder.

### Token Privileges

Leer watter **token privileges kan misbruik word om privileges te escalate:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Kyk gerus na [**al die moontlike token privileges en sommige definitions op hierdie external page**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
