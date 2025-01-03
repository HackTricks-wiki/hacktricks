# Toegangstokens

{{#include ../../banners/hacktricks-training.md}}

## Toegangstokens

Elke **gebruiker wat** op die stelsel **ingelog is, hou 'n toegangstoken met sekuriteitsinligting** vir daardie aanmeldsessie. Die stelsel skep 'n toegangstoken wanneer die gebruiker aanmeld. **Elke proses wat uitgevoer word** namens die gebruiker **het 'n kopie van die toegangstoken**. Die token identifiseer die gebruiker, die gebruiker se groepe, en die gebruiker se voorregte. 'n Token bevat ook 'n aanmeld SID (Sekuriteitsidentifiseerder) wat die huidige aanmeldsessie identifiseer.

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
of deur _Process Explorer_ van Sysinternals (kies proses en toegang "Sekuriteit" tab):

![](<../../images/image (772).png>)

### Plaaslike administrateur

Wanneer 'n plaaslike administrateur aanmeld, **word twee toegangstokens geskep**: Een met administrateurregte en die ander een met normale regte. **Standaard**, wanneer hierdie gebruiker 'n proses uitvoer, word die een met **gereelde** (nie-administrateur) **regte gebruik**. Wanneer hierdie gebruiker probeer om **enige iets uit te voer** **as administrateur** ("Hardloop as Administrateur" byvoorbeeld) sal die **UAC** gebruik word om toestemming te vra.\
As jy wil [**meer oor die UAC leer lees hierdie bladsy**](../authentication-credentials-uac-and-efs/#uac)**.**

### Kredensiële gebruiker impersonasie

As jy **geldige kredensiale van enige ander gebruiker** het, kan jy 'n **nuwe aanmeldsessie** met daardie kredensiale **skep**:
```
runas /user:domain\username cmd.exe
```
Die **toegangsteken** het ook 'n **verwysing** na die aanmeldsessies binne die **LSASS**, dit is nuttig as die proses toegang tot sommige voorwerpe van die netwerk moet verkry.\
Jy kan 'n proses begin wat **verskillende akrediteerbesonderhede vir toegang tot netwerkdienste gebruik** deur:
```
runas /user:domain\username /netonly cmd.exe
```
Dit is nuttig as jy nuttige akrediteerbare inligting het om toegang te verkry tot voorwerpe in die netwerk, maar daardie akrediteerbare inligting is nie geldig binne die huidige gasheer nie, aangesien dit slegs in die netwerk gebruik gaan word (in die huidige gasheer sal jou huidige gebruikersprivileges gebruik word).

### Tipes tokens

Daar is twee tipes tokens beskikbaar:

- **Primêre Token**: Dit dien as 'n voorstelling van 'n proses se sekuriteitsakrediteerbare inligting. Die skepping en assosiasie van primêre tokens met prosesse is aksies wat verhoogde privileges vereis, wat die beginsel van privilege-skeiding beklemtoon. Gewoonlik is 'n verifikasiediens verantwoordelik vir token-skepping, terwyl 'n aanmelddiens die assosiasie met die gebruiker se bedryfstelsel-skal hanteer. Dit is die moeite werd om op te let dat prosesse die primêre token van hul ouer proses by skepping erf.
- **Impersonasie Token**: Bemagtig 'n bedienertoepassing om die kliënt se identiteit tydelik aan te neem om toegang tot veilige voorwerpe te verkry. Hierdie meganisme is gelaag in vier vlakke van werking:
- **Anoniem**: Gee bediener toegang soortgelyk aan dié van 'n onbekende gebruiker.
- **Identifikasie**: Laat die bediener toe om die kliënt se identiteit te verifieer sonder om dit vir voorwerp toegang te gebruik.
- **Impersonasie**: Stel die bediener in staat om onder die kliënt se identiteit te werk.
- **Delegasie**: Soortgelyk aan Impersonasie, maar sluit die vermoë in om hierdie identiteit aanneming na afgeleë stelsels wat die bediener mee werk, uit te brei, wat akrediteerbare inligting se bewaring verseker.

#### Imiteer Tokens

Deur die _**incognito**_ module van metasploit te gebruik, as jy genoeg privileges het, kan jy maklik **lys** en **imiteer** ander **tokens**. Dit kan nuttig wees om **aksies uit te voer asof jy die ander gebruiker was**. Jy kan ook **privileges verhoog** met hierdie tegniek.

### Token Privileges

Leer watter **token privileges misbruik kan word om privileges te verhoog:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Kyk na [**alle moontlike token privileges en 'n paar definisies op hierdie eksterne bladsy**](https://github.com/gtworek/Priv2Admin).

## Verwysings

Leer meer oor tokens in hierdie tutorials: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) en [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
