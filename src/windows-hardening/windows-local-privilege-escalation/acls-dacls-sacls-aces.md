# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Toegangsbeheerlys (ACL)**

'n Toegangsbeheerlys (ACL) bestaan uit 'n geordende stel Toegangsbeheeringe (ACEs) wat die beskerming van 'n objek en sy eienskappe bepaal. In wese definieer 'n ACL watter aksies deur watter sekuriteitsbeginsels (gebruikers of groepe) toegelaat of geweier word op 'n gegewe objek.

Daar is twee tipes ACLs:

- **Diskresionêre Toegangsbeheerlys (DACL):** Spesifiseer watter gebruikers en groepe toegang tot 'n objek het of nie.
- **Stelsels Toegangsbeheerlys (SACL):** Beheer die ouditering van toegangspogings tot 'n objek.

Die proses om toegang tot 'n lêer te verkry behels dat die stelsel die objek se sekuriteitsbeskrywer teen die gebruiker se toegangstoken nagaan om te bepaal of toegang toegestaan moet word en die omvang van daardie toegang, gebaseer op die ACEs.

### **Belangrike Komponente**

- **DACL:** Bevat ACEs wat toegangstoestemmings aan gebruikers en groepe vir 'n objek toeken of weier. Dit is in wese die hoof ACL wat toegangregte bepaal.
- **SACL:** Word gebruik vir die ouditering van toegang tot objek, waar ACEs die tipes toegang definieer wat in die Sekuriteitsgebeurtenislogboek geregistreer moet word. Dit kan van onskatbare waarde wees om ongeoorloofde toegangspogings te ontdek of toegangkwessies op te los.

### **Stelselinteraksie met ACLs**

Elke gebruikersessie is geassosieer met 'n toegangstoken wat sekuriteitsinligting bevat wat relevant is vir daardie sessie, insluitend gebruiker, groep identiteite, en voorregte. Hierdie token sluit ook 'n aanmeld SID in wat die sessie uniek identifiseer.

Die Plaaslike Sekuriteitsowerheid (LSASS) verwerk toegang versoeke tot objek deur die DACL vir ACEs te ondersoek wat ooreenstem met die sekuriteitsbeginsel wat toegang probeer verkry. Toegang word onmiddellik toegestaan as daar geen relevante ACEs gevind word nie. Andersins vergelyk LSASS die ACEs teen die sekuriteitsbeginsel se SID in die toegangstoken om toegangsgeschiktheid te bepaal.

### **Samegevatte Proses**

- **ACLs:** Definieer toegangstoestemmings deur DACLs en ouditreëls deur SACLs.
- **Toegangstoken:** Bevat gebruiker, groep, en voorregte-inligting vir 'n sessie.
- **Toegangbesluit:** Word geneem deur DACL ACEs met die toegangstoken te vergelyk; SACLs word gebruik vir ouditering.

### ACEs

Daar is **drie hoof tipes Toegangsbeheeringe (ACEs)**:

- **Toegang Geweier ACE**: Hierdie ACE weier eksplisiet toegang tot 'n objek vir gespesifiseerde gebruikers of groepe (in 'n DACL).
- **Toegang Toegelaat ACE**: Hierdie ACE grant eksplisiet toegang tot 'n objek vir gespesifiseerde gebruikers of groepe (in 'n DACL).
- **Stelsels Oudit ACE**: Geplaas binne 'n Stelsels Toegangsbeheerlys (SACL), is hierdie ACE verantwoordelik vir die generering van ouditlogs tydens toegangspogings tot 'n objek deur gebruikers of groepe. Dit dokumenteer of toegang toegestaan of geweier is en die aard van die toegang.

Elke ACE het **vier kritieke komponente**:

1. Die **Sekuriteitsidentifiseerder (SID)** van die gebruiker of groep (of hul beginselnaam in 'n grafiese voorstelling).
2. 'n **vlag** wat die ACE tipe identifiseer (toegang geweier, toegestaan, of stelsels oudit).
3. **Erfenisvlagte** wat bepaal of kindobjekte die ACE van hul ouer kan erf.
4. 'n [**toegangsmasker**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 'n 32-bis waarde wat die objek se toegepaste regte spesifiseer.

Toegangsbepaling word uitgevoer deur elke ACE een vir een te ondersoek totdat:

- 'n **Toegang-Geweier ACE** eksplisiet die aangevraagde regte aan 'n trustee in die toegangstoken weier.
- **Toegang-Toegelaat ACE(s)** eksplisiet al die aangevraagde regte aan 'n trustee in die toegangstoken grant.
- Na die nagaan van alle ACEs, as enige aangevraagde regte **nie eksplisiet toegestaan** is nie, word toegang implisiet **geweier**.

### Volgorde van ACEs

Die manier waarop **ACEs** (reëls wat sê wie toegang kan of nie kan hê nie) in 'n lys genaamd **DACL** geplaas word, is baie belangrik. Dit is omdat sodra die stelsel toegang op grond van hierdie reëls gee of weier, dit ophou om na die res te kyk.

Daar is 'n beste manier om hierdie ACEs te organiseer, en dit word **"kanonieke orde"** genoem. Hierdie metode help om te verseker dat alles glad en regverdig werk. Hier is hoe dit gaan vir stelsels soos **Windows 2000** en **Windows Server 2003**:

- Eerstens, plaas al die reëls wat **spesifiek vir hierdie item** gemaak is voor diegene wat van elders kom, soos 'n ouer gids.
- In daardie spesifieke reëls, plaas diegene wat sê **"nee" (weier)** voor diegene wat sê **"ja" (toelaat)**.
- Vir die reëls wat van elders kom, begin met diegene van die **nabyste bron**, soos die ouer, en gaan dan terug van daar. Weer eens, plaas **"nee"** voor **"ja."**

Hierdie opstelling help op twee groot maniere:

- Dit verseker dat as daar 'n spesifieke **"nee"** is, dit gerespekteer word, ongeag watter ander **"ja"** reëls daar is.
- Dit laat die eienaar van 'n item die **laaste sê** hê oor wie toegang kry, voordat enige reëls van ouer gidse of verder terug in werking tree.

Deur dit op hierdie manier te doen, kan die eienaar van 'n lêer of gids baie presies wees oor wie toegang kry, en verseker dat die regte mense kan inkom en die verkeerde nie.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

So, hierdie **"kanonieke orde"** is alles oor om te verseker dat die toegang reëls duidelik en goed werk, spesifieke reëls eerste te plaas en alles op 'n slim manier te organiseer.

### GUI Voorbeeld

[**Voorbeeld van hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Dit is die klassieke sekuriteitstab van 'n gids wat die ACL, DACL en ACEs wys:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

As ons op die **Gevorderde knoppie** klik, sal ons meer opsies kry soos erfenis:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

En as jy 'n Sekuriteitsbeginsel byvoeg of wysig:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

En laastens het ons die SACL in die Ouditeringstab:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Toegangsbeheer in 'n Vereenvoudigde Wyse Verduidelik

Wanneer ons toegang tot hulpbronne bestuur, soos 'n gids, gebruik ons lyste en reëls bekend as Toegangsbeheerlys (ACLs) en Toegangsbeheeringe (ACEs). Hierdie definieer wie toegang tot sekere data kan of nie kan hê nie.

#### Toegang tot 'n Spesifieke Groep Weier

Stel jou voor jy het 'n gids genaamd Kostes, en jy wil hê dat almal toegang moet hê behalwe vir 'n bemarking span. Deur die reëls korrek op te stel, kan ons verseker dat die bemarking span eksplisiet toegang geweier word voordat ons almal anders toelaat. Dit word gedoen deur die reël om toegang tot die bemarking span te weier voor die reël wat toegang aan almal toelaat.

#### Toegang tot 'n Spesifieke Lid van 'n Geweerde Groep Toelaat

Kom ons sê Bob, die bemarkingsdirekteur, het toegang tot die Kostes gids nodig, alhoewel die bemarking span oor die algemeen nie toegang moet hê nie. Ons kan 'n spesifieke reël (ACE) vir Bob byvoeg wat hom toegang grant, en dit voor die reël wat toegang aan die bemarking span weier plaas. Op hierdie manier kry Bob toegang ten spyte van die algemene beperking op sy span.

#### Toegangsbeheeringe Verstaan

ACEs is die individuele reëls in 'n ACL. Hulle identifiseer gebruikers of groepe, spesifiseer watter toegang toegestaan of geweier word, en bepaal hoe hierdie reëls op sub-items van toepassing is (erfenis). Daar is twee hoof tipes ACEs:

- **Generiese ACEs**: Hierdie geld breedweg, wat óf alle tipes objek beïnvloed of net tussen houers (soos gidse) en nie-houers (soos lêers) onderskei. Byvoorbeeld, 'n reël wat gebruikers toelaat om die inhoud van 'n gids te sien, maar nie toegang tot die lêers daarin te hê nie.
- **Objek-Spesifieke ACEs**: Hierdie bied meer presiese beheer, wat toelaat dat reëls vir spesifieke tipes objek of selfs individuele eienskappe binne 'n objek gestel kan word. Byvoorbeeld, in 'n gids van gebruikers, kan 'n reël 'n gebruiker toelaat om hul telefoonnommer op te dateer, maar nie hul aanmeldure nie.

Elke ACE bevat belangrike inligting soos wie die reël van toepassing is (met 'n Sekuriteitsidentifiseerder of SID), wat die reël toelaat of weier (met 'n toegangsmasker), en hoe dit geërf word deur ander objek.

#### Sleutelverskille Tussen ACE Tipes

- **Generiese ACEs** is geskik vir eenvoudige toegangsbeheer scenario's, waar dieselfde reël op alle aspekte van 'n objek of op alle objek binne 'n houer van toepassing is.
- **Objek-Spesifieke ACEs** word gebruik vir meer komplekse scenario's, veral in omgewings soos Aktiewe Gids, waar jy toegang tot spesifieke eienskappe van 'n objek anders kan moet beheer.

In samevatting help ACLs en ACEs om presiese toegangsbeheer te definieer, wat verseker dat slegs die regte individue of groepe toegang tot sensitiewe inligting of hulpbronne het, met die vermoë om toegangregte tot die vlak van individuele eienskappe of objek tipes aan te pas.

### Toegangsbeheeringe Uitleg

| ACE Veld    | Beskrywing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipe        | Vlag wat die tipe ACE aandui. Windows 2000 en Windows Server 2003 ondersteun ses tipes ACE: Drie generiese ACE tipes wat aan alle beveiligbare objekte geheg is. Drie objek-spesifieke ACE tipes wat vir Aktiewe Gids objekte kan voorkom.                                                                                                                                                                                                                                                            |
| Vlagte      | Stel van bitvlagte wat erfenis en ouditering beheer.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Grootte     | Aantal bytes van geheue wat vir die ACE toegeken word.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Toegangsmasker | 32-bis waarde waarvan die bits ooreenstem met toegangregte vir die objek. Bits kan of aan of af gestel word, maar die betekenis van die instelling hang af van die ACE tipe. Byvoorbeeld, as die bit wat ooreenstem met die reg om toestemmings te lees aangeskakel is, en die ACE tipe is Weier, weier die ACE die reg om die objek se toestemmings te lees. As dieselfde bit aangeskakel is, maar die ACE tipe is Toelaat, grant die ACE die reg om die objek se toestemmings te lees. Meer besonderhede van die Toegangsmasker verskyn in die volgende tabel. |
| SID         | Identifiseer 'n gebruiker of groep wie se toegang deur hierdie ACE beheer of gemonitor word.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Toegangsmasker Uitleg

| Bit (Bereik) | Betekenis                            | Beskrywing/Voorbeeld                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objek Spesifieke Toegangregte      | Lees data, Voer uit, Voeg data by           |
| 16 - 22     | Standaard Toegangregte             | Verwyder, Skryf ACL, Skryf Eienaar            |
| 23          | Kan toegang tot sekuriteits ACL hê            |                                           |
| 24 - 27     | Gereserveer                           |                                           |
| 28          | Generies ALLES (Lees, Skryf, Voer uit) | Alles hieronder                          |
| 29          | Generies Voer uit                    | Alle dinge wat nodig is om 'n program uit te voer |
| 30          | Generies Skryf                      | Alle dinge wat nodig is om na 'n lêer te skryf   |
| 31          | Generies Lees                       | Alle dinge wat nodig is om na 'n lêer te lees       |

## Verwysings

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}
