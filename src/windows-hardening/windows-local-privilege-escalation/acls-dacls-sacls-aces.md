# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Toegangsbeheerlys (ACL)**

’n Toegangsbeheerlys (ACL) bestaan uit ’n geordende stel Toegangsbeheerinskrywings (ACEs) wat die beskerming van ’n objek en sy eienskappe bepaal. In wese definieer ’n ACL watter handelinge deur watter sekuriteitsbeginsels (gebruikers of groepe) op ’n gegewe objek toegelaat of geweier word.

Daar is twee tipes ACL’s:

- **Diskresionêre Toegangsbeheerlys (DACL):** Spesifiseer watter gebruikers en groepe toegang tot ’n objek het of nie het nie.
- **Stelseltoegangsbeheerlys (SACL):** Beheer die ouditering van toegangspogings tot ’n objek.

Wanneer toegang tot ’n lêer verkry word, vergelyk die stelsel die objek se sekuriteitsbeskrywer met die gebruiker se toegangstoken om te bepaal of toegang verleen moet word en wat die omvang daarvan moet wees, gebaseer op die ACEs.<sup>[[1]](#references)</sup>

Wanneer ’n ouergids Full Control verleen, maar ’n kinderlêer leesaksies weier, moet die **kinderlêer se** effektiewe DACL, eienaar en oorerwing afsonderlik nagegaan word. Om daardie lêer se DACL te verander, vereis `WRITE_DAC` op die lêer of die toepaslike eienaarreg; [Microsoft definieer `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) en [dokumenteer die eienaar se implisiete toegang](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Toestemmings op die ouergids alleen bewys nie dat die kinderlêer gelees kan word of dat sy DACL verander kan word nie.

### **Sleutelkomponente**

- **DACL:** Bevat ACEs wat toegangstoestemmings vir ’n objek aan gebruikers en groepe verleen of weier. Dit is in wese die hoof-ACL wat toegangsregte bepaal.
- **SACL:** Word gebruik om toegang tot objekte te oudit; ACEs definieer watter toegangstipes in die Security Event Log aangeteken moet word. Dit kan van onskatbare waarde wees om ongemagtigde toegangspogings op te spoor of toegangsprobleme te foutspoor.<sup>[[1]](#references)</sup>

### **Stelselinteraksie met ACL’s**

Elke gebruikersessie word met ’n toegangstoken geassosieer wat sekuriteitsinligting bevat wat vir daardie sessie relevant is, insluitend gebruiker- en groepidentiteite, asook voorregte. Hierdie token bevat ook ’n logon SID wat die sessie uniek identifiseer.

Die Local Security Authority (LSASS) verwerk toegangsversoeke tot objekte deur die DACL te ondersoek vir ACEs wat ooreenstem met die sekuriteitsbeginsel wat toegang probeer verkry. Toegang word onmiddellik verleen as geen relevante ACEs gevind word nie. Andersins vergelyk LSASS die ACEs met die sekuriteitsbeginsel se SID in die toegangstoken om te bepaal of toegang toegelaat word.<sup>[[1]](#references)</sup>

### **Proses in kort**

- **ACL’s:** Definieer toegangstoestemmings deur DACL’s en ouditreëls deur SACL’s.
- **Toegangstoken:** Bevat gebruiker-, groep- en voorreginligting vir ’n sessie.
- **Toegangsbesluit:** Word geneem deur DACL-ACEs met die toegangstoken te vergelyk; SACL’s word vir ouditering gebruik.<sup>[[1]](#references)</sup>

### ACEs

Daar is **drie hoofsoorte Toegangsbeheerinskrywings (ACEs)**:<sup>[[1]](#references)</sup>

- **Toegang-geweier-ACE**: Hierdie ACE weier uitdruklik toegang tot ’n objek vir gespesifiseerde gebruikers of groepe (in ’n DACL).
- **Toegang-toegelaat-ACE**: Hierdie ACE verleen uitdruklik toegang tot ’n objek aan gespesifiseerde gebruikers of groepe (in ’n DACL).
- **Stelseloudit-ACE**: Hierdie ACE, wat binne ’n Stelseltoegangsbeheerlys (SACL) geplaas word, is verantwoordelik vir die skep van ouditlogboeke wanneer gebruikers of groepe toegang tot ’n objek probeer verkry. Dit dokumenteer of toegang toegelaat of geweier is, asook die aard van die toegang.

Elke ACE het **vier kritieke komponente**:<sup>[[1]](#references)</sup>

1. Die gebruiker of groep se **Sekuriteitsidentifiseerder (SID)** (of hul beginselnaam in ’n grafiese voorstelling).
2. ’n **Vlag** wat die ACE-tipe aandui (toegang geweier, toegelaat of stelseloudit).
3. **Oorerwingsvlae** wat bepaal of kinderobjekte die ACE van hul ouer kan oorneem.
4. ’n [**toegangsmasker**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), ’n 32-bis-waarde wat die regte spesifiseer wat aan die objek verleen is.

Toegang word bepaal deur elke ACE opeenvolgend te ondersoek totdat:<sup>[[1]](#references)</sup>

- ’n **Toegang-geweier-ACE** die aangevraagde regte uitdruklik weier aan ’n trustee wat in die toegangstoken geïdentifiseer word.
- **Toegang-toegelaat-ACE(s)** al die aangevraagde regte uitdruklik aan ’n trustee in die toegangstoken verleen.
- As enige aangevraagde reg nie **uitdruklik toegelaat** is nadat al die ACEs nagegaan is nie, word toegang implisiet **geweier**.

### Volgorde van ACEs

Die manier waarop **ACEs** (reëls wat bepaal wie toegang tot iets kan of nie kan kry nie) in ’n lys genaamd **DACL** gerangskik word, is baie belangrik. Sodra die stelsel toegang op grond van hierdie reëls verleen of weier, hou dit op om die res na te gaan.<sup>[[1]](#references)</sup>

Daar is ’n beste manier om hierdie ACEs te rangskik, en dit word **“kanonieke volgorde”** genoem. Hierdie metode help om te verseker dat alles vlot en regverdig werk. So werk dit vir stelsels soos **Windows 2000** en **Windows Server 2003**:

- Plaas eers al die reëls wat **spesifiek vir hierdie item** geld, voor dié wat van elders af kom, soos ’n ouergids.
- Plaas onder hierdie spesifieke reëls die reëls wat **“nee” (weier)** sê voor dié wat **“ja” (toelaat)** sê.
- Vir reëls wat van elders af kom, begin met dié van die **naaste bron**, soos die ouergids, en werk dan verder terug. Plaas weer **“nee”** voor **“ja.”**

Hierdie rangskikking help op twee belangrike maniere:

- Dit verseker dat ’n spesifieke **“nee”** gerespekteer word, ongeag enige ander **“ja”**-reëls.
- Dit laat die eienaar van ’n item die **laaste sê** hê oor wie toegang kry, voordat enige reëls van ouergidse of verder terug toegepas word.

Deur dit so te doen, kan die eienaar van ’n lêer of gids presies bepaal wie toegang kry, sodat die regte mense toegang kan kry en die verkeerde mense nie.

![NTFS-diagram van die volgorde van toegangsbeheerinskrywings](https://www.ntfs.com/images/screenshots/ACEs.gif)

Hierdie **“kanonieke volgorde”** gaan dus daaroor om te verseker dat toegangsreëls duidelik en doeltreffend is, deur spesifieke reëls eerste te plaas en alles op ’n slim manier te rangskik.

### GUI-voorbeeld

[**Voorbeeld hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Dit is die klassieke sekuriteitsoortjie van ’n gids wat die ACL, DACL en ACEs wys:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

As ons op die **Advanced-knoppie** klik, kry ons meer opsies soos oorerwing:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

En as jy ’n Security Principal byvoeg of wysig:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Laastens is daar die SACL in die Auditing-oortjie:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Toegangsbeheer eenvoudig verduidelik

Wanneer ons toegang tot hulpbronne, soos ’n gids, bestuur, gebruik ons lyste en reëls wat bekend staan as Toegangsbeheerlyste (ACL’s) en Toegangsbeheerinskrywings (ACEs). Dit bepaal wie toegang tot sekere data kan of nie kan kry nie.<sup>[[1]](#references)</sup>

#### Weier toegang aan ’n spesifieke groep

Stel jou voor jy het ’n gids genaamd Cost, en jy wil hê almal moet toegang daartoe hê behalwe ’n bemarkingspan. Deur die reëls korrek op te stel, kan ons verseker dat toegang uitdruklik aan die bemarkingspan geweier word voordat toegang aan almal anders toegelaat word. Dit word gedoen deur die reël wat toegang aan die bemarkingspan weier, voor die reël te plaas wat toegang aan almal toelaat.

#### Laat ’n spesifieke lid van ’n groep wat toegang geweier word toe

Gestel Bob, die bemarkingsdirekteur, het toegang tot die Cost-gids nodig, hoewel die bemarkingspan oor die algemeen nie toegang behoort te hê nie. Ons kan ’n spesifieke reël (ACE) vir Bob byvoeg wat hom toegang verleen, en dit voor die reël plaas wat toegang aan die bemarkingspan weier. So kry Bob toegang ondanks die algemene beperking op sy span.

#### Verstaan toegangsbeheerinskrywings

ACEs is die individuele reëls in ’n ACL. Hulle identifiseer gebruikers of groepe, spesifiseer watter toegang toegelaat of geweier word, en bepaal hoe hierdie reëls op subitems toegepas word (oorerwing). Daar is twee hoofsoorte ACEs:

- **Generiese ACEs**: Dit geld breedweg en raak óf alle soorte objekte óf onderskei slegs tussen houers (soos gidse) en nie-houers (soos lêers). Byvoorbeeld, ’n reël wat gebruikers toelaat om die inhoud van ’n gids te sien, maar nie toegang tot die lêers daarin te kry nie.
- **Objekspesifieke ACEs**: Dit bied fyner beheer, deur reëls vir spesifieke soorte objekte of selfs individuele eienskappe binne ’n objek toe te laat. Byvoorbeeld, in ’n gebruikersgids kan ’n reël ’n gebruiker toelaat om hul telefoonnommer by te werk, maar nie hul aanmeldure nie.

Elke ACE bevat belangrike inligting, soos op wie die reël van toepassing is (met ’n Sekuriteitsidentifiseerder of SID), wat die reël toelaat of weier (met ’n toegangsmasker), en hoe dit deur ander objekte oorgeërf word.

#### Belangrike verskille tussen ACE-tipes

- **Generiese ACEs** is geskik vir eenvoudige toegangsbeheersituasies, waar dieselfde reël op alle aspekte van ’n objek of op alle objekte binne ’n houer van toepassing is.
- **Objekspesifieke ACEs** word vir meer ingewikkelde situasies gebruik, veral in omgewings soos Active Directory, waar jy dalk toegang tot spesifieke eienskappe van ’n objek op verskillende maniere moet beheer.

Kortom, ACL’s en ACEs help om presiese toegangsbeheer te definieer. Dit verseker dat slegs die regte individue of groepe toegang tot sensitiewe inligting of hulpbronne het, en laat jou toe om toegangsregte tot op die vlak van individuele eienskappe of objeksoorte aan te pas.

### Uitleg van toegangsbeheerinskrywings

| ACE-veld | Beskrywing |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Vlag wat die ACE-tipe aandui. Windows 2000 en Windows Server 2003 ondersteun ses ACE-tipes: drie generiese ACE-tipes wat aan alle beveiligbare objekte gekoppel word, en drie objekspesifieke ACE-tipes wat op Active Directory-objekte kan voorkom. |
| Flags       | Stel bisvlae wat oorerwing en ouditering beheer. |
| Size        | Aantal grepe geheue wat vir die ACE toegeken is. |
| Access mask | 32-bis-waarde waarvan die bisse met toegangsregte vir die objek ooreenstem. Bisse kan aan of af wees, maar die betekenis van die instelling hang van die ACE-tipe af. Byvoorbeeld, as die bis wat met die reg om toestemmings te lees ooreenstem, aangeskakel is en die ACE-tipe Deny is, weier die ACE die reg om die objek se toestemmings te lees. As dieselfde bis aangeskakel is, maar die ACE-tipe Allow is, verleen die ACE die reg om die objek se toestemmings te lees. Meer besonderhede oor die toegangsmasker verskyn in die volgende tabel. |
| SID         | Identifiseer ’n gebruiker of groep wie se toegang deur hierdie ACE beheer of gemonitor word. |

### Uitleg van die toegangsmasker

| Bis (Reeks) | Betekenis                            | Beskrywing/Voorbeeld                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objekspesifieke toegangsregte      | Lees data, voer uit, voeg data by           |
| 16 - 22     | Standaardtoegangsregte             | Skrap, skryf ACL, skryf eienaar            |
| 23          | Kan toegang tot sekuriteit-ACL verkry |                                           |
| 24 - 27     | Gereserveer                           |                                           |
| 28          | Generiese ALL (Lees, Skryf, Uitvoer) | Alles hieronder                          |
| 29          | Generiese Execute                    | Alles wat nodig is om ’n program uit te voer |
| 30          | Generiese Write                      | Alles wat nodig is om na ’n lêer te skryf   |
| 31          | Generiese Read                       | Alles wat nodig is om ’n lêer te lees       |

## References

- [1] [Hoe die stelsel ACL’s gebruik - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL en die ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
