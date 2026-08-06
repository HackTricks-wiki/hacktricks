# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

'n Access Control List (ACL) bestaan uit 'n geordende stel Access Control Entries (ACEs) wat die beskerming vir 'n objek en sy eienskappe bepaal. In wese definieer 'n ACL watter aksies deur watter security principals (users of groups) op 'n gegewe objek toegelaat of geweier word.

Daar is twee tipes ACLs:

- **Discretionary Access Control List (DACL):** Spesifiseer watter users en groups toegang tot 'n objek het of nie het nie.
- **System Access Control List (SACL):** Beheer die auditing van toegangspogings tot 'n objek.

Die proses om toegang tot 'n file te verkry, behels dat die system die objek se security descriptor teen die user se access token kontroleer om te bepaal of toegang toegestaan moet word en wat die omvang van daardie toegang is, gebaseer op die ACEs.<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** Bevat ACEs wat toegangspermissions aan users en groups vir 'n objek toestaan of weier. Dit is basies die hoof-ACL wat toegangsregte bepaal.
- **SACL:** Word gebruik om toegang tot objekte te audit, waar ACEs die tipe toegang definieer wat in die Security Event Log aangeteken moet word. Dit kan van groot waarde wees om ongemagtigde toegangspogings op te spoor of toegangsprobleme te troubleshoot.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Elke user session word geassosieer met 'n access token wat security information bevat wat relevant is vir daardie session, insluitend user-, group-identiteite en privileges. Hierdie token bevat ook 'n logon SID wat die session uniek identifiseer.

Die Local Security Authority (LSASS) verwerk toegangsversoeke tot objekte deur die DACL te ondersoek vir ACEs wat ooreenstem met die security principal wat toegang probeer verkry. Toegang word onmiddellik toegestaan indien geen relevante ACEs gevind word nie. Andersins vergelyk LSASS die ACEs met die security principal se SID in die access token om te bepaal of toegang toegelaat moet word.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Definieer toegangspermissions deur DACLs en audit-reëls deur SACLs.
- **Access Token:** Bevat user-, group- en privilege-information vir 'n session.
- **Access Decision:** Word geneem deur DACL ACEs met die access token te vergelyk; SACLs word vir auditing gebruik.<sup>[[1]](#references)</sup>

### ACEs

Daar is **drie hoofsoorte Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Hierdie ACE weier uitdruklik toegang tot 'n objek vir gespesifiseerde users of groups (in 'n DACL).
- **Access Allowed ACE**: Hierdie ACE verleen uitdruklik toegang tot 'n objek vir gespesifiseerde users of groups (in 'n DACL).
- **System Audit ACE**: Hierdie ACE, wat binne 'n System Access Control List (SACL) geplaas word, is verantwoordelik vir die generering van audit logs wanneer users of groups toegang tot 'n objek probeer verkry. Dit dokumenteer of toegang toegelaat of geweier is en wat die aard van die toegang was.

Elke ACE het **vier kritieke komponente**:<sup>[[1]](#references)</sup>

1. Die **Security Identifier (SID)** van die user of group (of hul principal name in 'n grafiese voorstelling).
2. 'n **flag** wat die ACE-tipe identifiseer (access denied, allowed of system audit).
3. **Inheritance flags** wat bepaal of child objects die ACE van hul parent kan inherit.
4. 'n [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 'n 32-bit waarde wat die objek se toegekende regte spesifiseer.

Toegangsbesluite word geneem deur elke ACE opeenvolgend te ondersoek totdat:<sup>[[1]](#references)</sup>

- 'n **Access-Denied ACE** die versoekte regte uitdruklik weier aan 'n trustee wat in die access token geïdentifiseer word.
- **Access-Allowed ACE(s)** alle versoekte regte uitdruklik aan 'n trustee in die access token toestaan.
- Nadat alle ACEs nagegaan is, word toegang implisiet **geweier** indien enige versoekte reg nie uitdruklik toegelaat is nie.

### Order of ACEs

Die manier waarop **ACEs** (reëls wat bepaal wie toegang tot iets kan of nie kan verkry nie) in 'n lys genaamd **DACL** geplaas word, is baie belangrik. Dit is omdat die system ophou om die res te ondersoek sodra dit toegang op grond van hierdie reëls toestaan of weier.<sup>[[1]](#references)</sup>

Daar is 'n beste manier om hierdie ACEs te organiseer, en dit word **"canonical order"** genoem. Hierdie metode help om te verseker dat alles glad en regverdig werk. So werk dit vir systems soos **Windows 2000** en **Windows Server 2003**:

- Plaas eers al die reëls wat **spesifiek vir hierdie item** gemaak is voor dié wat van elders afkomstig is, soos 'n parent folder.
- Plaas binne hierdie spesifieke reëls dié wat **"nee" (deny)** sê voor dié wat **"ja" (allow)** sê.
- Begin vir die reëls wat van elders afkomstig is met dié van die **naaste bron**, soos die parent, en werk dan van daar af terug. Plaas weer **"nee"** voor **"ja."**

Hierdie opstelling help op twee belangrike maniere:

- Dit verseker dat, indien daar 'n spesifieke **"nee"** is, dit gerespekteer word ongeag watter ander **"ja"**-reëls daar is.
- Dit laat die eienaar van 'n item toe om die **finale sê** te hê oor wie toegang kry, voordat enige reëls van parent folders of verdere bronne in werking tree.

Deur dinge op hierdie manier te doen, kan die eienaar van 'n file of folder presies bepaal wie toegang kry, sodat die regte mense toegang kan verkry en die verkeerde mense nie kan nie.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Hierdie **"canonical order"** gaan dus daaroor om te verseker dat die toegangsreëls duidelik is en goed werk, deur spesifieke reëls eerste te plaas en alles op 'n slim manier te organiseer.

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Dit is die klassieke security-tab van 'n folder wat die ACL, DACL en ACEs wys:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

As ons op die **Advanced button** klik, kry ons meer opsies soos inheritance:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

En as jy 'n Security Principal byvoeg of wysig:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Laastens het ons die SACL in die Auditing-tab:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Wanneer toegang tot resources, soos 'n folder, bestuur word, gebruik ons lyste en reëls bekend as Access Control Lists (ACLs) en Access Control Entries (ACEs). Dit definieer wie toegang tot sekere data kan of nie kan verkry nie.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Stel jou voor jy het 'n folder genaamd Cost, en jy wil hê almal moet toegang daartoe hê behalwe 'n marketing-span. Deur die reëls korrek op te stel, kan ons verseker dat die marketing-span uitdruklik toegang geweier word voordat almal anders toegelaat word. Dit word gedoen deur die reël wat toegang aan die marketing-span weier, voor die reël te plaas wat toegang aan almal toelaat.

#### Allowing Access to a Specific Member of a Denied Group

Kom ons sê Bob, die marketing-direkteur, benodig toegang tot die Cost-folder, hoewel die marketing-span oor die algemeen nie toegang behoort te hê nie. Ons kan 'n spesifieke reël (ACE) vir Bob byvoeg wat hom toegang verleen, en dit voor die reël plaas wat toegang aan die marketing-span weier. Op hierdie manier kry Bob toegang ondanks die algemene beperking op sy span.

#### Understanding Access Control Entries

ACEs is die individuele reëls in 'n ACL. Hulle identifiseer users of groups, spesifiseer watter toegang toegelaat of geweier word, en bepaal hoe hierdie reëls op sub-items toegepas word (inheritance). Daar is twee hoofsoorte ACEs:

- **Generic ACEs**: Hierdie is breed toepaslik en beïnvloed óf alle tipes objekte óf onderskei slegs tussen containers (soos folders) en non-containers (soos files). Byvoorbeeld, 'n reël wat users toelaat om die inhoud van 'n folder te sien, maar nie toegang tot die files daarin te verkry nie.
- **Object-Specific ACEs**: Hierdie bied meer presiese beheer deur reëls vir spesifieke tipes objekte of selfs individuele eienskappe binne 'n objek in te stel. Byvoorbeeld, in 'n directory van users kan 'n reël 'n user toelaat om sy telefoonnommer by te werk, maar nie sy login hours nie.

Elke ACE bevat belangrike information, soos op wie die reël van toepassing is (deur 'n Security Identifier of SID te gebruik), wat die reël toelaat of weier (deur 'n access mask te gebruik), en hoe dit deur ander objekte geërf word.

#### Key Differences Between ACE Types

- **Generic ACEs** is geskik vir eenvoudige toegangsbeheer-scenarios, waar dieselfde reël op alle aspekte van 'n objek of op alle objekte binne 'n container van toepassing is.
- **Object-Specific ACEs** word vir meer komplekse scenarios gebruik, veral in omgewings soos Active Directory, waar jy moontlik toegang tot spesifieke eienskappe van 'n objek op verskillende maniere moet beheer.

Kortom, ACLs en ACEs help om presiese toegangsbeheer te definieer, sodat slegs die regte individue of groups toegang tot sensitiewe information of resources het, met die vermoë om toegangsregte tot op die vlak van individuele eienskappe of objek-tipes aan te pas.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag wat die tipe ACE aandui. Windows 2000 en Windows Server 2003 ondersteun ses tipes ACEs: Drie generic ACE-tipes wat aan alle securable objects gekoppel is. Drie object-specific ACE-tipes wat vir Active Directory-objekte kan voorkom.                                                                                                                                                                                                                                                            |
| Flags       | Stel bit flags wat inheritance en auditing beheer.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Aantal bytes geheue wat vir die ACE toegewys is.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bit waarde waarvan die bits met toegangsregte vir die objek ooreenstem. Bits kan aan of af gestel word, maar die betekenis van die instelling hang van die ACE-tipe af. Byvoorbeeld, indien die bit wat ooreenstem met die reg om permissions te lees aangeskakel is, en die ACE-tipe Deny is, weier die ACE die reg om die objek se permissions te lees. Indien dieselfde bit aangeskakel is maar die ACE-tipe Allow is, verleen die ACE die reg om die objek se permissions te lees. Meer besonderhede oor die Access mask verskyn in die volgende tabel. |
| SID         | Identifiseer 'n user of group wie se toegang deur hierdie ACE beheer of gemonitor word.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Lees data, Execute, Append data           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Alles hieronder                          |
| 29          | Generic Execute                    | Alles wat nodig is om 'n program uit te voer |
| 30          | Generic Write                      | Alles wat nodig is om na 'n file te skryf   |
| 31          | Generic Read                       | Alles wat nodig is om 'n file te lees       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
