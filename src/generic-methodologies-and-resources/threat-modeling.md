# Bedreigingsmodellering

{{#include ../banners/hacktricks-training.md}}

## Bedreigingsmodellering

Welkom by HackTricks se omvattende gids oor bedreigingsmodellering! Verken hierdie kritieke aspek van kuberveiligheid, waar ons potensiële kwesbaarhede in ’n stelsel identifiseer, verstaan en daarteen strategieë ontwikkel. Hierdie draad dien as ’n stap-vir-stap-gids vol werklike voorbeelde, nuttige sagteware en maklik verstaanbare verduidelikings. Dit is ideaal vir beginners sowel as ervare praktisyns wat hul kuberveiligheidsverdediging wil versterk.

### Algemene gebruikscenario’s

1. **Sagteware-ontwikkeling**: As deel van die Secure Software Development Life Cycle (SSDLC) help bedreigingsmodellering om **potensiële bronne van kwesbaarhede te identifiseer** tydens die vroeë stadiums van ontwikkeling.
2. **Penetration Testing**: Die Penetration Testing Execution Standard (PTES)-raamwerk vereis **bedreigingsmodellering om die stelsel se kwesbaarhede te verstaan** voordat die toets uitgevoer word.

### Bedreigingsmodel in ’n neutedop

’n Bedreigingsmodel word tipies voorgestel as ’n diagram, beeld of ’n ander vorm van visuele illustrasie wat die beplande argitektuur of bestaande bouwerk van ’n toepassing uitbeeld. Dit lyk soos ’n **data-vloeidiagram**, maar die belangrikste onderskeid lê in die sekuriteitsgeoriënteerde ontwerp daarvan.

Bedreigingsmodelle bevat dikwels elemente wat in rooi gemerk is en potensiële kwesbaarhede, risiko’s of hindernisse simboliseer. Om die proses van risiko-identifikasie te stroomlyn, word die CIA-triade (Confidentiality, Integrity, Availability) gebruik. Dit vorm die basis van baie bedreigingsmodelleringsmetodologieë, waarvan STRIDE een van die algemeenstes is. Die gekose metodologie kan egter wissel na gelang van die spesifieke konteks en vereistes.

### Die CIA-triade

Die CIA-triade is ’n algemeen erkende model in die veld van inligtingsekuriteit en staan vir Confidentiality, Integrity en Availability. Hierdie drie pilare vorm die grondslag waarop baie sekuriteitsmaatreëls en -beleide gebou word, insluitend bedreigingsmodelleringsmetodologieë.

1. **Confidentiality**: Verseker dat die data of stelsel nie deur ongemagtigde individue verkry word nie. Dit is ’n sentrale aspek van sekuriteit en vereis toepaslike toegangsbeheer, enkripsie en ander maatreëls om data-oortredings te voorkom.
2. **Integrity**: Die akkuraatheid, konsekwentheid en betroubaarheid van die data gedurende die lewensiklus daarvan. Hierdie beginsel verseker dat die data nie deur ongemagtigde partye verander of gemanipuleer word nie. Dit behels dikwels checksums, hashing en ander dataverifikasiemetodes.
3. **Availability**: Dit verseker dat data en dienste vir gemagtigde gebruikers toeganklik is wanneer dit nodig is. Dit behels dikwels redundansie, fouttoleransie en hoë-beskikbaarheidkonfigurasies om stelsels aan die gang te hou, selfs tydens onderbrekings.

### Metodologieë vir bedreigingsmodellering

1. **STRIDE**: STRIDE, wat deur Microsoft ontwikkel is, is ’n akroniem vir **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Elke kategorie verteenwoordig ’n tipe bedreiging, en hierdie metodologie word algemeen in die ontwerpstadium van ’n program of stelsel gebruik om potensiële bedreigings te identifiseer.
2. **DREAD**: Dit is nog ’n metodologie van Microsoft wat vir die risiko-assessering van geïdentifiseerde bedreigings gebruik word. DREAD staan vir **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Elkeen van hierdie faktore word gegradeer, en die resultaat word gebruik om geïdentifiseerde bedreigings te prioritiseer.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dit is ’n sewe-stap, **risk-centric** metodologie. Dit sluit in die definiëring en identifisering van sekuriteitsdoelwitte, die skep van ’n tegniese omvang, toepassingsdekomposisie, bedreigingsanalise, kwesbaarheidsanalise en risiko-/triage-assessering.
4. **Trike**: Dit is ’n risikogebaseerde metodologie wat op die verdediging van bates fokus. Dit begin vanuit ’n **risk management**-perspektief en ondersoek bedreigings en kwesbaarhede binne daardie konteks.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Hierdie benadering poog om meer toeganklik te wees en integreer met Agile-ontwikkelingsomgewings. Dit kombineer elemente uit die ander metodologieë en fokus op **visuele voorstellings van bedreigings**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Hierdie raamwerk, wat deur die CERT Coordination Center ontwikkel is, is gerig op **organisatoriese risiko-assessering eerder as spesifieke stelsels of sagteware**.

## Tools

Daar is verskeie Tools en sagteware-oplossings beskikbaar wat kan **help** met die skep en bestuur van bedreigingsmodelle. Hier is ’n paar wat jy kan oorweeg.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

’n Gevorderde kruisplatform- en veeldoelige GUI-webspider/-crawler vir kuberveiligheidsprofessionele. Spider Suite kan vir attack surface mapping en -analise gebruik word.

**Gebruik**

1. Kies ’n URL en Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Bekyk Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

’n Oopbronprojek van OWASP. Threat Dragon is ’n web- sowel as desktop-toepassing wat stelseldiagrammering insluit, asook ’n reël-enjin om bedreigings/mitigerings outomaties te genereer.

**Gebruik**

1. Skep New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Soms kan dit so lyk:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Launch New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Save The New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Skep jou model

Jy kan Tools soos SpiderSuite Crawler gebruik om inspirasie te kry. ’n Basiese model sal ongeveer soos volg lyk:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Net ’n bietjie verduideliking oor die entiteite:

- Process (Die entiteit self, soos ’n Webserver of webfunksionaliteit)
- Actor (’n Persoon, soos ’n webwerfbesoeker, gebruiker of administrateur)
- Data Flow Line (Aanduiding van interaksie)
- Trust Boundary (Verskillende netwerksegmente of -omvang.)
- Store (Dinge waar data gestoor word, soos Databases)

5. Skep ’n Threat (Stap 1)

Eerstens moet jy die laag kies waarby jy ’n Threat wil voeg.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nou kan jy die Threat skep.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Hou in gedagte dat daar ’n verskil tussen Actor Threats en Process Threats is. As jy ’n Threat by ’n Actor voeg, sal jy slegs "Spoofing" en "Repudiation" kan kies. In ons voorbeeld voeg ons egter ’n Threat by ’n Process-entiteit, dus sal ons dit in die Threat-skeppingsvenster sien:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Klaar

Jou voltooide model behoort nou ongeveer soos volg te lyk. Só maak jy ’n eenvoudige bedreigingsmodel met OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Dit is ’n gratis Tool van Microsoft wat help om bedreigings tydens die ontwerpstadium van sagtewareprojekte te vind. Dit gebruik die STRIDE-metodologie en is besonder geskik vir ontwikkelaars wat op Microsoft se stack ontwikkel.

{{#include ../banners/hacktricks-training.md}}
