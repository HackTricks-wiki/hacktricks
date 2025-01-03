# Bedreigingsmodellering

## Bedreigingsmodellering

Welkom by HackTricks se omvattende gids oor Bedreigingsmodellering! Begin 'n verkenning van hierdie kritieke aspek van kuberveiligheid, waar ons potensiële kwesbaarhede in 'n stelsel identifiseer, verstaan en strategieë ontwikkel. Hierdie draad dien as 'n stap-vir-stap gids vol werklike voorbeelde, nuttige sagteware en maklik verstaanbare verduidelikings. Ideaal vir beide beginners en ervare praktisyns wat hul kuberveiligheid verdediging wil versterk.

### Gewoonlik Gebruikte Scenario's

1. **Sagteware Ontwikkeling**: As deel van die Veilige Sagteware Ontwikkelingslewe Siklus (SSDLC), help bedreigingsmodellering om **potensiële bronne van kwesbaarhede** in die vroeë stadiums van ontwikkeling te identifiseer.
2. **Penetrasietoetsing**: Die Penetrasietoetsing Uitvoeringsstandaard (PTES) raamwerk vereis **bedreigingsmodellering om die stelsel se kwesbaarhede** te verstaan voordat die toets uitgevoer word.

### Bedreigingsmodel in 'n Neutedop

'n Bedreigingsmodel word tipies voorgestel as 'n diagram, beeld, of 'n ander vorm van visuele illustrasie wat die beplande argitektuur of bestaande bou van 'n toepassing uitbeeld. Dit is soortgelyk aan 'n **data vloei diagram**, maar die sleutelonderskeid lê in die sekuriteitsgerigte ontwerp.

Bedreigingsmodelle bevat dikwels elemente wat in rooi gemerk is, wat potensiële kwesbaarhede, risiko's of hindernisse simboliseer. Om die proses van risiko-identifikasie te stroomlyn, word die CIA (Vertroulikheid, Integriteit, Beskikbaarheid) triade gebruik, wat die basis vorm van baie bedreigingsmodellering metodologieë, met STRIDE as een van die mees algemene. Die gekose metodologie kan egter wissel, afhangende van die spesifieke konteks en vereistes.

### Die CIA Triade

Die CIA Triade is 'n algemeen erkende model in die veld van inligtingsveiligheid, wat staan vir Vertroulikheid, Integriteit, en Beskikbaarheid. Hierdie drie pilare vorm die grondslag waarop baie sekuriteitsmaatreëls en -beleide gebou is, insluitend bedreigingsmodellering metodologieë.

1. **Vertroulikheid**: Verseker dat die data of stelsel nie deur ongeoorloofde individue toegang verkry word nie. Dit is 'n sentrale aspek van sekuriteit, wat toepaslike toegangbeheer, versleuteling, en ander maatreëls vereis om datalekke te voorkom.
2. **Integriteit**: Die akkuraatheid, konsekwentheid, en betroubaarheid van die data oor sy lewensiklus. Hierdie beginsel verseker dat die data nie deur ongeoorloofde partye verander of gemanipuleer word nie. Dit behels dikwels kontrole, hashing, en ander data-verifikasiemetodes.
3. **Beskikbaarheid**: Dit verseker dat data en dienste beskikbaar is vir geautoriseerde gebruikers wanneer nodig. Dit behels dikwels redundansie, fouttoleransie, en hoë-beskikbaarheid konfigurasies om stelsels aan die gang te hou, selfs in die gesig van onderbrekings.

### Bedreigingsmodellering Metodologieë

1. **STRIDE**: Ontwikkel deur Microsoft, STRIDE is 'n akroniem vir **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Elke kategorie verteenwoordig 'n tipe bedreiging, en hierdie metodologie word algemeen gebruik in die ontwerpfase van 'n program of stelsel om potensiële bedreigings te identifiseer.
2. **DREAD**: Dit is 'n ander metodologie van Microsoft wat gebruik word vir risiko-assessering van geïdentifiseerde bedreigings. DREAD staan vir **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Elke van hierdie faktore word gegradeer, en die resultaat word gebruik om geïdentifiseerde bedreigings te prioriseer.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dit is 'n sewe-stap, **risiko-georiënteerde** metodologie. Dit sluit die definisie en identifikasie van sekuriteitsdoelwitte in, die skep van 'n tegniese omvang, toepassingsdekomposisie, bedreigingsanalise, kwesbaarheidsanalise, en risiko/triage assessering.
4. **Trike**: Dit is 'n risiko-gebaseerde metodologie wat fokus op die verdediging van bates. Dit begin vanuit 'n **risiko bestuur** perspektief en kyk na bedreigings en kwesbaarhede in daardie konteks.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Hierdie benadering poog om meer toeganklik te wees en integreer in Agile ontwikkelingsomgewings. Dit kombineer elemente van die ander metodologieë en fokus op **visuele voorstellings van bedreigings**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Ontwikkel deur die CERT Koördinasiesentrum, is hierdie raamwerk gerig op **organisatoriese risiko-assessering eerder as spesifieke stelsels of sagteware**.

## Gereedskap

Daar is verskeie gereedskap en sagteware-oplossings beskikbaar wat kan **help** met die skepping en bestuur van bedreigingsmodelle. Hier is 'n paar wat jy mag oorweeg.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

'n Gevorderde kruis-platform en multi-funksie GUI web spinnekop/kruiper vir kuberveiligheid professionele. Spider Suite kan gebruik word vir aanval oppervlak kaartlegging en analise.

**Gebruik**

1. Kies 'n URL en Kruip

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Bekyk Grafiek

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

'n Oopbronprojek van OWASP, Threat Dragon is beide 'n web- en desktoptoepassing wat stelseldiagrammering insluit sowel as 'n reël-enjin om bedreigings/mitigasies outomaties te genereer.

**Gebruik**

1. Skep Nuwe Projek

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Soms kan dit soos volg lyk:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Begin Nuwe Projek

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Stoor Die Nuwe Projek

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Skep jou model

Jy kan gereedskap soos SpiderSuite Crawler gebruik om jou inspirasie te gee, 'n basiese model kan iets soos hierdie lyk

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Net 'n bietjie verduideliking oor die entiteite:

- Proses (Die entiteit self soos Webbediener of web funksionaliteit)
- Akteur ( 'n Persoon soos 'n Webwerf Besoeker, Gebruiker of Administrateur)
- Data Vloei Lyn (Aanduiding van Interaksie)
- Vertroue Grens (Verskillende netwerksegmente of skope.)
- Stoor (Dinge waar data gestoor word soos Databasisse)

5. Skep 'n Bedreiging (Stap 1)

Eerstens moet jy die laag kies waaraan jy 'n bedreiging wil toevoeg

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nou kan jy die bedreiging skep

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Hou in gedagte dat daar 'n verskil is tussen Akteur Bedreigings en Proses Bedreigings. As jy 'n bedreiging aan 'n Akteur sou toevoeg, sal jy slegs "Spoofing" en "Repudiation" kan kies. In ons voorbeeld voeg ons egter 'n bedreiging aan 'n Proses entiteit toe, so ons sal dit in die bedreiging skeppingskassie sien:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Klaar

Nou moet jou voltooide model iets soos hierdie lyk. En dit is hoe jy 'n eenvoudige bedreigingsmodel met OWASP Threat Dragon maak.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Dit is 'n gratis gereedskap van Microsoft wat help om bedreigings in die ontwerpfase van sagtewareprojekte te vind. Dit gebruik die STRIDE metodologie en is veral geskik vir diegene wat op Microsoft se stapel ontwikkel.
