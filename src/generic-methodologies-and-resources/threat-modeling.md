# Bedreigingsmodellering

Welkom by HackTricks se omvattende gids oor Threat Modeling! Begin met 'n verkenning van hierdie kritieke aspek van kuberveiligheid, waar ons potensiële kwesbaarhede in 'n stelsel identifiseer, verstaan en strategieë daarteen ontwikkel. Hierdie draad dien as 'n stap-vir-stap-gids propvol voorbeelde uit die werklike wêreld, nuttige sagteware en maklik verstaanbare verduidelikings. Ideaal vir sowel beginners as ervare praktisyns wat hul kuberveiligheidsverdediging wil versterk.

### Algemene gebruikscenario's

1. **Sagtewareontwikkeling**: As deel van die Secure Software Development Life Cycle (SSDLC) help Threat Modeling om **potensiële bronne van kwesbaarhede te identifiseer** tydens die vroeë stadiums van ontwikkeling.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Die Penetration Testing Execution Standard (PTES) beskou Threat Modeling as noodsaaklik vir korrekte uitvoering en vereis dat besigheidsbates, besigheidsprosesse, threat communities en hul vermoëns gedokumenteer word.<sup>[[2]](#references)</sup>

### Threat Model in 'n neutedop

'n Threat model word gewoonlik voorgestel as 'n diagram, beeld of ander visuele illustrasie van 'n beplande argitektuur of bestaande toepassing. Data-flow diagrams (DFDs) is 'n algemene manier om 'n stelsel en sy interaksies te modelleer, terwyl Threat Modeling 'n sekuriteitsgerigte ontleding byvoeg.<sup>[[1]](#references)</sup>

In Microsoft se Threat Modeling Tool dui rooi stippellyne trust boundaries aan; ander tools kan ander visuele konvensies gebruik.<sup>[[4]](#references)</sup> Om risk identification te stroomlyn, kan spanne die CIA (Confidentiality, Integrity, Availability)-triade of STRIDE-threat categories gebruik, maar die toepaslike metodologie hang van die projek se konteks en vereistes af.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Die CIA-triade

Die CIA-triade is 'n algemeen erkende information-security-model wat staan vir Confidentiality, Integrity en Availability. Hierdie eienskappe word algemeen gebruik om sekuriteitsdoelwitte vir data en stelsels te beskryf.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Om te verseker dat die data of stelsel nie deur ongemagtigde individue verkry word nie. Dit is 'n sentrale aspek van sekuriteit wat toepaslike toegangsbeheer, encryption en ander maatreëls vereis om data breaches te voorkom.
2. **Integrity**: Die akkuraatheid, konsekwentheid en betroubaarheid van die data gedurende sy lewensiklus. Hierdie beginsel verseker dat die data nie deur ongemagtigde partye verander of gemanipuleer word nie. Dit behels dikwels checksums, hashing en ander data-verifikasiemetodes.
3. **Availability**: Dit verseker dat data en dienste beskikbaar is vir gemagtigde gebruikers wanneer dit nodig is. Dit behels dikwels redundancy, fault tolerance en high-availability-konfigurasies om stelsels aan die gang te hou, selfs tydens ontwrigtings.

### Threat Modeling-metodologieë

1. **STRIDE**: Microsoft se STRIDE-benadering kategoriseer software threats as **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service en Elevation of Privilege**. Hierdie kategorieë help ontleders om moontlike threats by elke kwesbare punt in 'n ontwerp te identifiseer.<sup>[[5]](#references)</sup>
2. **DREAD**: Hierdie Microsoft-assesseringsbenadering beoordeel threats volgens **Damage, Reproducibility, Exploitability, Affected users en Discoverability**. Die gevolglike telling kan help om threats vir mitigation te prioritiseer.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dit is 'n sewe-stadium, **risk-centric**-metodologie wat objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling en risk/impact analysis dek.<sup>[[8]](#references)</sup>
4. **Trike**: Hierdie security-audit-framework benader Threat Modeling vanuit 'n **risk-management**- en defensiewe perspektief.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Hierdie metode beklemtoon skaalbare, bruikbare threat models vir toepassings- en operasionele aansigte en kan met development- en DevOps-lifecycles geïntegreer word.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): OCTAVE, wat deur die CERT Division van Carnegie Mellon se Software Engineering Institute geskep is, is 'n risk-based strategiese assesserings- en beplanningsmetode wat op organisatoriese risk eerder as net technology fokus.<sup>[[10]](#references)</sup>

## Tools

Daar is verskeie tools en sagteware-oplossings beskikbaar wat kan **help** met die skepping en bestuur van threat models. Hier is 'n paar wat jy kan oorweeg.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite is 'n cross-platform web crawler vir security professionals wat attack-surface mapping, endpoint discovery en web-application analysis ondersteun.<sup>[[6]](#references)</sup>

**Gebruik**

1. Kies 'n URL en Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Bekyk Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon is 'n gratis, open-source, cross-platform Threat Modeling-toepassing vir die teken van diagramme, die voorstel van threats en die aantekening van mitigations. Dit is beskikbaar as web- en desktop-toepassings.<sup>[[7]](#references)</sup>

**Gebruik**

1. Skep New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Soms kan dit soos volg lyk:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Launch New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Save The New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Skep jou model

Jy kan tools soos SpiderSuite Crawler gebruik om jou inspirasie te gee; 'n basiese model sal ongeveer so lyk:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Net 'n bietjie verduideliking oor die entiteite:

- Process (Die entiteit self, soos Webserver of web functionality)
- Actor (Een persoon, soos 'n Website Visitor, User of Administrator)
- Data Flow Line (Aanduiding van interaksie)
- Trust Boundary (Verskillende netwerksegmente of scopes.)
- Store (Dinge waar data gestoor word, soos Databases)

5. Skep 'n Threat (Stap 1)

Eerstens moet jy die layer kies waaraan jy 'n threat wil byvoeg

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nou kan jy die threat skep

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Hou in gedagte dat daar 'n verskil tussen Actor Threats en Process Threats is. As jy 'n threat by 'n Actor voeg, sal jy slegs "Spoofing" en "Repudiation" kan kies. In ons voorbeeld voeg ons egter 'n threat by 'n Process-entiteit, dus sal ons dit in die threat creation-box sien:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Klaar

Jou voltooide model behoort nou ongeveer soos volg te lyk. Só maak jy 'n eenvoudige threat model met OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft se Threat Modeling Tool is 'n gratis aflaaibare tool vir sagteware-ontwerpanalise. Die workflow daarvan skep 'n diagram, identifiseer threats en ondersteun mitigation en validation deur die STRIDE-benadering te gebruik.<sup>[[4]](#references)</sup>

## References

- [1] [Bedreigingsmodellering-kitsgids](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Bedreigingsmodellering - Die Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Sekuriteitsgrondbeginsels - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Aan die gang met die Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Bedreigingsmodellering vir drywers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: Die 7 stadiums verduidelik](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1-metodologiedokument](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: 'n Opsomming van beskikbare metodes](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
