# Modeliranje pretnji

Dobrodošli u sveobuhvatan HackTricks vodič za modeliranje pretnji! Istražite ovaj kritični aspekt sajber-bezbednosti, u okviru kog identifikujemo, razumemo i planiramo odbranu od potencijalnih ranjivosti u sistemu. Ovaj vodič korak po korak sadrži primere iz stvarnog sveta, koristan softver i lako razumljiva objašnjenja. Idealan je i za početnike i za iskusne praktičare koji žele da ojačaju svoju sajber-bezbednosnu odbranu.

### Često korišćeni scenariji

1. **Razvoj softvera**: Kao deo Secure Software Development Life Cycle (SSDLC), modeliranje pretnji pomaže u **identifikovanju potencijalnih izvora ranjivosti** u ranim fazama razvoja.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) smatra modeliranje pretnji neophodnim za pravilno izvršavanje i zahteva dokumentovanje poslovnih resursa, poslovnih procesa, zajednica pretnji i njihovih mogućnosti.<sup>[[2]](#references)</sup>

### Model pretnji ukratko

Model pretnji se obično predstavlja kao dijagram, slika ili druga vizuelna ilustracija planirane arhitekture ili postojeće aplikacije. Dijagrami toka podataka (DFD) predstavljaju uobičajen način modeliranja sistema i njegovih interakcija, dok modeliranje pretnji dodaje analizu usmerenu na bezbednost.<sup>[[1]](#references)</sup>

U Microsoft Threat Modeling Tool-u crvene isprekidane linije označavaju granice poverenja; drugi alati mogu koristiti drugačije vizuelne konvencije.<sup>[[4]](#references)</sup> Da bi pojednostavili identifikaciju rizika, timovi mogu koristiti CIA trijadu (Confidentiality, Integrity, Availability) ili STRIDE kategorije pretnji, ali odgovarajuća metodologija zavisi od konteksta i zahteva projekta.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA trijada

CIA trijada je široko poznat model informacione bezbednosti koji označava Confidentiality, Integrity i Availability. Ova svojstva se često koriste za opisivanje bezbednosnih ciljeva podataka i sistema.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Obezbeđivanje da podacima ili sistemu ne pristupaju neovlašćena lica. Ovo je centralni aspekt bezbednosti koji zahteva odgovarajuće kontrole pristupa, enkripciju i druge mere za sprečavanje curenja podataka.
2. **Integrity**: Tačnost, doslednost i pouzdanost podataka tokom njihovog životnog ciklusa. Ovaj princip obezbeđuje da neovlašćene strane ne izmene podatke ili ne manipulišu njima. Često obuhvata kontrolne zbirove, hashing i druge metode verifikacije podataka.
3. **Availability**: Obezbeđuje da podaci i servisi budu dostupni ovlašćenim korisnicima kada su im potrebni. Ovo često obuhvata redundansu, toleranciju na greške i konfiguracije visoke dostupnosti kako bi sistemi nastavili da rade čak i u slučaju prekida.

### Metodologije modeliranja pretnji

1. **STRIDE**: Microsoft STRIDE pristup kategorizuje softverske pretnje kao **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Ove kategorije pomažu analitičarima da identifikuju moguće pretnje na svakoj ranjivoj tački dizajna.<sup>[[5]](#references)</sup>
2. **DREAD**: Ovaj Microsoft pristup proceni boduje pretnje na osnovu faktora **Damage, Reproducibility, Exploitability, Affected users i Discoverability**. Dobijeni rezultat može pomoći u određivanju prioriteta pretnji radi njihove mitigacije.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Ovo je sedmostepena metodologija **usmerena na rizik** koja obuhvata ciljeve, tehnički obuhvat, dekompoziciju aplikacije, analizu pretnji, analizu ranjivosti i slabosti, modeliranje napada i analizu rizika/uticaja.<sup>[[8]](#references)</sup>
4. **Trike**: Ovaj framework za bezbednosnu reviziju pristupa modeliranju pretnji iz perspektive **upravljanja rizikom** i odbrane.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Ovaj metod naglašava skalabilne i upotrebljive modele pretnji za aplikativne i operativne prikaze i može se integrisati sa razvojnim i DevOps životnim ciklusima.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): OCTAVE, koji je kreirala CERT Division of Carnegie Mellon's Software Engineering Institute, predstavlja strateški metod procene i planiranja zasnovan na riziku, usmeren na organizacioni rizik, a ne samo na tehnologiju.<sup>[[10]](#references)</sup>

## Alati

Dostupni su različiti alati i softverska rešenja koja mogu **pomoći** u kreiranju i upravljanju modelima pretnji. Evo nekoliko opcija koje možete razmotriti.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite je cross-platform web crawler za stručnjake za bezbednost koji podržava mapiranje attack surface-a, otkrivanje endpoint-a i analizu web aplikacija.<sup>[[6]](#references)</sup>

**Upotreba**

1. Izaberite URL i pokrenite Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Pregledajte Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon je besplatna, open-source, cross-platform aplikacija za modeliranje pretnji, crtanje dijagrama, predlaganje pretnji i beleženje mitigacija. Dostupna je kao web i desktop aplikacija.<sup>[[7]](#references)</sup>

**Upotreba**

1. Kreirajte novi projekat

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Ponekad može izgledati ovako:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Pokrenite novi projekat

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Sačuvajte novi projekat

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Kreirajte svoj model

Možete koristiti alate kao što je SpiderSuite Crawler za inspiraciju; osnovni model bi mogao izgledati ovako

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Kratko objašnjenje entiteta:

- Process (Sam entitet, kao što su Webserver ili web funkcionalnost)
- Actor (Osoba, kao što su posetilac web-sajta, korisnik ili administrator)
- Data Flow Line (Indikator interakcije)
- Trust Boundary (Različiti mrežni segmenti ili opsezi.)
- Store (Mesta na kojima se čuvaju podaci, kao što su baze podataka)

5. Kreirajte pretnju (1. korak)

Prvo morate izabrati sloj kojem želite da dodate pretnju

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sada možete kreirati pretnju

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Imajte na umu da postoji razlika između Actor Threats i Process Threats. Ako biste dodali pretnju Actor-u, mogli biste da izaberete samo "Spoofing" i "Repudiation. Međutim, u našem primeru dodajemo pretnju Process entitetu, pa ćemo ovo videti u polju za kreiranje pretnje:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Završeno

Vaš završeni model sada bi trebalo da izgleda približno ovako. Ovako se pravi jednostavan model pretnji pomoću OWASP Threat Dragon-a.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft Threat Modeling Tool je besplatan alat koji se preuzima i služi za analizu dizajna softvera. Njegov tok rada kreira dijagram, identifikuje pretnje i podržava mitigaciju i validaciju pomoću STRIDE pristupa.<sup>[[4]](#references)</sup>

## References

- [1] [Cheat Sheet za modeliranje pretnji](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modeliranje pretnji - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Osnove bezbednosti - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Početak rada sa Microsoft Threat Modeling Tool-om](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modeliranje pretnji za drajvere - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA modeliranje pretnji: Objašnjenje 7 faza](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 dokument metodologije](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modeliranje pretnji: Pregled dostupnih metoda](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
