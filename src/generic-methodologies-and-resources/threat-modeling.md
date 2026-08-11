# Modeliranje pretnji

{{#include ../banners/hacktricks-training.md}}

Dobro došli u sveobuhvatan HackTricks vodič za modeliranje pretnji! Istražite ovaj ključni aspekt cybersecurity-ja, gde identifikujemo, razumemo i planiramo odbranu od potencijalnih ranjivosti u sistemu. Ovaj tekst služi kao vodič korak po korak, sa primerima iz stvarnog sveta, korisnim softverom i lako razumljivim objašnjenjima. Idealan je za početnike i iskusne praktičare koji žele da ojačaju svoje cybersecurity odbrane.

### Često korišćeni scenariji

1. **Razvoj softvera**: Kao deo Secure Software Development Life Cycle (SSDLC), modeliranje pretnji pomaže u **identifikovanju potencijalnih izvora ranjivosti** u ranim fazama razvoja.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) tretira modeliranje pretnji kao obavezno za pravilno izvršavanje i zahteva dokumentovanje poslovnih sredstava, poslovnih procesa, zajednica pretnji i njihovih mogućnosti.<sup>[[2]](#references)</sup>

### Model pretnji ukratko

Model pretnji se obično predstavlja kao dijagram, slika ili druga vizuelna ilustracija planirane arhitekture ili postojeće aplikacije. Data-flow dijagrami (DFD) predstavljaju uobičajen način modeliranja sistema i njegovih interakcija, dok modeliranje pretnji dodaje analizu usmerenu na sigurnost.<sup>[[1]](#references)</sup>

U Microsoft-ovom Threat Modeling Tool-u, crvene isprekidane linije označavaju granice poverenja; drugi alati mogu koristiti drugačije vizuelne konvencije.<sup>[[4]](#references)</sup> Da bi pojednostavili identifikovanje rizika, timovi mogu koristiti CIA (Confidentiality, Integrity, Availability) trijadu ili STRIDE kategorije pretnji, ali odgovarajuća metodologija zavisi od konteksta i zahteva projekta.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA trijada

CIA trijada je široko prepoznat model informacione sigurnosti koji označava Confidentiality, Integrity i Availability. Ova svojstva se često koriste za opisivanje sigurnosnih ciljeva podataka i sistema.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Obezbeđivanje da podacima ili sistemu ne pristupaju neovlašćene osobe. Ovo je centralni aspekt sigurnosti i zahteva odgovarajuće kontrole pristupa, enkripciju i druge mere za sprečavanje data breach-eva.
2. **Integrity**: Tačnost, doslednost i pouzdanost podataka tokom njihovog životnog ciklusa. Ovaj princip obezbeđuje da neovlašćene strane ne menjaju ili ne manipulišu podacima. Često obuhvata checksums, hashing i druge metode verifikacije podataka.
3. **Availability**: Obezbeđuje da podaci i servisi budu dostupni ovlašćenim korisnicima kada su im potrebni. Ovo često obuhvata redundansu, fault tolerance i konfiguracije visoke dostupnosti kako bi sistemi nastavili da rade čak i u slučaju prekida.

### Metodologije modeliranja pretnji

1. **STRIDE**: Microsoft-ov STRIDE pristup kategorizuje softverske pretnje kao **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Ove kategorije pomažu analitičarima da identifikuju moguće pretnje na svakoj ranjivoj tački dizajna.<sup>[[5]](#references)</sup>
2. **DREAD**: Ovaj Microsoft-ov pristup proceni boduje pretnje pomoću kriterijuma **Damage, Reproducibility, Exploitability, Affected users i Discoverability**. Dobijeni rezultat može pomoći u određivanju prioriteta pretnji za ublažavanje.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Ovo je sedmostepena metodologija usmerena na **rizik**, koja obuhvata ciljeve, tehnički obim, dekompoziciju aplikacije, analizu pretnji, analizu ranjivosti i slabosti, modeliranje napada i analizu rizika/uticaja.<sup>[[8]](#references)</sup>
4. **Trike**: Ovaj framework za sigurnosnu reviziju pristupa modeliranju pretnji iz perspektive **upravljanja rizikom** i odbrane.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Ovaj metod naglašava skalabilne i upotrebljive modele pretnji za aplikativne i operativne prikaze i može se integrisati sa razvojnim i DevOps životnim ciklusima.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): OCTAVE, koji je kreirala CERT Division of Carnegie Mellon's Software Engineering Institute, predstavlja strateški metod procene i planiranja zasnovan na riziku, usmeren na organizacioni rizik, a ne samo na tehnologiju.<sup>[[10]](#references)</sup>

## Alati

Dostupno je nekoliko alata i softverskih rešenja koja mogu **pomoći** pri kreiranju i upravljanju modelima pretnji. Evo nekoliko opcija koje možete razmotriti.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite je cross-platform web crawler za security profesionalce koji podržava mapiranje attack surface-a, otkrivanje endpoint-a i analizu web aplikacija.<sup>[[6]](#references)</sup>

**Upotreba**

1. Izaberite URL i pokrenite Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Prikažite Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon je besplatna, open-source, cross-platform aplikacija za modeliranje pretnji, crtanje dijagrama, predlaganje pretnji i beleženje mera za njihovo ublažavanje. Dostupna je kao web i desktop aplikacija.<sup>[[7]](#references)</sup>

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

Možete koristiti alate kao što je SpiderSuite Crawler kao inspiraciju; osnovni model bi izgledao otprilike ovako

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Ukratko objašnjenje entiteta:

- Process (sam entitet, kao što su Webserver ili web funkcionalnost)
- Actor (osoba, kao što su posetilac web-sajta, korisnik ili administrator)
- Data Flow Line (indikator interakcije)
- Trust Boundary (različiti mrežni segmenti ili opsezi)
- Store (mesta na kojima se čuvaju podaci, kao što su Database)

5. Kreirajte pretnju (korak 1)

Najpre morate izabrati layer kome želite da dodate pretnju

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sada možete kreirati pretnju

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Imajte na umu da postoji razlika između Actor Threats i Process Threats. Ako biste dodali pretnju Actor-u, mogli biste izabrati samo "Spoofing" i "Repudiation". Međutim, u našem primeru dodajemo pretnju Process entitetu, pa ćemo u polju za kreiranje pretnje videti sledeće:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Završeno

Vaš završeni model sada bi trebalo da izgleda otprilike ovako. Ovo je način na koji možete napraviti jednostavan model pretnji pomoću OWASP Threat Dragon-a.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft-ov Threat Modeling Tool je besplatan alat koji se preuzima i koristi za analizu dizajna softvera. Njegov workflow kreira dijagram, identifikuje pretnje i podržava ublažavanje i validaciju pomoću STRIDE pristupa.<sup>[[4]](#references)</sup>

## References

- [1] [Cheat Sheet za modeliranje pretnji](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Modeliranje pretnji - Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Osnove sigurnosti - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Početak rada sa Microsoft Threat Modeling Tool-om](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Modeliranje pretnji za drivere - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA modeliranje pretnji: Objašnjenje 7 faza](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 dokument metodologije](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Modeliranje pretnji: Pregled dostupnih metoda](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
