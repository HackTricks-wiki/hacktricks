# Modelovanje pretnji

{{#include ../banners/hacktricks-training.md}}

## Modelovanje pretnji

Dobro došli u sveobuhvatan HackTricks vodič za modelovanje pretnji! Istražite ovaj ključni aspekt sajber bezbednosti, u okviru kog identifikujemo, razumemo i planiramo odbranu od potencijalnih ranjivosti u sistemu. Ova tema služi kao vodič korak po korak, sa primerima iz stvarnog sveta, korisnim softverom i lako razumljivim objašnjenjima. Idealna je i za početnike i za iskusne praktičare koji žele da ojačaju svoju sajber bezbednost.

### Često korišćeni scenariji

1. **Razvoj softvera**: Kao deo Secure Software Development Life Cycle (SSDLC), modelovanje pretnji pomaže u **identifikovanju potencijalnih izvora ranjivosti** u ranim fazama razvoja.
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework zahteva **modelovanje pretnji radi razumevanja ranjivosti sistema** pre sprovođenja testa.

### Model pretnji ukratko

Model pretnji se obično predstavlja kao dijagram, slika ili neki drugi oblik vizuelne ilustracije koja prikazuje planiranu arhitekturu ili postojeću izgradnju aplikacije. Sličan je **dijagramu toka podataka**, ali ključna razlika je u njegovom dizajnu usmerenom na bezbednost.

Modeli pretnji često sadrže elemente označene crvenom bojom, koji simbolizuju potencijalne ranjivosti, rizike ili prepreke. Kako bi se pojednostavio proces identifikacije rizika, koristi se CIA trijada (Confidentiality, Integrity, Availability), koja predstavlja osnovu mnogih metodologija modelovanja pretnji, pri čemu je STRIDE jedna od najčešćih. Međutim, izabrana metodologija može da se razlikuje u zavisnosti od konkretnog konteksta i zahteva.

### CIA trijada

CIA trijada je široko poznat model u oblasti informacione bezbednosti i označava Confidentiality, Integrity i Availability. Ova tri stuba predstavljaju osnovu na kojoj se zasnivaju mnoge bezbednosne mere i politike, uključujući metodologije modelovanja pretnji.

1. **Poverljivost (Confidentiality)**: Obezbeđivanje da podacima ili sistemu ne pristupaju neovlašćena lica. Ovo je centralni aspekt bezbednosti i zahteva odgovarajuće kontrole pristupa, enkripciju i druge mere za sprečavanje data breaches.
2. **Integritet (Integrity)**: Tačnost, doslednost i pouzdanost podataka tokom njihovog životnog ciklusa. Ovaj princip obezbeđuje da neovlašćene strane ne menjaju podatke niti manipulišu njima. Često obuhvata checksums, hashing i druge metode verifikacije podataka.
3. **Dostupnost (Availability)**: Obezbeđuje da ovlašćeni korisnici mogu da pristupe podacima i uslugama kada je to potrebno. Ovo često obuhvata redundansu, toleranciju na greške i konfiguracije visoke dostupnosti kako bi sistemi nastavili da rade čak i u slučaju prekida.

### Metodologije modelovanja pretnji

1. **STRIDE**: STRIDE, koji je razvio Microsoft, predstavlja akronim za **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service i Elevation of Privilege**. Svaka kategorija predstavlja jednu vrstu pretnje, a ova metodologija se često koristi u fazi dizajna programa ili sistema za identifikaciju potencijalnih pretnji.
2. **DREAD**: Ovo je još jedna Microsoft metodologija koja se koristi za procenu rizika identifikovanih pretnji. DREAD označava **Damage potential, Reproducibility, Exploitability, Affected users i Discoverability**. Svaki od ovih faktora se ocenjuje, a rezultat se koristi za određivanje prioriteta identifikovanih pretnji.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Ovo je metodologija u sedam koraka, **usmerena na rizik**. Obuhvata definisanje i identifikovanje bezbednosnih ciljeva, određivanje tehničkog obuhvata, dekompoziciju aplikacije, analizu pretnji, analizu ranjivosti i procenu rizika/prioritizaciju.
4. **Trike**: Ovo je metodologija zasnovana na riziku koja se fokusira na zaštitu resursa. Polazi iz perspektive **upravljanja rizikom** i posmatra pretnje i ranjivosti u tom kontekstu.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Ovaj pristup nastoji da bude pristupačniji i integriše se u Agile razvojna okruženja. Kombinuje elemente drugih metodologija i fokusira se na **vizuelne prikaze pretnji**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Ovaj framework, koji je razvio CERT Coordination Center, usmeren je ka **proceni organizacionog rizika, a ne ka konkretnim sistemima ili softveru**.

## Alati

Dostupno je nekoliko alata i softverskih rešenja koja mogu da **pomognu** pri izradi i upravljanju modelima pretnji. Evo nekoliko alata koje možete razmotriti.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Napredni cross-platform i višefunkcionalni GUI web spider/crawler za profesionalce u oblasti sajber bezbednosti. Spider Suite se može koristiti za mapiranje i analizu attack surface-a.

**Upotreba**

1. Izaberite URL i pokrenite Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Pregledajte Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projekat otvorenog koda organizacije OWASP, Threat Dragon je web i desktop aplikacija koja obuhvata izradu sistemskih dijagrama, kao i rule engine za automatsko generisanje pretnji/mitigacija.

**Upotreba**

1. Kreirajte New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Ponekad može da izgleda ovako:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Pokrenite New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Sačuvajte New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Kreirajte svoj model

Možete koristiti alate kao što je SpiderSuite Crawler da biste dobili inspiraciju; osnovni model bi mogao da izgleda ovako

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Kratko objašnjenje entiteta:

- Process (Sam entitet, kao što su Webserver ili web funkcionalnost)
- Actor (Osoba, kao što su Visitor veb-sajta, User ili Administrator)
- Data Flow Line (Indikator interakcije)
- Trust Boundary (Različiti mrežni segmenti ili opsezi.)
- Store (Mesta na kojima se čuvaju podaci, kao što su Databases)

5. Kreirajte Threat (Korak 1)

Najpre morate da izaberete layer kojem želite da dodate threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sada možete da kreirate threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Imajte na umu da postoji razlika između Actor Threats i Process Threats. Ako biste dodali threat Actor-u, mogli biste da izaberete samo "Spoofing" i "Repudiation". Međutim, u našem primeru dodajemo threat Process entitetu, pa ćemo u threat creation box-u videti sledeće:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Završeno

Vaš završeni model sada bi trebalo da izgleda ovako. Ovako se pravi jednostavan model pretnji pomoću OWASP Threat Dragon-a.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Ovo je besplatan Microsoft alat koji pomaže u pronalaženju pretnji u fazi dizajna softverskih projekata. Koristi STRIDE metodologiju i naročito je pogodan za one koji razvijaju na Microsoft stack-u.

{{#include ../banners/hacktricks-training.md}}
