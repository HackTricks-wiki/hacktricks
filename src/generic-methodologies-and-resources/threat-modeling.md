# Threat Modeling

{{#include /banners/hacktricks-training.md}}

## Threat Modeling

Dobrodošli u sveobuhvatan vodič HackTricks-a o modelovanju pretnji! Započnite istraživanje ovog kritičnog aspekta sajber bezbednosti, gde identifikujemo, razumemo i strategijski se borimo protiv potencijalnih ranjivosti u sistemu. Ova tema služi kao vodič korak po korak, ispunjen stvarnim primerima, korisnim softverom i lako razumljivim objašnjenjima. Idealno za novajlije i iskusne praktičare koji žele da ojačaju svoju sajber bezbednost.

### Commonly Used Scenarios

1. **Razvoj softvera**: Kao deo Sigurnog životnog ciklusa razvoja softvera (SSDLC), modelovanje pretnji pomaže u **identifikaciji potencijalnih izvora ranjivosti** u ranim fazama razvoja.
2. **Penetraciono testiranje**: Okvir za izvršenje penetracionog testiranja (PTES) zahteva **modelovanje pretnji kako bi se razumele ranjivosti sistema** pre sprovođenja testa.

### Threat Model in a Nutshell

Model pretnji se obično prikazuje kao dijagram, slika ili neki drugi oblik vizuelne ilustracije koji prikazuje planiranu arhitekturu ili postojeću izgradnju aplikacije. Podseća na **dijagram toka podataka**, ali ključna razlika leži u njegovom dizajnu orijentisanom na bezbednost.

Modeli pretnji često sadrže elemente označene crvenom bojom, simbolizujući potencijalne ranjivosti, rizike ili prepreke. Da bi se pojednostavio proces identifikacije rizika, koristi se CIA (Poverljivost, Integritet, Dostupnost) trojka, koja čini osnovu mnogih metodologija modelovanja pretnji, pri čemu je STRIDE jedna od najčešćih. Međutim, odabrana metodologija može varirati u zavisnosti od specifičnog konteksta i zahteva.

### The CIA Triad

CIA trojka je široko prepoznat model u oblasti informacione bezbednosti, koji se odnosi na Poverljivost, Integritet i Dostupnost. Ove tri stuba čine osnovu na kojoj se grade mnoge mere i politike bezbednosti, uključujući metodologije modelovanja pretnji.

1. **Poverljivost**: Osiguranje da podaci ili sistem nisu dostupni neovlašćenim osobama. Ovo je centralni aspekt bezbednosti, koji zahteva odgovarajuće kontrole pristupa, enkripciju i druge mere za sprečavanje curenja podataka.
2. **Integritet**: Tačnost, doslednost i pouzdanost podataka tokom njihovog životnog ciklusa. Ova načela osiguravaju da podaci nisu izmenjeni ili kompromitovani od strane neovlašćenih strana. Često uključuje kontrolne sume, heširanje i druge metode verifikacije podataka.
3. **Dostupnost**: Ovo osigurava da su podaci i usluge dostupni ovlašćenim korisnicima kada su potrebni. Ovo često uključuje redundanciju, otpornost na greške i konfiguracije visoke dostupnosti kako bi se sistemi održavali u radu čak i u slučaju prekida.

### Threat Modeling Methodlogies

1. **STRIDE**: Razvijen od strane Microsoft-a, STRIDE je akronim za **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Svaka kategorija predstavlja tip pretnje, a ova metodologija se obično koristi u fazi dizajniranja programa ili sistema za identifikaciju potencijalnih pretnji.
2. **DREAD**: Ovo je još jedna metodologija iz Microsoft-a koja se koristi za procenu rizika identifikovanih pretnji. DREAD se odnosi na **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Svaki od ovih faktora se boduje, a rezultat se koristi za prioritizaciju identifikovanih pretnji.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Ovo je metodologija zasnovana na **riziku** koja se sastoji od sedam koraka. Uključuje definisanje i identifikaciju bezbednosnih ciljeva, kreiranje tehničkog okvira, dekompoziciju aplikacije, analizu pretnji, analizu ranjivosti i procenu rizika/triage.
4. **Trike**: Ovo je metodologija zasnovana na riziku koja se fokusira na odbranu sredstava. Počinje iz perspektive **upravljanja rizikom** i gleda na pretnje i ranjivosti u tom kontekstu.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Ovaj pristup ima za cilj da bude pristupačniji i integriše se u Agile razvojne okruženja. Kombinuje elemente iz drugih metodologija i fokusira se na **vizuelne prikaze pretnji**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Razvijen od strane CERT Coordination Center, ovaj okvir je usmeren ka **organizacionoj proceni rizika umesto na specifične sisteme ili softver**.

## Tools

Postoji nekoliko alata i softverskih rešenja dostupnih koja mogu **pomoći** u kreiranju i upravljanju modelima pretnji. Evo nekoliko koje biste mogli razmotriti.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Napredni višepplatformski i višefunkcionalni GUI web spider/crawler za profesionalce u sajber bezbednosti. Spider Suite se može koristiti za mapiranje i analizu površine napada.

**Usage**

1. Izaberite URL i Crawlujte

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Prikaz grafika

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projekat otvorenog koda iz OWASP-a, Threat Dragon je i web i desktop aplikacija koja uključuje dijagramiranje sistema kao i pravilo za automatsko generisanje pretnji/mitigacija.

**Usage**

1. Kreirajte novi projekat

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Ponekad može izgledati ovako:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Pokrenite novi projekat

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Sačuvajte novi projekat

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Kreirajte svoj model

Možete koristiti alate poput SpiderSuite Crawler-a da vam daju inspiraciju, osnovni model bi izgledao ovako

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Samo malo objašnjenja o entitetima:

- Proces (Sam entitet kao što je Webserver ili web funkcionalnost)
- Akter (Osoba kao što je posetilac veb sajta, korisnik ili administrator)
- Linija toka podataka (Indikator interakcije)
- Granica poverenja (Različiti mrežni segmenti ili opsezi.)
- Skladište (Mesta gde se podaci čuvaju kao što su baze podataka)

5. Kreirajte pretnju (Korak 1)

Prvo morate izabrati sloj kojem želite dodati pretnju

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sada možete kreirati pretnju

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Imajte na umu da postoji razlika između pretnji aktera i pretnji procesa. Ako biste dodali pretnju akteru, tada ćete moći da izaberete samo "Spoofing" i "Repudiation". Međutim, u našem primeru dodajemo pretnju entitetu procesa, tako da ćemo ovo videti u okviru za kreiranje pretnje:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Gotovo

Sada vaš završeni model treba da izgleda ovako. I ovako pravite jednostavan model pretnje sa OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Ovo je besplatan alat od Microsoft-a koji pomaže u pronalaženju pretnji u fazi dizajniranja softverskih projekata. Koristi STRIDE metodologiju i posebno je pogodan za one koji razvijaju na Microsoft-ovom stack-u.


{{#include /banners/hacktricks-training.md}}
