# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Da biste saznali više o macOS MDM-ima, proverite:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Osnovi

### **MDM (Upravljanje mobilnim uređajima) Pregled**

[Upravljanje mobilnim uređajima](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) se koristi za nadgledanje različitih uređaja krajnjih korisnika kao što su pametni telefoni, laptopovi i tableti. Posebno za Apple-ove platforme (iOS, macOS, tvOS), uključuje skup specijalizovanih funkcija, API-ja i praksi. Rad MDM-a zavisi od kompatibilnog MDM servera, koji može biti komercijalno dostupan ili otvorenog koda, i mora podržavati [MDM protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ključne tačke uključuju:

- Centralizovana kontrola nad uređajima.
- Zavist od MDM servera koji se pridržava MDM protokola.
- Sposobnost MDM servera da šalje različite komande uređajima, na primer, daljinsko brisanje podataka ili instalaciju konfiguracije.

### **Osnovi DEP (Program za registraciju uređaja)**

[Program za registraciju uređaja](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) koji nudi Apple pojednostavljuje integraciju upravljanja mobilnim uređajima (MDM) omogućavajući konfiguraciju bez dodira za iOS, macOS i tvOS uređaje. DEP automatizuje proces registracije, omogućavajući uređajima da budu operativni odmah po otvaranju pakovanja, uz minimalnu intervenciju korisnika ili administratora. Osnovni aspekti uključuju:

- Omogućava uređajima da se autonomno registruju sa unapred definisanim MDM serverom prilikom prve aktivacije.
- Prvenstveno korisno za potpuno nove uređaje, ali takođe primenljivo na uređaje koji prolaze kroz rekonfiguraciju.
- Olakšava jednostavnu postavku, čineći uređaje spremnim za organizacionu upotrebu brzo.

### **Razmatranje bezbednosti**

Važno je napomenuti da lakoća registracije koju pruža DEP, iako korisna, može takođe predstavljati bezbednosne rizike. Ako zaštitne mere nisu adekvatno primenjene za MDM registraciju, napadači bi mogli iskoristiti ovaj pojednostavljeni proces da registruju svoj uređaj na MDM serveru organizacije, pretvarajući se da je korporativni uređaj.

> [!CAUTION]
> **Bezbednosna upozorenje**: Pojednostavljena DEP registracija mogla bi potencijalno omogućiti neovlašćenu registraciju uređaja na MDM serveru organizacije ako odgovarajuće zaštitne mere nisu na snazi.

### Osnovi Šta je SCEP (Protokol za jednostavnu registraciju sertifikata)?

- Relativno stari protokol, stvoren pre nego što su TLS i HTTPS postali široko rasprostranjeni.
- Daje klijentima standardizovan način slanja **Zahteva za potpisivanje sertifikata** (CSR) u svrhu dobijanja sertifikata. Klijent će tražiti od servera da mu da potpisani sertifikat.

### Šta su Konfiguracijski profili (aka mobileconfigs)?

- Apple-ov zvanični način **postavljanja/primene sistemske konfiguracije.**
- Format datoteke koji može sadržati više tereta.
- Zasnovan na listama svojstava (XML tip).
- “mogu biti potpisani i šifrovani kako bi se potvrdio njihov izvor, osigurala njihova celovitost i zaštitili njihovi sadržaji.” Osnovi — Strana 70, iOS Security Guide, januar 2018.

## Protokoli

### MDM

- Kombinacija APNs (**Apple server**i) + RESTful API (**MDM** **dobavljači** serveri)
- **Komunikacija** se odvija između **uređaja** i servera povezanog sa **proizvodom za upravljanje uređajima**
- **Komande** se isporučuju sa MDM-a na uređaj u **plist-encoded rečnicima**
- Sve preko **HTTPS**. MDM serveri mogu biti (i obično su) pinovani.
- Apple dodeljuje MDM dobavljaču **APNs sertifikat** za autentifikaciju

### DEP

- **3 API-ja**: 1 za prodavce, 1 za MDM dobavljače, 1 za identitet uređaja (nedokumentovano):
- Takozvani [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ovo koriste MDM serveri da povežu DEP profile sa specifičnim uređajima.
- [DEP API koji koriste Apple ovlašćeni prodavci](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) za registraciju uređaja, proveru statusa registracije i proveru statusa transakcije.
- Nedokumentovani privatni DEP API. Ovo koriste Apple uređaji da zatraže svoj DEP profil. Na macOS-u, `cloudconfigurationd` binarni fajl je odgovoran za komunikaciju preko ovog API-ja.
- Moderniji i **JSON** zasnovan (naspram plist)
- Apple dodeljuje **OAuth token** MDM dobavljaču

**DEP "cloud service" API**

- RESTful
- sinhronizuje zapise uređaja sa Apple-a na MDM server
- sinhronizuje “DEP profile” sa Apple-om sa MDM servera (isporučuje Apple uređaju kasnije)
- DEP “profil” sadrži:
- URL MDM dobavljača servera
- Dodatni pouzdani sertifikati za URL servera (opciono pinovanje)
- Dodatne postavke (npr. koje ekrane preskočiti u Setup Assistant)

## Serijski broj

Apple uređaji proizvedeni nakon 2010. obično imaju **12-znamenkaste alfanumeričke** serijske brojeve, pri čemu **prva tri broja predstavljaju mesto proizvodnje**, sledeća **dva** označavaju **godinu** i **nedelju** proizvodnje, sledeća **tri** broja daju **jedinstveni** **identifikator**, a **poslednja** **četiri** broja predstavljaju **broj modela**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Koraci za registraciju i upravljanje

1. Kreiranje zapisa uređaja (Prodavac, Apple): Zapis za novi uređaj se kreira
2. Dodeljivanje zapisa uređaja (Kupac): Uređaj se dodeljuje MDM serveru
3. Sinhronizacija zapisa uređaja (MDM dobavljač): MDM sinhronizuje zapise uređaja i šalje DEP profile Apple-u
4. DEP prijava (Uređaj): Uređaj dobija svoj DEP profil
5. Preuzimanje profila (Uređaj)
6. Instalacija profila (Uređaj) a. uključuje MDM, SCEP i root CA terete
7. Izdavanje MDM komande (Uređaj)

![](<../../../images/image (694).png>)

Datoteka `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` izvozi funkcije koje se mogu smatrati **visok nivo "koraka"** procesa registracije.

### Korak 4: DEP prijava - Dobijanje aktivacionog zapisa

Ovaj deo procesa se odvija kada **korisnik prvi put pokrene Mac** (ili nakon potpunog brisanja)

![](<../../../images/image (1044).png>)

ili kada se izvršava `sudo profiles show -type enrollment`

- Utvrditi **da li je uređaj DEP omogućen**
- Aktivacioni zapis je interno ime za **DEP “profil”**
- Počinje čim se uređaj poveže na Internet
- Pokreće ga **`CPFetchActivationRecord`**
- Implementira ga **`cloudconfigurationd`** putem XPC. **"Setup Assistant"** (kada se uređaj prvi put pokrene) ili **`profiles`** komanda će **kontaktirati ovaj daemon** da preuzme aktivacioni zapis.
- LaunchDaemon (uvek se pokreće kao root)

Sledi nekoliko koraka da se dobije aktivacioni zapis koji obavlja **`MCTeslaConfigurationFetcher`**. Ovaj proces koristi enkripciju nazvanu **Absinthe**

1. Preuzmi **sertifikat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicijalizuj** stanje iz sertifikata (**`NACInit`**)
1. Koristi razne podatke specifične za uređaj (tj. **Serijski broj putem `IOKit`**)
3. Preuzmi **ključ sesije**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Uspostavi sesiju (**`NACKeyEstablishment`**)
5. Napravi zahtev
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) šaljući podatke `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON teret je šifrovan koristeći Absinthe (**`NACSign`**)
3. Svi zahtevi preko HTTPs, korišćeni su ugrađeni root sertifikati

![](<../../../images/image (566) (1).png>)

Odgovor je JSON rečnik sa nekim važnim podacima kao što su:

- **url**: URL domaćina MDM dobavljača za aktivacioni profil
- **anchor-certs**: Niz DER sertifikata korišćenih kao pouzdani sidri

### **Korak 5: Preuzimanje profila**

![](<../../../images/image (444).png>)

- Zahtev poslat na **url naveden u DEP profilu**.
- **Sidreni sertifikati** se koriste za **procenu poverenja** ako su navedeni.
- Podsetnik: **anchor_certs** svojstvo DEP profila
- **Zahtev je jednostavan .plist** sa identifikacijom uređaja
- Primeri: **UDID, verzija OS-a**.
- CMS-potpisan, DER-enkodiran
- Potpisan koristeći **sertifikat identiteta uređaja (iz APNS-a)**
- **Lanac sertifikata** uključuje istekao **Apple iPhone Device CA**

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Korak 6: Instalacija profila

- Kada se preuzme, **profil se čuva na sistemu**
- Ovaj korak počinje automatski (ako je u **setup assistant**)
- Pokreće ga **`CPInstallActivationProfile`**
- Implementira ga mdmclient preko XPC
- LaunchDaemon (kao root) ili LaunchAgent (kao korisnik), u zavisnosti od konteksta
- Konfiguracijski profili imaju više tereta za instalaciju
- Okvir ima arhitekturu zasnovanu na plugin-ima za instalaciju profila
- Svaka vrsta tereta je povezana sa plugin-om
- Može biti XPC (u okviru) ili klasični Cocoa (u ManagedClient.app)
- Primer:
- Tereti sertifikata koriste CertificateService.xpc

Obično, **aktivacioni profil** koji pruža MDM dobavljač će **uključivati sledeće terete**:

- `com.apple.mdm`: da **registruje** uređaj u MDM
- `com.apple.security.scep`: da sigurno obezbedi **sertifikat klijenta** uređaju.
- `com.apple.security.pem`: da **instalira pouzdane CA sertifikate** u sistemski ključan.
- Instalacija MDM tereta ekvivalentna je **MDM prijavi u dokumentaciji**
- Teret **sadrži ključne osobine**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs tema za aktivaciju
- Da bi se instalirao MDM teret, zahtev se šalje na **`CheckInURL`**
- Implementirano u **`mdmclient`**
- MDM teret može zavisiti od drugih tereta
- Omogućava **zahteve da budu pinovani na specifične sertifikate**:
- Svojstvo: **`CheckInURLPinningCertificateUUIDs`**
- Svojstvo: **`ServerURLPinningCertificateUUIDs`**
- Isporučuje se putem PEM tereta
- Omogućava uređaju da bude dodeljen sertifikat identiteta:
- Svojstvo: IdentityCertificateUUID
- Isporučuje se putem SCEP tereta

### **Korak 7: Slušanje za MDM komande**

- Nakon što je MDM prijava završena, dobavljač može **izdati push obaveštenja koristeći APNs**
- Po prijemu, obrađuje ih **`mdmclient`**
- Da bi proverio MDM komande, zahtev se šalje na ServerURL
- Koristi prethodno instalirani MDM teret:
- **`ServerURLPinningCertificateUUIDs`** za pinovanje zahteva
- **`IdentityCertificateUUID`** za TLS sertifikat klijenta

## Napadi

### Registracija uređaja u drugim organizacijama

Kao što je ranije komentarisano, da bi pokušali da registruju uređaj u organizaciji **potreban je samo Serijski broj koji pripada toj organizaciji**. Kada se uređaj registruje, nekoliko organizacija će instalirati osetljive podatke na novi uređaj: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Stoga, ovo bi moglo biti opasno mesto za napadače ako proces registracije nije pravilno zaštićen:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
