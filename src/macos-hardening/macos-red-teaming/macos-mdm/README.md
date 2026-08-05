# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Da biste saznali više o macOS MDM sistemima, pogledajte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Osnove

### **Pregled MDM-a (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) se koristi za nadgledanje različitih uređaja krajnjih korisnika, kao što su pametni telefoni, laptopovi i tableti. Konkretno, za Apple platforme (iOS, macOS, tvOS), obuhvata skup specijalizovanih funkcija, API-ja i praksi. Rad MDM-a zavisi od kompatibilnog MDM servera, koji je komercijalno dostupan ili open-source i mora da podržava [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ključne tačke su:

- Centralizovana kontrola nad uređajima.
- Zavisnost od MDM servera koji se pridržava MDM protokola.
- Mogućnost MDM servera da šalje različite komande uređajima, na primer za udaljeno brisanje podataka ili instalaciju konfiguracije.

### **Osnove DEP-a (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), koji nudi Apple, pojednostavljuje integraciju Mobile Device Management-a (MDM) tako što omogućava zero-touch konfiguraciju iOS, macOS i tvOS uređaja. DEP automatizuje proces enrolmenta, omogućavajući da uređaji budu operativni odmah nakon vađenja iz kutije, uz minimalnu intervenciju korisnika ili administratora. Osnovni aspekti uključuju:

- Omogućava uređajima da se automatski registruju na unapred definisanom MDM serveru prilikom prve aktivacije.
- Prvenstveno je koristan za potpuno nove uređaje, ali se može primeniti i na uređaje koji se rekonfigurišu.
- Omogućava jednostavno podešavanje, tako da uređaji brzo budu spremni za organizacionu upotrebu.

### **Bezbednosna razmatranja**

Važno je napomenuti da jednostavnost enrolmenta koju DEP pruža, iako korisna, može predstavljati i bezbednosni rizik. Ako zaštitne mere nisu adekvatno sprovedene za MDM enrolment, napadači bi mogli da iskoriste ovaj pojednostavljeni proces da registruju svoj uređaj na MDM serveru organizacije, predstavljajući ga kao korporativni uređaj.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Bezbednosno upozorenje**: Pojednostavljeni DEP enrolment potencijalno može omogućiti neovlašćenu registraciju uređaja na MDM serveru organizacije ako nisu uvedene odgovarajuće zaštitne mere.

### Osnove: Šta je SCEP (Simple Certificate Enrolment Protocol)?

- Relativno star protokol, kreiran pre nego što su TLS i HTTPS postali široko rasprostranjeni.
- Klijentima pruža standardizovan način slanja **Certificate Signing Request** (CSR) zahteva u svrhu dobijanja sertifikata. Klijent traži od servera da mu izda potpisani sertifikat.

### Šta su Configuration Profiles (poznati i kao mobileconfigs)?

- Apple-ov zvanični način za **podešavanje/sprovođenje sistemske konfiguracije.**
- Format datoteke koji može sadržati više payload-a.
- Zasnovan na property listama (XML formatu).
- „can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.“ Basics — Page 70, iOS Security Guide, January 2018.

## Protokoli

### MDM

- Kombinacija APNs-a (**Apple server**i) + RESTful API-ja (**MDM** **vendor** serveri)
- **Komunikacija** se odvija između **uređaja** i servera povezanog sa **proizvodom za** **upravljanje** **uređajima**
- **Komande** se sa MDM-a uređaju dostavljaju u **plist-enkodovanim rečnicima**
- Sve se odvija preko **HTTPS-a**. MDM serveri mogu imati (i obično imaju) pinning.
- Apple MDM vendoru dodeljuje **APNs sertifikat** za autentifikaciju

### DEP

- **3 API-ja**: 1 za preprodavce, 1 za MDM vendore, 1 za identitet uređaja (nedokumentovan):
- Takozvani [DEP „cloud service“ API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM serveri ga koriste za povezivanje DEP profila sa konkretnim uređajima.
- [DEP API koji koriste Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) za enrolment uređaja, proveru statusa enrolmenta i proveru statusa transakcije.
- Nedokumentovani privatni DEP API. Apple uređaji ga koriste za zahtevanje svog DEP profila. Na macOS-u je binarni fajl `cloudconfigurationd` odgovoran za komunikaciju preko ovog API-ja.
- Moderniji i zasnovan na **JSON-u** (nasuprot **plist-u**)
- Apple MDM vendoru dodeljuje **OAuth token**

**DEP „cloud service“ API**

- RESTful
- sinhronizuje zapise uređaja sa Apple-a na MDM server
- sinhronizuje „DEP profile“ sa MDM servera ka Apple-u (Apple ih kasnije dostavlja uređaju)
- DEP „profil“ sadrži:
- URL MDM vendor servera
- Dodatne pouzdane sertifikate za URL servera (opcionalni pinning)
- Dodatna podešavanja (npr. koje ekrane treba preskočiti u Setup Assistant-u)

## Serijski broj

Apple uređaji proizvedeni nakon 2010. godine uglavnom imaju **12-cifrene alfanumeričke** serijske brojeve, pri čemu prve **tri cifre predstavljaju lokaciju proizvodnje**, sledeće **dve** označavaju **godinu** i **nedelju** proizvodnje, naredne **tri** cifre daju **jedinstveni** **identifikator**, a poslednje **četiri** cifre predstavljaju **broj modela**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Koraci enrolmenta i upravljanja

1. Kreiranje zapisa uređaja (Reseller, Apple): Kreira se zapis za novi uređaj
2. Dodela zapisa uređaja (Customer): Uređaj se dodeljuje MDM serveru
3. Sinhronizacija zapisa uređaja (MDM vendor): MDM sinhronizuje zapise uređaja i prosleđuje DEP profile Apple-u
4. DEP check-in (Device): Uređaj preuzima svoj DEP profil
5. Preuzimanje profila (Device)
6. Instalacija profila (Device), uključujući MDM, SCEP i root CA payload-e
7. Izdavanje MDM komandi (Device)

![Serijski broj - Koraci enrolmenta i upravljanja: 7. Izdavanje MDM komandi (Device)](<../../../images/image (694).png>)

Datoteka `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` izlaže funkcije koje se mogu smatrati **visokonivojskim „koracima“** procesa enrolmenta.

### Korak 4: DEP check-in - Preuzimanje Activation Record-a

Ovaj deo procesa se odvija kada **korisnik prvi put pokrene Mac** (ili nakon potpunog brisanja uređaja)

![Koraci enrolmenta i upravljanja - Korak 4: DEP check-in - Preuzimanje Activation Record-a: Ovaj deo procesa se odvija kada korisnik prvi put pokrene Mac (ili nakon potpunog...](<../../../images/image (1044).png>)

ili kada se izvrši `sudo profiles show -type enrollment`

- Utvrđuje **da li je uređaj omogućen za DEP**
- Activation Record je interni naziv za **DEP „profil“**
- Počinje čim se uređaj poveže na Internet
- Pokreće ga **`CPFetchActivationRecord`**
- Implementira ga **`cloudconfigurationd`** preko XPC-a. **„Setup Assistant“** (kada se uređaj prvi put pokrene) ili komanda **`profiles`** kontaktira ovaj daemon radi preuzimanja activation record-a.
- LaunchDaemon (uvek se izvršava kao root)

Za preuzimanje Activation Record-a, komponenta **`MCTeslaConfigurationFetcher`** izvršava nekoliko koraka. Ovaj proces koristi enkripciju pod nazivom **Absinthe**<sup>[[1]](#references)</sup>

1. Preuzimanje **sertifikata**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicijalizacija** stanja iz sertifikata (**`NACInit`**)
1. Koriste se različiti podaci specifični za uređaj (npr. **serijski broj preko `IOKit`-a**)
3. Preuzimanje **session key-a**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Uspostavljanje sesije (**`NACKeyEstablishment`**)
5. Slanje zahteva
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), uz slanje podataka `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload je šifrovan pomoću Absinthe-a (**`NACSign`**)
3. Svi zahtevi se šalju preko HTTPS-a, koriste se ugrađeni root sertifikati

![Koraci enrolmenta i upravljanja - Korak 4: DEP check-in - Preuzimanje Activation Record-a: 3. Svi zahtevi se šalju preko HTTPS-a, koriste se ugrađeni root sertifikati](<../../../images/image (566) (1).png>)

Odgovor je JSON rečnik sa važnim podacima, kao što su:

- **url**: URL hosta MDM vendora za activation profil
- **anchor-certs**: Niz DER sertifikata koji se koriste kao pouzdani trust anchor-i

### **Korak 5: Preuzimanje profila**

![Korak 4: DEP check-in - Preuzimanje Activation Record-a - Korak 5: Preuzimanje profila: Korak 5: Preuzimanje profila](<../../../images/image (444).png>)

- Zahtev se šalje na **url naveden u DEP profilu**.
- **Anchor sertifikati** se koriste za **proveru poverenja** ako su navedeni.
- Podsetnik: svojstvo **anchor_certs** DEP profila
- **Zahtev je jednostavan .plist** sa identifikacijom uređaja
- Primeri: **UDID, verzija OS-a**.
- CMS-potpisan, DER-enkodovan
- Potpisan pomoću **sertifikata identiteta uređaja (iz APNS-a)**
- **Lanac sertifikata** uključuje istekao **Apple iPhone Device CA**

![Korak 4: DEP check-in - Preuzimanje Activation Record-a - Korak 5: Preuzimanje profila: Potpisan pomoću sertifikata identiteta uređaja (iz APNS-a)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Korak 6: Instalacija profila

- Nakon preuzimanja, **profil se čuva na sistemu**
- Ovaj korak počinje automatski (ako se nalazi u **setup assistant-u**)
- Pokreće ga **`CPInstallActivationProfile`**
- Implementira ga mdmclient preko XPC-a
- LaunchDaemon (kao root) ili LaunchAgent (kao korisnik), u zavisnosti od konteksta
- Configuration profiles imaju više payload-a za instalaciju
- Framework ima plugin-based arhitekturu za instalaciju profila
- Svaki tip payload-a povezan je sa plugin-om
- Može biti XPC (u framework-u) ili klasični Cocoa (u ManagedClient.app)
- Primer:
- Certificate Payloads koriste CertificateService.xpc

Activation profile koji pruža MDM vendor obično će sadržati sledeće payload-e:

- `com.apple.mdm`: za **enrolment** uređaja u MDM
- `com.apple.security.scep`: za bezbedno dostavljanje **client sertifikata** uređaju.
- `com.apple.security.pem`: za **instalaciju pouzdanih CA sertifikata** u System Keychain uređaja.
- Instaliranje MDM payload-a ekvivalentno je **MDM check-in-u u dokumentaciji**
- Payload **sadrži ključna svojstva**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic za njegovo pokretanje
- Za instalaciju MDM payload-a, zahtev se šalje na **`CheckInURL`**
- Implementira ga **`mdmclient`**
- MDM payload može zavisiti od drugih payload-a
- Omogućava **pinning zahteva na određene sertifikate**:
- Svojstvo: **`CheckInURLPinningCertificateUUIDs`**
- Svojstvo: **`ServerURLPinningCertificateUUIDs`**
- Dostavlja se putem PEM payload-a
- Omogućava dodeljivanje identitetskog sertifikata uređaju:
- Svojstvo: IdentityCertificateUUID
- Dostavlja se putem SCEP payload-a

### **Korak 7: Ošluškivanje MDM komandi**

- Nakon završetka MDM check-in-a, vendor može **slati push notifikacije pomoću APNs-a**
- Po prijemu ih obrađuje **`mdmclient`**
- Za preuzimanje MDM komandi, zahtev se šalje na ServerURL
- Koristi prethodno instalirani MDM payload:
- **`ServerURLPinningCertificateUUIDs`** za pinning zahteva
- **`IdentityCertificateUUID`** za TLS client sertifikat

## Napadi

### Enrolment uređaja u druge organizacije

Kao što je prethodno navedeno, za pokušaj enrolmenta uređaja u organizaciju **potreban je samo serijski broj koji pripada toj organizaciji**. Kada se uređaj enroluje, nekoliko organizacija će na novi uređaj instalirati osetljive podatke: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Zbog toga ovo može biti opasna ulazna tačka za napadače ako proces enrolmenta nije pravilno zaštićen:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Reference

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
