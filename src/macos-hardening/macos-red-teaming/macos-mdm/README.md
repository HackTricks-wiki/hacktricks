# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Da biste saznali više o macOS MDM-ovima, pogledajte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Osnove

### **Pregled MDM-a (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) se koristi za upravljanje različitim uređajima krajnjih korisnika, poput pametnih telefona, laptopova i tableta. Posebno za Apple platforme (iOS, macOS, tvOS), obuhvata skup specijalizovanih funkcija, API-ja i praksi. MDM zavisi od kompatibilnog MDM servera, koji može biti komercijalno dostupan ili otvorenog koda i mora podržavati [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ključne stavke uključuju:

- Centralizovanu kontrolu nad uređajima.
- Zavisnost od MDM servera koji poštuje MDM protokol.
- MDM server može da šalje različite komande uređajima, na primer, za daljinsko brisanje podataka ili instaliranje konfiguracije.

### **Osnove DEP-a (Device Enrollment Program)**

Apple-ov [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) pojednostavljuje integraciju Mobile Device Management-a (MDM) tako što omogućava automatsku konfiguraciju iOS, macOS i tvOS uređaja bez dodira. DEP automatizuje postupak upisa, čime uređaji postaju spremni za rad odmah po vađenju iz kutije, uz minimalno učešće korisnika ili administratora. Ključni aspekti uključuju:

- Omogućava uređajima da se sami registruju na unapred definisanom MDM serveru prilikom prvog aktiviranja.
- Pre svega je koristan za potpuno nove uređaje, ali se može koristiti i za uređaje koji se ponovo konfigurišu.
- Omogućava jednostavno podešavanje, tako da uređaji brzo budu spremni za organizacionu upotrebu.

### **Bezbednosna razmatranja**

Važno je napomenuti da jednostavnost upisa koju DEP pruža može predstavljati i bezbednosni rizik. Ako bezbednosne mere za MDM upis nisu adekvatno sprovedene, napadači bi mogli da iskoriste ovaj pojednostavljeni postupak i registruju svoj uređaj na MDM serveru organizacije, predstavljajući ga kao korporativni uređaj.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Bezbednosno upozorenje**: Pojednostavljeni DEP upis potencijalno može omogućiti neovlašćenu registraciju uređaja na MDM serveru organizacije ako nisu uspostavljene odgovarajuće zaštitne mere.

### Osnove: Šta je SCEP (Simple Certificate Enrolment Protocol)?

- Relativno star protokol, nastao pre nego što su TLS i HTTPS postali široko rasprostranjeni.
- Klijentima pruža standardizovan način slanja **zahteva za potpisivanje sertifikata** (CSR) kako bi dobili sertifikat. Klijent traži od servera da mu izda potpisani sertifikat.

### Šta su Configuration Profiles (poznati i kao mobileconfigs)?

- Apple-ov zvanični način za **podešavanje/sprovođenje sistemske konfiguracije.**
- Format datoteke koji može sadržati više korisnih sadržaja.
- Zasnovani na property list-ovima (XML formatu).
- „mogu biti potpisani i šifrovani da bi se potvrdilo njihovo poreklo, obezbedio njihov integritet i zaštitio njihov sadržaj.“ Basics — strana 70, iOS Security Guide, januar 2018.

## Protokoli

### MDM

- Kombinacija APNs-a (**Apple serveri**) + RESTful API-ja (**MDM** **serveri dobavljača**)
- **Komunikacija** se odvija između **uređaja** i servera povezanog sa proizvodom za **upravljanje** **uređajima**
- **Komande** se isporučuju sa MDM-a uređaju u obliku **rečnika kodiranih u plist**
- Sve se odvija preko **HTTPS-a**. MDM serveri mogu da koriste pinning (i obično ga koriste).
- Apple dodeljuje MDM dobavljaču **APNs sertifikat** za autentifikaciju

### DEP

- **3 API-ja**: 1 za preprodavce, 1 za MDM dobavljače, 1 za identitet uređaja (nedokumentovan):
  - Takozvani [DEP „cloud service“ API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM serveri ga koriste za povezivanje DEP profila sa određenim uređajima.
  - [DEP API koji koriste Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) za upis uređaja, proveru statusa upisa i proveru statusa transakcije.
  - Nedokumentovani privatni DEP API. Apple uređaji ga koriste za preuzimanje svog DEP profila. Na macOS-u, binarna datoteka `cloudconfigurationd` zadužena je za komunikaciju preko ovog API-ja.
- Savremeniji i zasnovan na **JSON-u** (za razliku od plist-a)
- Apple dodeljuje MDM dobavljaču **OAuth token**

**DEP „cloud service“ API**

- RESTful
- sinhronizuje zapise o uređajima sa Apple-a na MDM server
- sinhronizuje „DEP profile“ sa MDM servera na Apple (Apple ih kasnije isporučuje uređaju)
- DEP „profil“ sadrži:
  - URL MDM servera dobavljača
  - Dodatne pouzdane sertifikate za URL servera (opcionalni pinning)
  - Dodatna podešavanja (npr. koje ekrane preskočiti u Setup Assistant-u)

## Serijski broj

Apple uređaji proizvedeni posle 2010. uglavnom imaju **12-znakovne alfanumeričke** serijske brojeve. **Prve tri cifre predstavljaju lokaciju proizvodnje**, naredne **dve** označavaju **godinu** i **nedelju** proizvodnje, sledeće **tri** cifre predstavljaju **jedinstveni** **identifikator**, a **poslednje** **četiri** cifre predstavljaju **broj modela**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Koraci upisa i upravljanja

1. Kreiranje zapisa o uređaju (preprodavac, Apple): Kreira se zapis za novi uređaj
2. Dodela zapisa o uređaju (korisnik): Uređaj se dodeljuje MDM serveru
3. Sinhronizacija zapisa o uređaju (MDM dobavljač): MDM sinhronizuje zapise o uređajima i šalje DEP profile Apple-u
4. DEP check-in (uređaj): Uređaj preuzima svoj DEP profil
5. Preuzimanje profila (uređaj)
6. Instalacija profila (uređaj) a. uključujući MDM, SCEP i root CA payload-ove
7. Izdavanje MDM komandi (uređaj)

![Serijski broj - Koraci upisa i upravljanja: 7. Izdavanje MDM komandi (uređaj)](<../../../images/image (694).png>)

Datoteka `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` izvozi funkcije koje se mogu smatrati **visokonivojskim „koracima“** postupka upisa.

### Korak 4: DEP check-in - Dobavljanje Activation Record-a

Ovaj deo postupka se odvija kada **korisnik prvi put pokrene Mac** (ili nakon potpunog brisanja)

![Koraci upisa i upravljanja - Korak 4: DEP check-in - Dobavljanje Activation Record-a: Ovaj deo postupka se odvija kada korisnik prvi put pokrene Mac (ili nakon potpunog...](<../../../images/image (1044).png>)

ili kada se izvrši `sudo profiles show -type enrollment`

- Utvrđuje **da li je uređaj omogućen za DEP**
- Activation Record je interni naziv za **DEP „profil“**
- Počinje čim se uređaj poveže na Internet
- Pokreće ga **`CPFetchActivationRecord`**
- Implementira ga **`cloudconfigurationd`** preko XPC-a. **„Setup Assistant“** (prilikom prvog pokretanja uređaja) ili komanda **`profiles`** će **kontaktirati ovaj daemon** radi preuzimanja activation record-a.
  - LaunchDaemon (uvek radi kao root)

Preuzimanje Activation Record-a obavlja se kroz nekoliko koraka koje izvršava **`MCTeslaConfigurationFetcher`**. Ovaj postupak koristi šifrovanje nazvano **Absinthe**<sup>[[1]](#references)</sup>

1. Preuzimanje **sertifikata**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicijalizacija** stanja na osnovu sertifikata (**`NACInit`**)
   1. Koristi različite podatke specifične za uređaj (tj. **serijski broj preko `IOKit`**)
3. Preuzimanje **session key-a**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Uspostavljanje sesije (**`NACKeyEstablishment`**)
5. Slanje zahteva
   1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) uz slanje podataka `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. JSON payload je šifrovan pomoću Absinthe-a (**`NACSign`**)
   3. Svi zahtevi se šalju preko HTTPS-a, koriste se ugrađeni root sertifikati

![Koraci upisa i upravljanja - Korak 4: DEP check-in - Dobavljanje Activation Record-a: 3. Svi zahtevi se šalju preko HTTPS-a, koriste se ugrađeni root sertifikati](<../../../images/image (566) (1).png>)

Odgovor je JSON rečnik sa važnim podacima kao što su:

- **url**: URL hosta MDM dobavljača za activation profile
- **anchor-certs**: Niz DER sertifikata koji se koriste kao pouzdani anchor-i

### **Korak 5: Preuzimanje profila**

![Korak 4: DEP check-in - Dobavljanje Activation Record-a - Korak 5: Preuzimanje profila: Korak 5: Preuzimanje profila](<../../../images/image (444).png>)

- Zahtev se šalje na **url naveden u DEP profilu**.
- **Anchor sertifikati** se koriste za **procenu poverenja** ako su navedeni.
  - Podsetnik: svojstvo **anchor_certs** DEP profila
- **Zahtev je jednostavan .plist** sa identifikacionim podacima uređaja
  - Primeri: **UDID, verzija OS-a**.
- Potpisan pomoću CMS-a i kodiran u DER formatu
- Potpisan pomoću **sertifikata identiteta uređaja (iz APNS-a)**
- **Lanac sertifikata** obuhvata istekli **Apple iPhone Device CA**

![Korak 4: DEP check-in - Dobavljanje Activation Record-a - Korak 5: Preuzimanje profila: Potpisan pomoću sertifikata identiteta uređaja (iz APNS-a)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Korak 6: Instalacija profila

- Nakon preuzimanja, **profil se čuva u sistemu**
- Ovaj korak počinje automatski (ako se nalazite u **Setup Assistant-u**)
- Pokreće ga **`CPInstallActivationProfile`**
- Implementira ga mdmclient preko XPC-a
  - LaunchDaemon (kao root) ili LaunchAgent (kao korisnik), u zavisnosti od konteksta
- Configuration profiles sadrže više payload-ova za instalaciju
- Framework koristi arhitekturu sa plugin-ovima za instaliranje profila
- Svaki tip payload-a povezan je sa plugin-om
  - Može biti XPC (u framework-u) ili klasični Cocoa (u ManagedClient.app)
- Primer:
  - Certificate Payloads koriste CertificateService.xpc

Activation profile koji obezbeđuje MDM dobavljač obično **sadrži sledeće payload-ove**:

- `com.apple.mdm`: za **upis** uređaja u MDM
- `com.apple.security.scep`: za bezbedno obezbeđivanje **klijentskog sertifikata** uređaju.
- `com.apple.security.pem`: za **instaliranje pouzdanih CA sertifikata** u System Keychain uređaja.
- Instaliranje MDM payload-a odgovara **MDM check-in-u u dokumentaciji**
- Payload **sadrži ključna svojstva**:
- - MDM Check-In URL (**`CheckInURL`**)
  - URL za periodično preuzimanje MDM komandi (**`ServerURL`**) + APNs topic za njegovo pokretanje
- Za instaliranje MDM payload-a, zahtev se šalje na **`CheckInURL`**
- Implementira ga **`mdmclient`**
- MDM payload može zavisiti od drugih payload-ova
- Omogućava **pinning zahteva na određene sertifikate**:
  - Svojstvo: **`CheckInURLPinningCertificateUUIDs`**
  - Svojstvo: **`ServerURLPinningCertificateUUIDs`**
  - Isporučuje se preko PEM payload-a
- Omogućava pridruživanje sertifikata identiteta uređaju:
  - Svojstvo: IdentityCertificateUUID
  - Isporučuje se preko SCEP payload-a

### **Korak 7: Slušanje MDM komandi**

- Kada se MDM check-in završi, dobavljač može **slati push obaveštenja koristeći APNs**
- Po prijemu, njima upravlja **`mdmclient`**
- Za proveru MDM komandi, zahtev se šalje na ServerURL
- Koristi prethodno instalirani MDM payload:
  - **`ServerURLPinningCertificateUUIDs`** za pinning zahteva
  - **`IdentityCertificateUUID`** za TLS klijentski sertifikat

## Napadi

### Upis uređaja u druge organizacije

Dodeljeni serijski broj može da ukazuje na putanju upisa uređaja u organizaciju, ali **ne** garantuje MDM upis. Server može da zahteva autentifikaciju korisnika preko `configuration_web_url` pre nego što vrati profil za upis. Proverite da li alternativna putanja upisa izostavlja tu proveru, umesto da pretpostavite da svaki dodeljeni serijski broj omogućava pridruživanje uređaja floti.<sup>[[3]](#references)</sup>

Za postupak neovlašćenog upisa koristite stranicu na linku ispod. Za MDM kontrolu i isporuku paketa nakon kompromitovanja pogledajte [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Detaljan pregled macOS MDM-a (i kako se može kompromitovati)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — „MDM Me Maybe?“ (bezbednosno istraživanje DEP/MDM upisa)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Autentifikacija putem web prikaza](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
