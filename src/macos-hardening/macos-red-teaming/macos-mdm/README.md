# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Da biste saznali više o macOS MDM-ovima, pogledajte:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Osnove

### **Pregled MDM-a (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) koristi se za nadzor različitih uređaja krajnjih korisnika, kao što su pametni telefoni, laptopovi i tableti. Posebno za Apple platforme (iOS, macOS, tvOS), obuhvata skup specijalizovanih funkcija, API-ja i praksi. Rad MDM-a zavisi od kompatibilnog MDM servera, koji može biti komercijalno dostupan ili open-source, i mora podržavati [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Ključne tačke obuhvataju:

- Centralizovanu kontrolu nad uređajima.
- Zavisnost od MDM servera koji poštuje MDM protokol.
- Mogućnost MDM servera da uređajima šalje različite komande, kao što su daljinsko brisanje podataka ili instalacija konfiguracije.

### **Osnove DEP-a (Device Enrollment Program)**

[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), koji nudi Apple, pojednostavljuje integraciju Mobile Device Management-a (MDM) omogućavanjem konfiguracije bez intervencije korisnika za iOS, macOS i tvOS uređaje. DEP automatizuje proces registracije, omogućavajući da uređaji budu spremni za rad odmah nakon vađenja iz kutije, uz minimalnu intervenciju korisnika ili administratora. Osnovni aspekti obuhvataju:

- Omogućava uređajima da se automatski registruju na unapred definisanom MDM serveru pri prvom aktiviranju.
- Prvenstveno je koristan za potpuno nove uređaje, ali se može primeniti i na uređaje koji prolaze kroz rekonfiguraciju.
- Omogućava jednostavno podešavanje, tako da uređaji brzo budu spremni za organizacionu upotrebu.

### **Bezbednosna razmatranja**

Važno je napomenuti da jednostavnost registracije koju DEP omogućava, iako korisna, može predstavljati i bezbednosni rizik. Ako zaštitne mere nisu adekvatno primenjene za MDM registraciju, napadači bi mogli da iskoriste ovaj pojednostavljeni proces da registruju svoj uređaj na MDM serveru organizacije, predstavljajući ga kao korporativni uređaj.<sup>[2]</sup>

> [!CAUTION]
> **Bezbednosno upozorenje**: Pojednostavljena DEP registracija potencijalno može omogućiti neovlašćenu registraciju uređaja na MDM serveru organizacije ako odgovarajuće zaštitne mere nisu primenjene.

### Osnove: Šta je SCEP (Simple Certificate Enrolment Protocol)?

- Relativno star protokol, kreiran pre nego što su TLS i HTTPS postali široko rasprostranjeni.
- Klijentima pruža standardizovan način slanja **Certificate Signing Request** (CSR) zahteva radi dobijanja sertifikata. Klijent traži od servera da mu izda potpisani sertifikat.

### Šta su Configuration Profiles (poznati i kao mobileconfigs)?

- Apple-ov zvanični način za **podešavanje i nametanje konfiguracije sistema.**
- Format datoteke koji može sadržati više payload-a.
- Zasnovan na property listama (XML formatu).
- „mogu biti potpisani i šifrovani radi potvrde njihovog porekla, obezbeđivanja integriteta i zaštite sadržaja.“ Basics — Page 70, iOS Security Guide, January 2018.

## Protokoli

### MDM

- Kombinacija APNs-a (**Apple server**i) + RESTful API-ja (**MDM** **vendor** serveri)
- **Komunikacija** se odvija između **uređaja** i servera povezanog sa **proizvodom** za **upravljanje** **uređajima**
- **Komande** se sa MDM-a uređaju isporučuju u obliku **plist-enkodiranih rečnika**
- Sve se odvija preko **HTTPS-a**. MDM serveri mogu koristiti pinning (i obično ga koriste).
- Apple MDM vendor-u dodeljuje **APNs sertifikat** za autentifikaciju

### DEP

- **3 API-ja**: 1 za prodavce, 1 za MDM vendore, 1 za identitet uređaja (nedokumentovan):
- Takozvani [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM serveri ga koriste za povezivanje DEP profila sa konkretnim uređajima.
- [DEP API koji koriste Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) za registraciju uređaja, proveru statusa registracije i proveru statusa transakcije.
- Nedokumentovani privatni DEP API. Apple Devices ga koriste za zahtev za svoj DEP profil. Na macOS-u je binarna datoteka `cloudconfigurationd` odgovorna za komunikaciju preko ovog API-ja.
- Moderniji i zasnovan na **JSON-u** (za razliku od plist-a)
- Apple MDM vendor-u dodeljuje **OAuth token**

**DEP "cloud service" API**

- RESTful
- sinhronizuje zapise uređaja sa Apple-a na MDM server
- sinhronizuje „DEP profile“ sa MDM servera ka Apple-u (Apple ih kasnije isporučuje uređaju)
- DEP „profil“ sadrži:
- URL MDM vendor servera
- Dodatne pouzdane sertifikate za URL servera (opcionalni pinning)
- Dodatna podešavanja (npr. koje ekrane treba preskočiti u Setup Assistant-u)

## Serijski broj

Apple uređaji proizvedeni nakon 2010. godine uglavnom imaju **alfanumeričke serijske brojeve od 12 karaktera**, pri čemu prve tri cifre predstavljaju mesto proizvodnje, sledeće **dve** označavaju **godinu** i **nedelju** proizvodnje, naredne **tri** cifre daju **jedinstveni** **identifikator**, a poslednje **četiri** cifre predstavljaju **broj modela**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Koraci za registraciju i upravljanje

1. Kreiranje zapisa uređaja (prodavac, Apple): Kreira se zapis za novi uređaj
2. Dodela zapisa uređaja (korisnik): Uređaj se dodeljuje MDM serveru
3. Sinhronizacija zapisa uređaja (MDM vendor): MDM sinhronizuje zapise uređaja i šalje DEP profile Apple-u
4. DEP check-in (uređaj): Uređaj dobija svoj DEP profil
5. Preuzimanje profila (uređaj)
6. Instalacija profila (uređaj) a. uključujući MDM, SCEP i root CA payload-e
7. Izdavanje MDM komandi (uređaj)

![Serijski broj - Koraci za registraciju i upravljanje: 7. Izdavanje MDM komandi (uređaj)](<../../../images/image (694).png>)

Datoteka `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` izvozi funkcije koje se mogu smatrati **„koracima“ visokog nivoa** procesa registracije.

### Korak 4: DEP check-in - Dobavljanje Activation Record-a

Ovaj deo procesa odvija se kada **korisnik prvi put pokrene Mac** (ili nakon potpunog brisanja)

![Koraci za registraciju i upravljanje - Korak 4: DEP check-in - Dobavljanje Activation Record-a: Ovaj deo procesa odvija se kada korisnik prvi put pokrene Mac (ili nakon potpunog...](<../../../images/image (1044).png>)

ili pri izvršavanju komande `sudo profiles show -type enrollment`

- Utvrđuje **da li je uređaj omogućen za DEP**
- Activation Record je interni naziv za **DEP „profil“**
- Započinje čim se uređaj poveže na Internet
- Pokreće ga **`CPFetchActivationRecord`**
- Implementira ga **`cloudconfigurationd`** preko XPC-a. **„Setup Assistant**“ (kada se uređaj prvi put pokrene) ili komanda **`profiles`** kontaktira ovaj daemon radi preuzimanja activation record-a.
- LaunchDaemon (uvek radi kao root)

Za dobijanje Activation Record-a izvršava se nekoliko koraka koje obavlja **`MCTeslaConfigurationFetcher`**. Ovaj proces koristi šifrovanje pod nazivom **Absinthe**<sup>[1]</sup>

1. Preuzimanje **sertifikata**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicijalizacija** stanja iz sertifikata (**`NACInit`**)
1. Koristi različite podatke specifične za uređaj (tj. **serijski broj preko `IOKit`-a**)
3. Preuzimanje **session key-a**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Uspostavljanje sesije (**`NACKeyEstablishment`**)
5. Slanje zahteva
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile), uz slanje podataka `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON payload se šifruje pomoću Absinthe-a (**`NACSign`**)
3. Svi zahtevi se šalju preko HTTPs-a, koriste se ugrađeni root sertifikati

![Koraci za registraciju i upravljanje - Korak 4: DEP check-in - Dobavljanje Activation Record-a: 3. Svi zahtevi se šalju preko HTTPs-a, koriste se ugrađeni root sertifikati](<../../../images/image (566) (1).png>)

Odgovor je JSON rečnik sa važnim podacima kao što su:

- **url**: URL hosta MDM vendor-a za activation profil
- **anchor-certs**: Niz DER sertifikata koji se koriste kao pouzdani anchor-i

### **Korak 5: Preuzimanje profila**

![Korak 4: DEP check-in - Dobavljanje Activation Record-a - Korak 5: Preuzimanje profila: Korak 5: Preuzimanje profila](<../../../images/image (444).png>)

- Zahtev se šalje na **url naveden u DEP profilu**.
- **Anchor sertifikati** se koriste za **proveru poverenja** ako su navedeni.
- Podsetnik: svojstvo **anchor_certs** DEP profila
- **Zahtev je jednostavan .plist** sa identifikacijom uređaja
- Primeri: **UDID, verzija OS-a**.
- CMS-potpisan, DER-enkodiran
- Potpisan pomoću **sertifikata identiteta uređaja (iz APNS-a)**
- **Lanac sertifikata** uključuje istekli **Apple iPhone Device CA**

![Korak 4: DEP check-in - Dobavljanje Activation Record-a - Korak 5: Preuzimanje profila: Potpisan pomoću sertifikata identiteta uređaja (iz APNS-a)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Korak 6: Instalacija profila

- Nakon preuzimanja, **profil se čuva na sistemu**
- Ovaj korak počinje automatski (ako je aktivan **Setup Assistant**)
- Pokreće ga **`CPInstallActivationProfile`**
- Implementira ga mdmclient preko XPC-a
- LaunchDaemon (kao root) ili LaunchAgent (kao korisnik), u zavisnosti od konteksta
- Configuration profiles imaju više payload-a za instalaciju
- Framework koristi arhitekturu zasnovanu na plugin-ovima za instalaciju profila
- Svaki tip payload-a povezan je sa plugin-om
- Može biti XPC (u framework-u) ili klasični Cocoa (u ManagedClient.app)
- Primer:
- Certificate Payloads koriste CertificateService.xpc

Activation profil koji obezbeđuje MDM vendor obično će **sadržati sledeće payload-e**:

- `com.apple.mdm`: za **registraciju** uređaja u MDM
- `com.apple.security.scep`: za bezbednu isporuku **klijentskog sertifikata** uređaju.
- `com.apple.security.pem`: za **instalaciju pouzdanih CA sertifikata** u System Keychain uređaja.
- Instaliranje MDM payload-a ekvivalentno je **MDM check-in-u u dokumentaciji**
- Payload **sadrži ključna svojstva**:
- - MDM Check-In URL (**`CheckInURL`**)
- URL za polling MDM komandi (**`ServerURL`**) + APNs topic za njegovo pokretanje
- Za instalaciju MDM payload-a zahtev se šalje na **`CheckInURL`**
- Implementira se u **`mdmclient`**
- MDM payload može zavisiti od drugih payload-a
- Omogućava **pinning zahteva na konkretne sertifikate**:
- Svojstvo: **`CheckInURLPinningCertificateUUIDs`**
- Svojstvo: **`ServerURLPinningCertificateUUIDs`**
- Isporučuje se putem PEM payload-a
- Omogućava dodelu sertifikata identiteta uređaju:
- Svojstvo: IdentityCertificateUUID
- Isporučuje se putem SCEP payload-a

### **Korak 7: Osluškivanje MDM komandi**

- Nakon završetka MDM check-in-a, vendor može **slati push notifikacije koristeći APNs**
- Po prijemu ih obrađuje **`mdmclient`**
- Radi preuzimanja MDM komandi, zahtev se šalje na ServerURL
- Koristi prethodno instalirani MDM payload:
- **`ServerURLPinningCertificateUUIDs`** za pinning zahteva
- **`IdentityCertificateUUID`** za TLS klijentski sertifikat

## Napadi

### Registracija uređaja u drugim organizacijama

Kao što je prethodno navedeno, za pokušaj registracije uređaja u organizaciji potreban je **samo serijski broj koji pripada toj organizaciji**. Kada se uređaj registruje, više organizacija će na novi uređaj instalirati osetljive podatke: sertifikate, aplikacije, WiFi lozinke, VPN konfiguracije [i tako dalje](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Zbog toga ovo može biti opasna ulazna tačka za napadače ako proces registracije nije pravilno zaštićen:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Reference

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
