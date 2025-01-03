# Sertifikati

{{#include ../banners/hacktricks-training.md}}

## Šta je Sertifikat

**Javni ključ sertifikat** je digitalni ID koji se koristi u kriptografiji da dokaže da neko poseduje javni ključ. Uključuje detalje o ključevi, identitet vlasnika (subjekt) i digitalni potpis od poverene vlasti (izdavača). Ako softver veruje izdavaču i potpis je validan, sigurna komunikacija sa vlasnikom ključa je moguća.

Sertifikati se uglavnom izdaju od strane [sertifikacionih tela](https://en.wikipedia.org/wiki/Certificate_authority) (CA) u [infrastrukturi javnog ključa](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) postavci. Druga metoda je [mreža poverenja](https://en.wikipedia.org/wiki/Web_of_trust), gde korisnici direktno verifikuju ključeve jedni drugih. Uobičajeni format za sertifikate je [X.509](https://en.wikipedia.org/wiki/X.509), koji se može prilagoditi specifičnim potrebama kako je navedeno u RFC 5280.

## x509 Uobičajena Polja

### **Uobičajena Polja u x509 Sertifikatima**

U x509 sertifikatima, nekoliko **polja** igra ključne uloge u obezbeđivanju validnosti i sigurnosti sertifikata. Evo pregleda ovih polja:

- **Broj Verzije** označava verziju x509 formata.
- **Serijski Broj** jedinstveno identifikuje sertifikat unutar sistema Sertifikacione Vlasti (CA), uglavnom za praćenje opoziva.
- **Subjekt** polje predstavlja vlasnika sertifikata, što može biti mašina, pojedinac ili organizacija. Uključuje detaljnu identifikaciju kao što su:
- **Uobičajeno Ime (CN)**: Domeni pokriveni sertifikatom.
- **Zemlja (C)**, **Lokacija (L)**, **Država ili Pokrajina (ST, S, ili P)**, **Organizacija (O)**, i **Organizaciona Jedinica (OU)** pružaju geografske i organizacione detalje.
- **Istaknuto Ime (DN)** obuhvata punu identifikaciju subjekta.
- **Izdavač** detaljno opisuje ko je verifikovao i potpisao sertifikat, uključujući slična podpolja kao Subjekt za CA.
- **Period Validnosti** označen je **Ne Pre** i **Ne Posle** vremenskim oznakama, osiguravajući da sertifikat nije korišćen pre ili posle određenog datuma.
- **Javni Ključ** sekcija, ključna za sigurnost sertifikata, specificira algoritam, veličinu i druge tehničke detalje javnog ključa.
- **x509v3 ekstenzije** poboljšavaju funkcionalnost sertifikata, specificirajući **Korišćenje Ključa**, **Prošireno Korišćenje Ključa**, **Alternativno Ime Subjekta**, i druge osobine za fino podešavanje primene sertifikata.

#### **Korišćenje Ključa i Ekstenzije**

- **Korišćenje Ključa** identifikuje kriptografske primene javnog ključa, kao što su digitalni potpis ili enkripcija ključa.
- **Prošireno Korišćenje Ključa** dodatno sužava slučajeve korišćenja sertifikata, npr. za TLS autentifikaciju servera.
- **Alternativno Ime Subjekta** i **Osnovna Ograničenja** definišu dodatne nazive hostova pokrivene sertifikatom i da li je to CA ili sertifikat krajnjeg entiteta, respektivno.
- Identifikatori kao što su **Identifikator Ključa Subjekta** i **Identifikator Ključa Vlasti** osiguravaju jedinstvenost i praćenje ključeva.
- **Pristup Informacijama o Vlasti** i **Tačke Distribucije CRL** pružaju puteve za verifikaciju izdavača CA i proveru statusa opoziva sertifikata.
- **CT Precertifikat SCTs** nude transparente dnevnike, što je ključno za javno poverenje u sertifikat.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Razlika između OCSP i CRL distribucionih tačaka**

**OCSP** (**RFC 2560**) uključuje klijenta i odgovarača koji rade zajedno kako bi proverili da li je digitalni javni ključ sertifikat opozvan, bez potrebe za preuzimanjem celog **CRL**. Ova metoda je efikasnija od tradicionalnog **CRL**, koji pruža listu opozvanih serijskih brojeva sertifikata, ali zahteva preuzimanje potencijalno velikog fajla. CRL može sadržati do 512 unosa. Više detalja je dostupno [ovde](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Šta je transparentnost sertifikata**

Transparentnost sertifikata pomaže u borbi protiv pretnji vezanih za sertifikate osiguravajući da je izdavanje i postojanje SSL sertifikata vidljivo vlasnicima domena, CA i korisnicima. Njeni ciljevi su:

- Sprečavanje CA da izdaju SSL sertifikate za domen bez znanja vlasnika domena.
- Uspostavljanje otvorenog sistema revizije za praćenje greškom ili zlonamerno izdatih sertifikata.
- Zaštita korisnika od prevarantskih sertifikata.

#### **Sertifikati logovi**

Sertifikati logovi su javno revizibilni, samo za dodavanje zapisi sertifikata, koje održavaju mrežne usluge. Ovi logovi pružaju kriptografske dokaze za revizijske svrhe. Izdavaoci i javnost mogu podnositi sertifikate ovim logovima ili ih pretraživati radi verifikacije. Dok tačan broj log servera nije fiksiran, očekuje se da će biti manje od hiljadu globalno. Ove servere mogu nezavisno upravljati CA, ISP ili bilo koja zainteresovana strana.

#### **Upit**

Da biste istražili logove transparentnosti sertifikata za bilo koji domen, posetite [https://crt.sh/](https://crt.sh).

Postoje različiti formati za skladištenje sertifikata, svaki sa svojim slučajevima upotrebe i kompatibilnošću. Ovaj pregled pokriva glavne formate i pruža smernice za konvertovanje između njih.

## **Formati**

### **PEM format**

- Najšire korišćen format za sertifikate.
- Zahteva odvojene fajlove za sertifikate i privatne ključeve, kodirane u Base64 ASCII.
- Uobičajene ekstenzije: .cer, .crt, .pem, .key.
- Primarno koriste Apache i slični serveri.

### **DER format**

- Binarni format sertifikata.
- Nedostaju "BEGIN/END CERTIFICATE" izjave koje se nalaze u PEM fajlovima.
- Uobičajene ekstenzije: .cer, .der.
- Često se koristi sa Java platformama.

### **P7B/PKCS#7 format**

- Skladišti se u Base64 ASCII, sa ekstenzijama .p7b ili .p7c.
- Sadrži samo sertifikate i lance sertifikata, isključujući privatni ključ.
- Podržava Microsoft Windows i Java Tomcat.

### **PFX/P12/PKCS#12 format**

- Binarni format koji enkapsulira server sertifikate, međusertifikate i privatne ključeve u jednom fajlu.
- Ekstenzije: .pfx, .p12.
- Uglavnom se koristi na Windows-u za uvoz i izvoz sertifikata.

### **Konvertovanje formata**

**PEM konverzije** su neophodne za kompatibilnost:

- **x509 to PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM u DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER u PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM u P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 u PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX konverzije** su ključne za upravljanje sertifikatima na Windows-u:

- **PFX u PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX to PKCS#8** uključuje dva koraka:
1. Konvertujte PFX u PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konvertujte PEM u PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B to PFX** takođe zahteva dve komande:
1. Konvertujte P7B u CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertujte CER i privatni ključ u PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
--- 

{{#include ../banners/hacktricks-training.md}}
