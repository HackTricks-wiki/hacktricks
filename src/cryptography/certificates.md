# Sertifikate

{{#include ../banners/hacktricks-training.md}}

## Wat is 'n Sertifikaat

'n **Publieke sleutelsertifikaat** is 'n digitale ID wat in kriptografie gebruik word om te bewys dat iemand 'n publieke sleutel besit. Dit sluit die sleutel se besonderhede, die eienaar se identiteit (die onderwerp), en 'n digitale handtekening van 'n vertroude gesag (die uitgewer) in. As die sagteware die uitgewer vertrou en die handtekening geldig is, is veilige kommunikasie met die sleutel se eienaar moontlik.

Sertifikate word meestal uitgereik deur [sertifikaatowerhede](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) in 'n [publieke sleutel infrastruktuur](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) opstelling. 'n Ander metode is die [web van vertroue](https://en.wikipedia.org/wiki/Web_of_trust), waar gebruikers mekaar se sleutels direk verifieer. Die algemene formaat vir sertifikate is [X.509](https://en.wikipedia.org/wiki/X.509), wat aangepas kan word vir spesifieke behoeftes soos uiteengesit in RFC 5280.

## x509 Algemene Velde

### **Algemene Velde in x509 Sertifikate**

In x509 sertifikate speel verskeie **velde** kritieke rolle in die versekerings van die sertifikaat se geldigheid en sekuriteit. Hier is 'n uiteensetting van hierdie velde:

- **Weergawe Nommer** dui die x509 formaat se weergawe aan.
- **Serie Nommer** identifiseer die sertifikaat uniek binne 'n Sertifikaatowerheid se (CA) stelsel, hoofsaaklik vir herroepingopsporing.
- Die **Onderwerp** veld verteenwoordig die sertifikaat se eienaar, wat 'n masjien, 'n individu, of 'n organisasie kan wees. Dit sluit gedetailleerde identifikasie in soos:
- **Algemene Naam (CN)**: Domeine wat deur die sertifikaat gedek word.
- **Land (C)**, **Plaaslikeheid (L)**, **Staat of Provinsie (ST, S, of P)**, **Organisasie (O)**, en **Organisatoriese Eenheid (OU)** verskaf geografiese en organisatoriese besonderhede.
- **Gekenneteerde Naam (DN)** sluit die volle onderwerp identifikasie in.
- **Uitgewer** gee besonderhede oor wie die sertifikaat geverifieer en onderteken het, insluitend soortgelyke subvelde soos die Onderwerp vir die CA.
- **Geldigheidsperiode** word gemerk deur **Nie Voor** en **Nie Na** tydstempels, wat verseker dat die sertifikaat nie voor of na 'n sekere datum gebruik word nie.
- Die **Publieke Sleutel** afdeling, wat van kardinale belang is vir die sertifikaat se sekuriteit, spesifiseer die algoritme, grootte, en ander tegniese besonderhede van die publieke sleutel.
- **x509v3 uitbreidings** verbeter die sertifikaat se funksionaliteit, wat **Sleutel Gebruik**, **Verlengde Sleutel Gebruik**, **Onderwerp Alternatiewe Naam**, en ander eienskappe spesifiseer om die sertifikaat se toepassing te verfyn.

#### **Sleutel Gebruik en Uitbreidings**

- **Sleutel Gebruik** identifiseer kriptografiese toepassings van die publieke sleutel, soos digitale handtekening of sleutel versleuteling.
- **Verlengde Sleutel Gebruik** beperk verder die sertifikaat se gebruiksgevalle, bv. vir TLS bedienerverifikasie.
- **Onderwerp Alternatiewe Naam** en **Basiese Beperking** definieer addisionele gasheername wat deur die sertifikaat gedek word en of dit 'n CA of eindentiteit sertifikaat is, onderskeidelik.
- Identifiseerders soos **Onderwerp Sleutel Identifiseerder** en **Gesags Sleutel Identifiseerder** verseker uniekheid en opspoorbaarheid van sleutels.
- **Gesags Inligting Toegang** en **CRL Verspreidingspunte** bied paaie om die uitreikende CA te verifieer en die sertifikaat se herroepingstatus te kontroleer.
- **CT Precertificate SCTs** bied deursigtigheid logs, wat van kardinale belang is vir publieke vertroue in die sertifikaat.
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
### **Verskil tussen OCSP en CRL Verspreidingspunte**

**OCSP** (**RFC 2560**) behels 'n kliënt en 'n responder wat saamwerk om te kontroleer of 'n digitale publieke sleutelsertifikaat herroep is, sonder om die volle **CRL** af te laai. Hierdie metode is meer doeltreffend as die tradisionele **CRL**, wat 'n lys van herroepte sertifikaatserienommers verskaf, maar vereis dat 'n potensieel groot lêer afgelaai word. CRL's kan tot 512 inskrywings insluit. Meer besonderhede is beskikbaar [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Wat is Sertifikaat Deursigtigheid**

Sertifikaat Deursigtigheid help om sertifikaatverwante bedreigings te bekamp deur te verseker dat die uitreiking en bestaan van SSL-sertifikate sigbaar is vir domeineienaars, CA's en gebruikers. Die doelwitte is:

- Om te voorkom dat CA's SSL-sertifikate vir 'n domein uitreik sonder die domeineienaar se kennis.
- Om 'n oop ouditstelsel te vestig vir die opsporing van per ongeluk of kwaadwillig uitgereikte sertifikate.
- Om gebruikers te beskerm teen bedrogsertifikate.

#### **Sertifikaat Logs**

Sertifikaat logs is publiek ouditbaar, append-only rekords van sertifikate, wat deur netwerkdienste onderhou word. Hierdie logs bied kriptografiese bewysstukke vir ouditdoeleindes. Beide uitreikingsowerhede en die publiek kan sertifikate aan hierdie logs indien of dit raadpleeg vir verifikasie. Terwyl die presiese aantal logbedieners nie vasgestel is nie, word verwag dat dit minder as 'n duisend wêreldwyd sal wees. Hierdie bedieners kan onafhanklik bestuur word deur CA's, ISP's, of enige belangstellende entiteit.

#### **Navraag**

Om Sertifikaat Deursigtigheid logs vir enige domein te verken, besoek [https://crt.sh/](https://crt.sh).

Verskillende formate bestaan vir die stoor van sertifikate, elk met sy eie gebruiksgevalle en kompatibiliteit. Hierdie opsomming dek die hoofformate en bied leiding oor die omskakeling tussen hulle.

## **Formate**

### **PEM Formaat**

- Meest gebruikte formaat vir sertifikate.
- Vereis aparte lêers vir sertifikate en private sleutels, gekodeer in Base64 ASCII.
- Algemene uitbreidings: .cer, .crt, .pem, .key.
- Primêr gebruik deur Apache en soortgelyke bedieners.

### **DER Formaat**

- 'n Binaire formaat van sertifikate.
- Ontbreek die "BEGIN/END CERTIFICATE" verklarings wat in PEM-lêers gevind word.
- Algemene uitbreidings: .cer, .der.
- Gereeld gebruik met Java platforms.

### **P7B/PKCS#7 Formaat**

- Gestoor in Base64 ASCII, met uitbreidings .p7b of .p7c.
- Bevat slegs sertifikate en kettingsertifikate, met uitsluiting van die private sleutel.
- Gesteun deur Microsoft Windows en Java Tomcat.

### **PFX/P12/PKCS#12 Formaat**

- 'n Binaire formaat wat bedienersertifikate, intermediêre sertifikate, en private sleutels in een lêer inkapsuleer.
- Uitbreidings: .pfx, .p12.
- Hoofsaaklik gebruik op Windows vir sertifikaat invoer en uitvoer.

### **Omskakeling van Formate**

**PEM omskakelings** is noodsaaklik vir kompatibiliteit:

- **x509 na PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM na DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER na PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM na P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 na PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX omskakelings** is noodsaaklik vir die bestuur van sertifikate op Windows:

- **PFX na PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX na PKCS#8** behels twee stappe:
1. Skakel PFX na PEM om
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Skakel PEM na PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B na PFX** vereis ook twee opdragte:
1. Skakel P7B na CER om
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Skakel CER en Privaat Sleutel na PFX om
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
--- 

{{#include ../banners/hacktricks-training.md}}
