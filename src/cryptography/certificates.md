# Vyeti

{{#include ../banners/hacktricks-training.md}}

## Nini ni Cheti

Cheti cha **funguo ya umma** ni kitambulisho cha kidijitali kinachotumika katika cryptography kuthibitisha kwamba mtu anamiliki funguo ya umma. Kinajumuisha maelezo ya funguo, utambulisho wa mmiliki (mada), na saini ya kidijitali kutoka kwa mamlaka inayotegemewa (mtoaji). Ikiwa programu inategemea mtoaji na saini ni halali, mawasiliano salama na mmiliki wa funguo yanawezekana.

Vyeti kwa kawaida vinatolewa na [mamlaka ya vyeti](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) katika muundo wa [miundombinu ya funguo za umma](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Njia nyingine ni [mtandao wa kuaminiana](https://en.wikipedia.org/wiki/Web_of_trust), ambapo watumiaji wanathibitisha funguo za kila mmoja moja kwa moja. Muundo wa kawaida wa vyeti ni [X.509](https://en.wikipedia.org/wiki/X.509), ambayo inaweza kubadilishwa kwa mahitaji maalum kama ilivyoelezwa katika RFC 5280.

## x509 Sehemu za Kawaida

### **Sehemu za Kawaida katika Vyeti vya x509**

Katika vyeti vya x509, sehemu kadhaa **zinacheza** majukumu muhimu katika kuhakikisha halali na usalama wa cheti. Hapa kuna muhtasari wa sehemu hizi:

- **Nambari ya Toleo** inaashiria toleo la muundo wa x509.
- **Nambari ya Mfululizo** inatambulisha cheti kwa kipekee ndani ya mfumo wa Mamlaka ya Cheti (CA), hasa kwa ajili ya kufuatilia kufutwa.
- Sehemu ya **Mada** inawakilisha mmiliki wa cheti, ambaye anaweza kuwa mashine, mtu binafsi, au shirika. Inajumuisha utambulisho wa kina kama:
- **Jina la Kawaida (CN)**: Majina ya maeneo yanayofunikwa na cheti.
- **Nchi (C)**, **Eneo (L)**, **Jimbo au Mkoa (ST, S, au P)**, **Shirika (O)**, na **Kitengo cha Shirika (OU)** vinatoa maelezo ya kijiografia na ya shirika.
- **Jina Lililotambulika (DN)** linajumuisha utambulisho kamili wa mada.
- Maelezo ya **Mtoaji** yanaeleza nani alithibitisha na kusaini cheti, ikiwa ni pamoja na sehemu zinazofanana kama za Mada kwa CA.
- **Muda wa Halali** umewekwa alama na **Siyo Kabla** na **Siyo Baada** ya alama za muda, kuhakikisha cheti hakitumiki kabla au baada ya tarehe fulani.
- Sehemu ya **Funguo ya Umma**, muhimu kwa usalama wa cheti, inaelezea algorithimu, ukubwa, na maelezo mengine ya kiufundi ya funguo ya umma.
- **x509v3 nyongeza** zinaboresha kazi za cheti, zikielezea **Matumizi ya Funguo**, **Matumizi ya Funguo ya Kupanuliwa**, **Jina Alternatif la Mada**, na mali nyingine za kuboresha matumizi ya cheti.

#### **Matumizi ya Funguo na Nyongeza**

- **Matumizi ya Funguo** yanatambulisha matumizi ya cryptographic ya funguo ya umma, kama saini ya kidijitali au ufichaji wa funguo.
- **Matumizi ya Funguo ya Kupanuliwa** yanapunguza zaidi matumizi ya cheti, kwa mfano, kwa uthibitisho wa seva ya TLS.
- **Jina Alternatif la Mada** na **Kikomo cha Msingi** vin定义 majina mengine ya mwenyeji yanayofunikwa na cheti na ikiwa ni cheti cha CA au cheti cha mwisho, mtawalia.
- Vitambulisho kama **Vitambulisho vya Funguo vya Mada** na **Vitambulisho vya Funguo vya Mamlaka** vinahakikisha upekee na ufuatiliaji wa funguo.
- **Upatikanaji wa Taarifa za Mamlaka** na **Nukta za Usambazaji wa CRL** vinatoa njia za kuthibitisha CA inayotoa na kuangalia hali ya kufutwa kwa cheti.
- **CT Precertificate SCTs** vinatoa kumbukumbu za uwazi, muhimu kwa uaminifu wa umma katika cheti.
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
### **Tofauti kati ya OCSP na CRL Distribution Points**

**OCSP** (**RFC 2560**) inahusisha mteja na responder wakifanya kazi pamoja kuangalia kama cheti cha umma wa dijiti kimeondolewa, bila kuhitaji kupakua **CRL** kamili. Njia hii ni bora zaidi kuliko **CRL** ya jadi, ambayo inatoa orodha ya nambari za serial za vyeti vilivyondolewa lakini inahitaji kupakua faili kubwa. CRLs zinaweza kujumuisha hadi entries 512. Maelezo zaidi yanapatikana [here](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Nini maana ya Uwazi wa Cheti**

Uwazi wa Cheti husaidia kupambana na vitisho vinavyohusiana na vyeti kwa kuhakikisha utoaji na uwepo wa vyeti vya SSL unaonekana kwa wamiliki wa domain, CAs, na watumiaji. Malengo yake ni:

- Kuzuia CAs kutoa vyeti vya SSL kwa domain bila maarifa ya mmiliki wa domain.
- Kuanzisha mfumo wa ukaguzi wa wazi wa kufuatilia vyeti vilivyotolewa kwa makosa au kwa uovu.
- Kulinda watumiaji dhidi ya vyeti vya udanganyifu.

#### **Makaratasi ya Vyeti**

Makaratasi ya vyeti ni rekodi za vyeti zinazoweza kukaguliwa hadharani, zinazoongezwa tu, zinazoshughulikiwa na huduma za mtandao. Makaratasi haya yanatoa uthibitisho wa kihesabu kwa ajili ya ukaguzi. Mamlaka za utoaji na umma wanaweza kuwasilisha vyeti kwenye makaratasahaya au kuyatafuta kwa ajili ya uthibitisho. Ingawa idadi halisi ya seva za log haijafanywa kuwa thabiti, inatarajiwa kuwa chini ya elfu moja duniani kote. Seva hizi zinaweza kusimamiwa kwa uhuru na CAs, ISPs, au shirika lolote linalovutiwa.

#### **Utafutaji**

Ili kuchunguza makaratasahaya ya Uwazi wa Cheti kwa domain yoyote, tembelea [https://crt.sh/](https://crt.sh).

Mifumo tofauti inapatikana kwa ajili ya kuhifadhi vyeti, kila moja ikiwa na matumizi yake na ulinganifu. Muhtasari huu unashughulikia mifumo kuu na kutoa mwongozo juu ya kubadilisha kati yao.

## **Mifumo**

### **PEM Format**

- Mfumo unaotumika zaidi kwa vyeti.
- Unahitaji faili tofauti kwa vyeti na funguo za faragha, zilizowekwa katika Base64 ASCII.
- Upanuzi wa kawaida: .cer, .crt, .pem, .key.
- Kimsingi hutumiwa na Apache na seva zinazofanana.

### **DER Format**

- Mfumo wa binary wa vyeti.
- Huna taarifa za "BEGIN/END CERTIFICATE" zinazopatikana katika faili za PEM.
- Upanuzi wa kawaida: .cer, .der.
- Mara nyingi hutumiwa na majukwaa ya Java.

### **P7B/PKCS#7 Format**

- Huhifadhiwa katika Base64 ASCII, ikiwa na upanuzi .p7b au .p7c.
- Inajumuisha vyeti tu na vyeti vya mnyororo, ikiondoa funguo ya faragha.
- Inasaidiwa na Microsoft Windows na Java Tomcat.

### **PFX/P12/PKCS#12 Format**

- Mfumo wa binary unaojumuisha vyeti vya seva, vyeti vya kati, na funguo za faragha katika faili moja.
- Upanuzi: .pfx, .p12.
- Kimsingi hutumiwa kwenye Windows kwa ajili ya kuagiza na kusafirisha vyeti.

### **Kubadilisha Mifumo**

**Mabadiliko ya PEM** ni muhimu kwa ajili ya ulinganifu:

- **x509 to PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM hadi DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER hadi PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM hadi P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 hadi PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX conversions** ni muhimu kwa usimamizi wa vyeti kwenye Windows:

- **PFX to PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX hadi PKCS#8** inahusisha hatua mbili:
1. Geuza PFX kuwa PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Geuza PEM kuwa PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B to PFX** pia inahitaji amri mbili:
1. Geuza P7B kuwa CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Badilisha CER na Funguo Binafsi kuwa PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
--- 

{{#include ../banners/hacktricks-training.md}}
