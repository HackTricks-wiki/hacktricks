# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Da biste otkrili phishing pokušaj važno je **razumeti phishing tehnike koje se danas koriste**. Na roditeljskoj stranici ovog posta možete pronaći te informacije, pa ako niste upoznati koje se tehnike danas koriste preporučujem da odete na roditeljsku stranicu i pročitate barem taj deo.

Ovaj post se zasniva na ideji da će **napadači pokušati na neki način imitirati ili koristiti domen žrtve**. Ako se vaš domen zove `example.com` i budete phished koristeći potpuno drugačiji domen iz nekog razloga poput `youwonthelottery.com`, ove tehnike to neće otkriti.

## Domain name variations

Prilično je **lako** **otkriti** one **phishing** pokušaje koji će koristiti **sličan domen** unutar emaila.\
Dovoljno je **generisati listu najverovatnijih phishing imena** koja bi napadač mogao koristiti i **proveriti** da li je **registrovan** ili samo proveriti da li bilo koji **IP** koristi taj domen.

### Finding suspicious domains

Za ovu svrhu možete koristiti bilo koji od sledećih alata. Imajte na umu da će ovi alati takođe automatski izvršavati DNS zahteve da provere da li domen ima dodeljen neki IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Savet: Ako generišete listu kandidata, ubacite je i u logove vašeg DNS resolvera kako biste otkrili **NXDOMAIN upite iz vaše organizacije** (korisnici koji pokušavaju da dosegnu tipfeler pre nego što napadač zapravo registruje domen). Sinkholujte ili preblokirajte ove domene ako politika dozvoljava.

### Bitflipping

**Kratko objašnjenje ove tehnike možete naći na roditeljskoj stranici. Ili pročitajte originalno istraživanje na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na primer, 1-bitna izmena u domenu microsoft.com može ga transformisati u _windnws.com._\
**Napadači mogu registrovati što više bit-flipping domena povezanih sa žrtvom kako bi preusmerili legitimne korisnike na svoju infrastrukturu**.

**Svi mogući bit-flipping nazivi domena takođe bi trebalo da budu praćeni.**

Ako takođe treba da uzmete u obzir homoglyph/IDN lookalikes (npr. mešanje Latin/Cyrillic karaktera), proverite:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

Kada imate listu potencijalno sumnjivih imena domena treba da ih **proverite** (uglavnom portove HTTP i HTTPS) da biste videli da li koriste neki login form sličan nekom iz domena žrtve.\
Takođe možete proveriti port 3333 da vidite da li je otvoren i pokreće instancu `gophish`.\
Zanimljivo je znati **koliko je stara svaki otkriveni sumnjiv domen** — što je mlađi, to je rizičniji.\
Takođe možete dobiti **snimke ekrana** HTTP i/ili HTTPS sumnjive web stranice da vidite da li je sumnjiva i u tom slučaju **pristupiti joj radi dublje analize**.

### Advanced checks

Ako želite da odete korak dalje preporučio bih da **nadgledate te sumnjive domene i povremeno tražite nove** (svakog dana? to traje samo nekoliko sekundi/minuta). Takođe bi trebalo da **proverite** otvorene **portove** povezanih IP-ova i **tražite instance `gophish` ili sličnih alata** (da, napadači takođe greše) i **nadgledate HTTP i HTTPS web stranice sumnjivih domena i poddomena** da biste videli da li su kopirali neki login form sa stranica žrtve.\
Da biste to **automatizovali** preporučujem da imate listu login formi domena žrtve, da pokrenete spider nad sumnjivim web stranicama i upoređujete svaki login form pronađen na sumnjivim domenima sa svakim login formom žrtvinog domena koristeći nešto poput `ssdeep`.\
Ako ste locirali login forme sumnjivih domena, možete pokušati da **pošaljete lažne kredencijale** i **proverite da li vas preusmerava na domen žrtve**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Mnogi phishing kitovi ponovo koriste favicon-e iz brenda koji impersoniraju. Internet-wide skeneri izračunavaju MurmurHash3 od base64-encoded favicon-a. Možete generisati hash i pivotirati na njega:

Primer u Pythonu (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Upit na Shodan: `http.favicon.hash:309020573`
- Sa alatima: pogledajte community tools poput favfreak za generisanje hashes i dorks za Shodan/ZoomEye/Censys.

Napomene
- Favicons se ponovo koriste; tretirajte podudaranja kao tragove i verifikujte sadržaj i certs pre nego što reagujete.
- Kombinujte sa domain-age i heuristikom ključnih reči za veću preciznost.

### Lov na URL telemetriju (urlscan.io)

`urlscan.io` čuva istorijske snimke ekrana, DOM, requests i TLS meta-podatke poslatih URL-ova. Možete tražiti zloupotrebu brenda i klonove:

Primeri upita (UI ili API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrict to recent results: append `AND date:>now-7d`

Primer API-ja:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Iz JSON-a, pivot on:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` da otkriješ veoma nove certs za lookalikes
- `task.source` values like `certstream-suspicious` da povežeš nalaze sa CT monitoringom

### Starost domena preko RDAP-a (scriptable)

RDAP vraća mašinski čitljive događaje o kreiranju. Korisno za označavanje **novoregistrovanih domena (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Obogatite svoj pipeline označavanjem domena prema starosti registracije (npr. <7 dana, <30 dana) i prioritizujte trijažu u skladu s tim.

### TLS/JAx otisci prstiju za otkrivanje AiTM infrastrukture

Savremeni credential-phishing sve češće koristi **Adversary-in-the-Middle (AiTM)** reverse proxy-e (npr. Evilginx) za krađu session tokena. Možete dodati detekcije na mrežnoj strani:

- Zabeležite TLS/HTTP otiske (JA3/JA4/JA4S/JA4H) na egressu. Neki Evilginx buildovi su primećeni sa stabilnim JA4 vrednostima klijent/server. Alarmirajte na poznato-loše otiske samo kao slab signal i uvek potvrdite sa sadržajem i domain intel-om.
- Proaktivno beležite TLS certificate metadata (issuer, SAN count, wildcard use, validity) za lookalike hostove otkrivene putem CT ili urlscan i korelirajte sa starošću DNS-a i geolokacijom.

> Napomena: tretirajte otiske kao enrichment, ne kao jedine blokere; frameworks se razvijaju i mogu randomizovati ili obfuskovati.

### Domain names using keywords

Roditeljska stranica takođe pominje tehniku varijacije naziva domena koja se sastoji od ubacivanja **domena žrtve u veći domen** (npr. paypal-financial.com za paypal.com).

#### Certificate Transparency

Nije moguće primeniti prethodni "Brute-Force" pristup, ali je zapravo **moguće otkriti takve phishing pokušaje** zahvaljujući certificate transparency. Svaki put kada CA izda sertifikat, detalji postaju javni. To znači da čitanjem certificate transparency ili čak praćenjem istog, **moguće je pronaći domene koji koriste ključnu reč u svom imenu**. Na primer, ako napadač generiše sertifikat za [https://paypal-financial.com](https://paypal-financial.com), pregledajući sertifikat moguće je naći ključnu reč "paypal" i znati da se koristi sumnjiv e-mail.

The post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggests that you can use Censys to search for certificates affecting a specific keyword and filter by date (only "new" certificates) and by the CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Međutim, isto možete uraditi koristeći besplatni web [**crt.sh**](https://crt.sh). Možete **pretražiti ključnu reč** i **filtrirati** rezultate **po datumu i CA** ako želite.

![](<../../images/image (519).png>)

Koristeći ovu poslednju opciju možete čak koristiti polje Matching Identities da vidite da li neka identitet iz pravog domena odgovara nekom od sumnjivih domena (imajte na umu da sumnjiv domen može biti false positive).

**Još jedna alternativa** je fantastičan projekat pod nazivom [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream obezbeđuje real-time stream novo-generisanih sertifikata koji možete koristiti za detekciju određenih ključnih reči u (near) real-time. Zapravo, postoji projekat [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) koji radi upravo to.

Praktičan savet: pri trijaži CT hitova, prioritizujte NRD-ove, nepoverljive/unknown registrare, privacy-proxy WHOIS, i certs sa vrlo nedavnim `NotBefore` vremenima. Održavajte allowlistu vaših owned domena/brandova da smanjite šum.

#### **New domains**

**Jedna poslednja alternativa** je da prikupite listu **newly registered domains** za neke TLD-ove ([Whoxy](https://www.whoxy.com/newly-registered-domains/) provides such service) i **proverite ključne reči u tim domenima**. Međutim, dugi domeni obično koriste jedan ili više subdomena, stoga ključna reč neće biti u FLD-u i nećete moći da pronađete phishing subdomen.

Dodatna heuristika: tretirajte određene **file-extension TLDs** (npr. `.zip`, `.mov`) sa dodatnim stepenom sumnje pri alertovanju. Oni se često mešaju sa imenima fajlova u mamcima; kombinujte TLD signal sa brand ključnim rečima i NRD age za bolju preciznost.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
