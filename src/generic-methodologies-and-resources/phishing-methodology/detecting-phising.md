# Otkrivanje Phishing-a

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Da biste otkrili phishing pokušaj, važno je **razumeti phishing tehnike koje se danas koriste**. Na nadređenoj stranici ovog posta možete pronaći ove informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem vam da odete na nadređenu stranicu i pročitate bar taj odeljak.

Ovaj post se zasniva na ideji da će **napadači pokušati da na neki način oponašaju ili koriste naziv domena žrtve**. Ako se vaš domen zove `example.com`, a phishing napad koristi potpuno drugačiji naziv domena, iz nekog razloga kao što je `youwonthelottery.com`, ove tehnike ga neće otkriti.

## Varijacije naziva domena

Prilično je **lako** **otkriti** one **phishing** pokušaje koji će koristiti **sličan naziv domena** unutar email-a.\
Dovoljno je **generisati listu najverovatnijih phishing naziva** koje bi napadač mogao da koristi i **proveriti** da li su **registrovani**, ili jednostavno proveriti da li ih koristi neka **IP** adresa.

### Pronalaženje sumnjivih domena

U tu svrhu možete koristiti bilo koji od sledećih alata. Imajte na umu da će ovi alati takođe automatski izvršavati DNS zahteve kako bi proverili da li domen ima dodeljenu IP adresu:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Savet: Ako generišete listu kandidata, prosledite je i svojim DNS resolver logovima kako biste otkrili **NXDOMAIN lookups iz vaše organizacije** (korisnici pokušavaju da pristupe typo domenu pre nego što ga napadač zapravo registruje). Preusmerite ove domene u sinkhole ili ih unapred blokirajte ako politika to dozvoljava.

### Bitflipping

**Kratko objašnjenje ove tehnike možete pronaći na nadređenoj stranici. Ili pročitajte originalno istraživanje na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Na primer, izmena jednog bita u domenu microsoft.com može da ga pretvori u _windnws.com._\
**Napadači mogu registrovati što je moguće više bit-flipping domena povezanih sa žrtvom kako bi legitimne korisnike preusmerili na svoju infrastrukturu**.<sup>[[1]](#references)</sup>

**Takođe treba nadgledati sve moguće bit-flipping nazive domena.**

Ako takođe morate da uzmete u obzir homoglyph/IDN lookalikes (npr. mešanje latiničnih i ćiriličnih znakova), proverite:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Osnovne provere

Kada imate listu potencijalno sumnjivih naziva domena, trebalo bi da ih **proverite** (uglavnom portove HTTP i HTTPS) kako biste **utvrdili da li koriste neki login formular sličan** formularu sa domena žrtve.\
Možete takođe proveriti port 3333 da biste videli da li je otvoren i da li na njemu radi instanca alata `gophish`.\
Takođe je korisno znati **koliko je star svaki otkriveni sumnjivi domen**; što je mlađi, to je rizičniji.\
Možete dobiti i **screenshots** sumnjive HTTP i/ili HTTPS web stranice kako biste videli da li je sumnjiva i, u tom slučaju, **pristupiti joj radi detaljnije analize**.

### Napredne provere

Ako želite da odete korak dalje, preporučujem vam da **nadgledate te sumnjive domene i povremeno pretražujete nove** (svakog dana? potrebno je samo nekoliko sekundi/minuta). Takođe bi trebalo da **proverite** otvorene **portove** povezanih IP adresa i **potražite instance alata `gophish` ili sličnih alata** (da, i napadači prave greške), kao i da **nadgledate HTTP i HTTPS web stranice sumnjivih domena i poddomena** kako biste videli da li su kopirali neki login formular sa web stranica žrtve.\
Da biste **automatizovali ovo**, preporučujem da imate listu login formulara domena žrtve, da spider-ujete sumnjive web stranice i uporedite svaki pronađeni login formular unutar sumnjivih domena sa svakim login formularom domena žrtve, koristeći nešto poput alata `ssdeep`.\
Ako ste pronašli login formulare sumnjivih domena, možete pokušati da **pošaljete nasumične kredencijale** i **proverite da li vas preusmeravaju na domen žrtve**.

---

### Lov pomoću favicon-a i web fingerprint-a (Shodan/ZoomEye/Censys)

Mnogi phishing kit-ovi ponovo koriste favicon-e brenda koji oponašaju. Internet-wide skeneri izračunavaju MurmurHash3 vrednost base64-encoded favicon-a. Možete generisati hash i koristiti ga za pivotiranje:

Primer za Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Upit za Shodan: `http.favicon.hash:309020573`
- Korišćenjem alata: pogledajte community alate kao što je favfreak za generisanje hash vrednosti i dorkova za Shodan/ZoomEye/Censys.

Napomene
- Favicon ikone se ponovo koriste; podudaranja tretirajte kao potencijalne tragove i proverite sadržaj i sertifikate pre preduzimanja bilo kakvih radnji.
- Kombinujte heuristike starosti domena i ključnih reči radi bolje preciznosti.

### Lov na URL telemetriju (urlscan.io)

`urlscan.io` čuva istorijske snimke ekrana, DOM, zahteve i TLS metapodatke poslatih URL-ova. Možete tragati za zloupotrebom brenda i klonovima:<sup>[[2]](#references)</sup>

Primeri upita (UI ili API):
- Pronalaženje sličnih domena uz izuzimanje legitimnih domena: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Pronalaženje sajtova koji direktno učitavaju vaše resurse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ograničavanje na nedavne rezultate: dodajte `AND date:>now-7d`

Primer API-ja:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Iz JSON-a izdvojite:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` da biste uočili veoma nove sertifikate kod lookalike domena
- Vrednosti `task.source`, kao što je `certstream-suspicious`, da biste povezali nalaze sa CT monitoringom

### Starost domena putem RDAP-a (pogodno za skriptovanje)

RDAP vraća mašinski čitljive događaje kreiranja. Korisno je za označavanje **novo registrovanih domena (NRD-ova)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Obogatite svoj pipeline označavanjem domena prema kategorijama starosti registracije (npr. <7 dana, <30 dana) i odredite prioritet trijaže u skladu s tim.

### TLS/JAx fingerprints za otkrivanje AiTM infrastrukture

Savremeni phishing za krađu akreditiva sve češće koristi **Adversary-in-the-Middle (AiTM)** reverse proxy-je (npr. Evilginx) za krađu session tokena. Možete dodati detekcije na mrežnoj strani:

- Beležite TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) na izlaznom saobraćaju. Primećeno je da neke Evilginx verzije imaju stabilne JA4 vrednosti klijenta/servera. Upozoravajte samo na poznate zlonamerne fingerprints kao slab signal i uvek potvrdite nalaz analizom sadržaja i intelligence podacima o domenu.<sup>[[3]](#references)</sup>
- Proaktivno beležite metapodatke TLS sertifikata (izdavalac, broj SAN zapisa, korišćenje wildcard-a, validnost) za lookalike hostove otkrivene putem CT-a ili urlscan-a i korelirajte ih sa starošću DNS-a i geolokacijom.

> Napomena: Tretirajte fingerprints kao obogaćivanje podataka, a ne kao jedine blokade; framework-i se razvijaju i mogu randomizovati ili sakriti fingerprints.

### Nazivi domena koji koriste ključne reči

Nadređena stranica takođe pominje tehniku varijacije naziva domena koja se sastoji od stavljanja **naziva domena žrtve unutar većeg domena** (npr. paypal-financial.com za paypal.com).

#### Certificate Transparency

Nije moguće primeniti prethodni pristup „Brute-Force“, ali je zapravo **moguće otkriti takve phishing pokušaje** i zahvaljujući certificate transparency. Svaki put kada CA izda sertifikat, detalji postaju javni. To znači da je čitanjem ili čak nadgledanjem certificate transparency zapisa **moguće pronaći domene koji koriste ključnu reč u svom nazivu**. Na primer, ako napadač generiše sertifikat za [https://paypal-financial.com](https://paypal-financial.com), pregledom sertifikata moguće je pronaći ključnu reč „paypal“ i saznati da se koristi sumnjiv email.

Objava [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeriše da možete koristiti Censys za pretragu sertifikata koji se odnose na određenu ključnu reč i filtrirati ih po datumu (samo „nove“ sertifikate) i po CA izdavaocu „Let's Encrypt“:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Međutim, „isto“ možete uraditi koristeći besplatni web [**crt.sh**](https://crt.sh). Možete **pretraživati ključnu reč** i po želji **filtrirati** rezultate **po datumu i CA-u**.

![Nazivi domena koji koriste ključne reči - Certificate Transparency: Međutim, „isto“ možete uraditi koristeći besplatni web crt.sh. Možete pretraživati ključnu reč i filtrirati rezultate po datumu i...](<../../images/image (519).png>)

Korišćenjem ove poslednje opcije možete čak upotrebiti polje Matching Identities da proverite da li se neki identitet iz stvarnog domena podudara sa nekim od sumnjivih domena (imajte na umu da sumnjiv domen može biti false positive).

**Još jedna alternativa** je odličan projekat pod nazivom [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream pruža stream novogenerisanih sertifikata u realnom vremenu, koji možete koristiti za otkrivanje navedenih ključnih reči u (skoro) realnom vremenu. Zapravo, postoji projekat pod nazivom [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) koji upravo to radi.

Praktičan savet: prilikom trijaže CT pogodaka dajte prioritet NRD-ovima, nepouzdanim/nepoznatim registrarima, WHOIS zapisima sa privacy-proxy zaštitom i sertifikatima sa veoma skorim vremenom `NotBefore`. Održavajte allowlist-u svojih domena/brendova kako biste smanjili šum.

#### **Novi domeni**

**Poslednja alternativa** je prikupljanje liste **skoro registrovanih domena** za neke TLD-ove ([Whoxy](https://www.whoxy.com/newly-registered-domains/) pruža takvu uslugu) i **provera ključnih reči u tim domenima**. Međutim, dugi domeni obično koriste jedan ili više subdomena, pa se ključna reč neće pojaviti unutar FLD-a i nećete moći da pronađete phishing subdomen.

Dodatna heuristika: određenim **TLD-ovima koji izgledaju kao ekstenzije fajlova** (npr. `.zip`, `.mov`) dodelite viši nivo sumnje prilikom generisanja upozorenja. Oni se često mogu zameniti sa nazivima fajlova u phishing porukama; kombinujte signal TLD-a sa ključnim rečima brenda i starošću NRD-a radi veće preciznosti.

## Reference

- [1] [Preotimanje saobraćaja ka Microsoft-ovom windows.com pomoću bitflipping-a](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Referenca Search API-ja](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Otkrivanje phishinga: alati i tehnike](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
