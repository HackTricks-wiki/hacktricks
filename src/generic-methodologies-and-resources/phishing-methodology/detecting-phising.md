# Otkrivanje phishinga

## Uvod

Da biste otkrili phishing pokušaj, važno je **razumeti phishing tehnike koje se danas koriste**. Na roditeljskoj stranici ovog posta možete pronaći ove informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem da odete na roditeljsku stranicu i pročitate barem taj odeljak.

Ovaj post se zasniva na ideji da će **napadači pokušati da na neki način oponašaju ili koriste naziv domena žrtve**. Ako se vaš domen zove `example.com`, a phishing napad se iz nekog razloga sprovodi preko potpuno drugačijeg naziva domena, kao što je `youwonthelottery.com`, ove tehnike ga neće otkriti.

## Varijacije naziva domena

Prilično je **lako** **otkriti** one **phishing** pokušaje koji će u emailu koristiti naziv **sličnog domena**.\
Dovoljno je **generisati listu najverovatnijih phishing naziva** koje bi napadač mogao da koristi i **proveriti** da li su **registrovani** ili jednostavno proveriti da li ih koristi neka **IP** adresa.

### Pronalaženje sumnjivih domena

U tu svrhu možete koristiti bilo koji od sledećih alata. Oba razrešavaju kandidate domena kako bi proverila da li se koriste.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Savet: Ako generišete listu kandidata, prosledite je i svojim DNS resolver logovima kako biste otkrili **NXDOMAIN upite iz vaše organizacije** (korisnici pokušavaju da pristupe domenu sa greškom pre nego što ga napadač zapravo registruje). Ako politika to dozvoljava, preusmerite ove domene u sinkhole ili ih unapred blokirajte.

### Bitflipping

**Za kratko objašnjenje pogledajte roditeljsku stranicu; za primarno istraživanje bit flippinga na Windows.com pogledajte [Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) i [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Na primer, izmena jednog bita u domenu microsoft.com može da ga pretvori u _windnws.com._\
**Napadači mogu registrovati što je moguće više bit-flipping domena povezanih sa žrtvom kako bi legitimne korisnike preusmerili na svoju infrastrukturu**.<sup>[[1]](#references)[[2]](#references)</sup>

**Takođe treba pratiti sva moguća imena bit-flipping domena.**

Ako takođe treba da uzmete u obzir homoglifne/IDN lookalike domene (npr. mešanje latiničnih i ćiriličnih znakova), pogledajte:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Osnovne provere

Kada budete imali listu potencijalno sumnjivih naziva domena, trebalo bi da ih **proverite** (uglavnom portove HTTP i HTTPS) kako biste **utvrdili da li koriste neki login formular sličan** formularu sa domena žrtve.\
Možete proveriti i port 3333 da biste videli da li je otvoren i da li na njemu radi instanca alata `gophish`.\
Takođe je korisno znati **koliko je star svaki otkriveni sumnjivi domen**; što je mlađi, to je rizičniji.\
Možete dobiti i **screenshotove** sumnjive HTTP i/ili HTTPS web stranice kako biste videli da li je sumnjiva i, u tom slučaju, **pristupiti joj radi detaljnijeg pregleda**.

### Napredne provere

Ako želite da odete korak dalje, preporučujem da **nadgledate te sumnjive domene i povremeno pretražujete nove** (svakog dana? potrebno je samo nekoliko sekundi/minuta). Takođe bi trebalo da **proverite** otvorene **portove** povezanih IP adresa i **potražite instance alata `gophish` ili sličnih alata** (da, i napadači prave greške), kao i da **nadgledate HTTP i HTTPS web stranice sumnjivih domena i poddomena** kako biste videli da li su kopirali neki login formular sa web stranica žrtve.\
Da biste ovo **automatizovali**, preporučujem da imate listu login formulara sa domena žrtve, da spiderujete sumnjive web stranice i uporedite svaki pronađeni login formular unutar sumnjivih domena sa svakim login formularom sa domena žrtve, koristeći nešto poput alata `ssdeep`.\
Ako ste pronašli login formulare na sumnjivim domenima, možete pokušati da **pošaljete lažne kredencijale** i **proverite da li vas preusmeravaju na domen žrtve**.

---

### Lov pomoću favicon-a i web fingerprinta (Shodan/Censys)

Mnogi phishing kitovi ponovo koriste favicon-e brenda koji oponašaju. Shodan hešira svoje base64-enkodirane podatke favicon-a pomoću MurmurHash3, dok Censys izlaže sopstvena polja sa hešom favicon-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Možete generisati hash kompatibilan sa Shodan-om i pretraživati na osnovu njega:

Python primer (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Pretražite Shodan: `http.favicon.hash:309020573`
- Uz pomoć alata: pogledajte community tools kao što je favfreak za izračunavanje hash vrednosti i generisanje Shodan dorks.<sup>[[16]](#references)</sup>

Napomene
- Favicons se ponovo koriste; tretirajte podudaranja kao tragove i proverite sadržaj i sertifikate pre nego što preduzmete nešto.
- Kombinujte ovo sa heuristikama starosti domena i ključnih reči radi veće preciznosti.

### Lov na URL telemetriju (urlscan.io)

`urlscan.io` čuva istorijske snimke ekrana, DOM, zahteve i TLS metapodatke poslatih URL-ova. Možete tražiti zloupotrebu brenda i klonove:<sup>[[8]](#references)</sup>

Primeri upita (UI ili API):
- Pronađite slične sajtove, izuzimajući vaše legitimne domene: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Pronađite sajtove koji koriste hotlinking za vaše resurse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ograničite rezultate na skorije rezultate: dodajte `AND date:>now-7d`

Primer API-ja:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Iz JSON-a, fokusirajte se na:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` da biste uočili veoma nove sertifikate kod lookalike domena
- vrednosti `task.source` kao što je `certstream-suspicious` da biste povezali nalaze sa CT monitoringom

### Starost domena putem RDAP-a (pogodno za skriptovanje)

RDAP vraća mašinski čitljive događaje registracije. Korisno za označavanje **novoregistrovanih domena (NRD-ova)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Obogatite svoj pipeline označavanjem domena prema kategorijama starosti registracije (npr. <7 dana, <30 dana) i u skladu s tim odredite prioritete trijaže.

### TLS/JAx fingerprints za otkrivanje AiTM infrastrukture

Credential-phishing može koristiti **Adversary-in-the-Middle (AiTM)** reverse proxy-je (npr. Evilginx) za krađu session tokena.<sup>[[11]](#references)</sup> Možete dodati detekcije na mrežnoj strani:

- Beležite TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) na izlaznom saobraćaju. Primećeno je da neke Evilginx build verzije koriste stabilne JA4 vrednosti klijenta/servera. Upozoravajte samo na poznate zlonamerne fingerprints kao slab signal i uvek potvrdite nalaz analizom sadržaja i domain intel podacima.<sup>[[12]](#references)</sup>
- Proaktivno beležite metapodatke TLS sertifikata (issuer, broj SAN zapisa, upotrebu wildcard-a, validnost) za lookalike hostove otkrivene putem CT-a ili urlscan-a i korelišite ih sa starošću DNS-a i geolokacijom.

> Napomena: Tretirajte fingerprints kao enrichment, a ne kao jedine blokere; framework-i se razvijaju i mogu nasumično menjati ili prikrivati svoje karakteristike.

### Domain names using keywords

Parent stranica takođe pominje tehniku varijacije naziva domena koja se sastoji u tome da se **naziv domena žrtve postavi unutar većeg domena** (npr. paypal-financial.com za paypal.com).

#### Certificate Transparency

Certificate Transparency (CT) logovi izlažu identitete sertifikata, pa pretraga Subject ili SAN naziva prema brand keywords može otkriti lookalike domene (na primer, sertifikat za `paypal-financial.com` izlaže keyword `paypal`). Po potrebi filtrirajte rezultate prema datumu izdavanja i CA-u i validirajte kandidate, jer poklapanja keyword-a mogu biti false positive.<sup>[[13]](#references)</sup>

Originalni [phishing-domain hunting write-up Patrika Hudaka](https://0xpatrik.com/phishing-domains/) demonstrira ovaj workflow u Censys-u, uključujući filtere za datum sertifikata i issuer, kao što je Let's Encrypt.<sup>[[13]](#references)</sup>

Možete koristiti i besplatni servis [**crt.sh**](https://crt.sh) za pretragu keyword-a i filtriranje rezultata prema datumu i CA-u.<sup>[[13]](#references)</sup>

Njegovo polje Matching Identities može pomoći u poređenju identiteta stvarnog domena sa sumnjivim domenima, ali tretirajte poklapanja kao tragove, a ne kao dokaz.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) emituje CT ažuriranja gotovo u realnom vremenu, a [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) koristi taj stream za procenu sumnjivih naziva sertifikata.<sup>[[14]](#references)[[15]](#references)</sup>

Praktičan savet: pri trijaži CT pogodaka dajte prioritet NRD-ovima, nepouzdanim/nepoznatim registrarima, WHOIS privacy-proxy zapisima i sertifikatima sa veoma skorim `NotBefore` vremenima. Održavajte allowlist-u domena/brendova koji su u vašem vlasništvu kako biste smanjili šum.

#### **Novi domeni**

Druga opcija je prikupljanje novoregistrovanih domena prema TLD-u (na primer, putem [Whoxy](https://www.whoxy.com/newly-registered-domains/)) i filtriranje prema brand keywords. Ovim se ne otkriva phishing hostovan na subdomenima kada keyword nije prisutan u registrovanom domenu.<sup>[[13]](#references)</sup>

Dodatna heuristika: tretirajte određene **file-extension TLD-ove** (npr. `.zip`, `.mov`) sa dodatnim oprezom pri alertovanju. Oni se često mogu zameniti sa nazivima fajlova u lure-ovima; kombinujte TLD signal sa brand keywords i starošću NRD-a radi veće preciznosti.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Preuzimanje saobraćaja ka Microsoft-ovom windows.com domenu korišćenjem bitflipping-a](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Detaljna analiza: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 dokumentacija](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Dataset web svojstava platformi](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referenca Search API-ja](https://urlscan.io/docs/search/)
- [9] [Pomoć za Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON odgovori za Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: Kako sprečiti, otkriti i reagovati na krađu cloud tokena](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Pronalaženje phishinga: alati i tehnike](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Predstavljanje CertStream-a](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
