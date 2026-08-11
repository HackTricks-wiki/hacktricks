# Detektovanje phishinga

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Da biste detektovali phishing pokušaj, važno je **razumeti phishing tehnike koje se danas koriste**. Na nadređenoj stranici ovog posta možete pronaći te informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem vam da odete na nadređenu stranicu i pročitate bar taj odeljak.

Ovaj post se zasniva na ideji da će **napadači pokušati da na neki način oponašaju ili koriste naziv domena žrtve**. Ako se vaš domen zove `example.com`, a phishingujete se korišćenjem potpuno drugačijeg naziva domena, iz nekog razloga poput `youwonthelottery.com`, ove tehnike neće otkriti takav napad.

## Varijacije naziva domena

Prilično je **lako** **otkriti** one **phishing** pokušaje koji će koristiti naziv **sličnog domena** unutar emaila.\
Dovoljno je **generisati listu najverovatnijih phishing naziva** koje bi napadač mogao da koristi i **proveriti** da li su **registrovani** ili jednostavno proveriti da li ih koristi neka **IP** adresa.

### Pronalaženje sumnjivih domena

U tu svrhu možete koristiti neki od sledećih alata. Oba razrešavaju potencijalne domene kako bi proverili da li se koriste.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Savet: Ako generišete listu kandidata, prosledite je i svojim DNS resolver logovima kako biste detektovali **NXDOMAIN upite iz vaše organizacije** (korisnici pokušavaju da pristupe domenu sa greškom u kucanju pre nego što ga napadač zaista registruje). Ako to politika dozvoljava, preusmerite ove domene u sinkhole ili ih unapred blokirajte.

### Bit flipping

**Za kratko objašnjenje pogledajte nadređenu stranicu; za primarno istraživanje bit flippinga na Windows.com pogledajte [Remy Hax-ov tekst](https://remyhax.xyz/posts/bitsquatting-windows/) i [izveštaj BleepingComputer-a](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Na primer, izmena jednog bita u domenu microsoft.com može da ga transformiše u _windnws.com._\
**Napadači mogu registrovati što je moguće više bit-flipping domena povezanih sa žrtvom kako bi legitimne korisnike preusmerili na svoju infrastrukturu**.<sup>[[1]](#references)[[2]](#references)</sup>

**Takođe treba nadgledati sve moguće bit-flipping nazive domena.**

Ako je potrebno da uzmete u obzir i homoglyph/IDN lookalike domene (npr. mešanje latiničnih i ćiriličnih znakova), pogledajte:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Osnovne provere

Kada imate listu potencijalno sumnjivih naziva domena, trebalo bi da ih **proverite** (uglavnom portove HTTP i HTTPS) kako biste **videli da li koriste neki login formular sličan formularu** sa domena žrtve.\
Možete proveriti i port 3333 da biste videli da li je otvoren i da li na njemu radi instanca alata `gophish`.\
Takođe je korisno znati **koliko je star svaki otkriveni sumnjivi domen**, jer je rizik veći što je domen mlađi.\
Možete dobiti i **screenshotove** sumnjive HTTP i/ili HTTPS web stranice da biste videli da li je sumnjiva i, u tom slučaju, **pristupiti joj radi detaljnijeg pregleda**.

### Napredne provere

Ako želite da odete korak dalje, preporučujem da **nadgledate te sumnjive domene i povremeno tražite nove** (svakog dana? To traje samo nekoliko sekundi/minuta). Takođe bi trebalo da **proverite** otvorene **portove** povezanih IP adresa i **potražite instance alata `gophish` ili sličnih alata** (da, i napadači prave greške), kao i da **nadgledate HTTP i HTTPS web stranice sumnjivih domena i poddomena** kako biste videli da li su kopirali neki login formular sa web stranica žrtve.\
Da biste **automatizovali ovaj proces**, preporučujem da imate listu login formulara sa domena žrtve, da crawlujete sumnjive web stranice i da svaki pronađeni login formular unutar sumnjivih domena uporedite sa svakim login formularom sa domena žrtve, koristeći nešto poput `ssdeep`.\
Ako ste pronašli login formulare sumnjivih domena, možete pokušati da **pošaljete lažne kredencijale** i **proverite da li vas preusmeravaju na domen žrtve**.

---

### Lov pomoću favicona i web fingerprinta (Shodan/Censys)

Mnogi phishing kitovi ponovo koriste favicone brenda koji oponašaju. Shodan hešuje svoje base64-enkodirane podatke favicona pomoću MurmurHash3, dok Censys izlaže sopstvena polja heša favicona.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Možete generisati hash kompatibilan sa Shodanom i koristiti ga za pivotiranje:

Python primer (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Upit za Shodan: `http.favicon.hash:309020573`
- Uz pomoć alata: pogledajte community alate kao što je favfreak za izračunavanje hash-eva i generisanje Shodan dorkova.<sup>[[16]](#references)</sup>

Napomene
- Favikoni se ponovo koriste; tretirajte podudaranja kao tragove i proverite sadržaj i sertifikate pre preduzimanja radnji.
- Kombinujte ovo sa heuristikama starosti domena i ključnih reči radi veće preciznosti.

### Lov na URL telemetriju (urlscan.io)

`urlscan.io` čuva istorijske snimke ekrana, DOM, zahteve i TLS metapodatke prosleđenih URL-ova. Možete loviti zloupotrebu brenda i klonove:<sup>[[8]](#references)</sup>

Primeri upita (UI ili API):
- Pronalaženje sličnih domena uz izuzimanje legitimnih domena: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Pronalaženje sajtova koji hotlinkuju vaše resurse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ograničavanje na nedavne rezultate: dodajte `AND date:>now-7d`

Primer API-ja:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Iz JSON-a, pivotiraj na:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` da uočiš veoma nove sertifikate kod lookalike domena
- vrednosti `task.source`, poput `certstream-suspicious`, da povežeš nalaze sa CT monitoringom

### Starost domena putem RDAP-a (pogodno za skriptovanje)

RDAP vraća mašinski čitljive događaje registracije. Koristan je za označavanje **novoregistrovanih domena (NRD-ova)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Obogatite svoj pipeline označavanjem domena prema kategorijama starosti registracije (npr. <7 dana, <30 dana) i odredite prioritet trijaže u skladu s tim.

### TLS/JAx fingerprinti za otkrivanje AiTM infrastrukture

Phishing za krađu kredencijala može koristiti **Adversary-in-the-Middle (AiTM)** reverse proxy-je (npr. Evilginx) za krađu session tokena.<sup>[[11]](#references)</sup> Možete dodati detekcije na mrežnoj strani:

- Beležite TLS/HTTP fingerprinte (JA3/JA4/JA4S/JA4H) na izlaznom saobraćaju. Primećeno je da neke Evilginx verzije koriste stabilne JA4 vrednosti klijenta/servera. Upozorenja zasnovana samo na poznatim lošim fingerprintima koristite kao slab signal i uvek ih potvrdite analizom sadržaja i podacima o domenu.<sup>[[12]](#references)</sup>
- Proaktivno beležite metapodatke TLS sertifikata (izdavač, broj SAN-ova, upotreba wildcarda, period važenja) za lookalike hostove otkrivene putem CT-a ili urlscan-a i korelišite ih sa starošću DNS-a i geolokacijom.

> Napomena: Fingerprinte tretirajte kao obogaćivanje podataka, a ne kao jedine blokade; framework-i se razvijaju i mogu nasumično menjati ili prikrivati svoje karakteristike.

### Nazivi domena koji koriste ključne reči

Nadređena stranica takođe pominje tehniku varijacije naziva domena koja se sastoji u tome da se **naziv domena žrtve postavi unutar većeg domena** (npr. paypal-financial.com za paypal.com).

#### Certificate Transparency

Certificate Transparency (CT) logovi otkrivaju identitete sertifikata, pa pretraga Subject ili SAN naziva prema ključnim rečima brenda može otkriti lookalike domene (na primer, sertifikat za `paypal-financial.com` otkriva ključnu reč `paypal`). Po potrebi filtrirajte rezultate prema datumu izdavanja i CA-u i proverite kandidate, jer podudaranja ključnih reči mogu biti lažno pozitivna.<sup>[[13]](#references)</sup>

Originalni [phishing-domain hunting tekst Patrika Hudaka](https://0xpatrik.com/phishing-domains/) prikazuje ovaj postupak u Censys-u, uključujući filtere za datum sertifikata i izdavača, kao što je Let's Encrypt.<sup>[[13]](#references)</sup>

![Rezultati pretrage sertifikata u Censys-u korišćeni za identifikovanje lookalike domena](<../../images/image (1115).png>)

Možete koristiti i besplatni servis [**crt.sh**](https://crt.sh) za pretragu ključne reči i filtriranje rezultata prema datumu i CA-u.<sup>[[13]](#references)</sup>

![crt.sh pretraga ključne reči za sumnjive identitete sertifikata](<../../images/image (519).png>)

Njegovo polje Matching Identities može pomoći u poređenju identiteta stvarnog domena sa sumnjivim domenima, ali podudaranja tretirajte kao tragove, a ne kao dokaz.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) emituje CT ažuriranja gotovo u realnom vremenu, a [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) koristi taj stream za procenu sumnjivih naziva sertifikata.<sup>[[14]](#references)[[15]](#references)</sup>

Praktičan savet: pri trijaži CT rezultata dajte prioritet NRD-ovima, nepouzdanim/nepoznatim registrarima, WHOIS-u sa privacy-proxy zaštitom i sertifikatima sa veoma skorim vrednostima `NotBefore`. Održavajte allowlist-u domena/brendova koji su u vašem vlasništvu kako biste smanjili šum.

#### **Novi domeni**

Druga opcija je prikupljanje novoregistrovanih domena prema TLD-u (na primer, putem servisa [Whoxy](https://www.whoxy.com/newly-registered-domains/)) i filtriranje prema ključnim rečima brenda. Ovim se propušta phishing hostovan na poddomenima kada ključna reč nije prisutna u registrovanom domenu.<sup>[[13]](#references)</sup>

Dodatna heuristika: određene **TLD-ove sa ekstenzijama fajlova** (npr. `.zip`, `.mov`) tretirajte sa dodatnom sumnjom pri generisanju upozorenja. Oni se u lure-ovima često pogrešno shvataju kao nazivi fajlova; kombinujte signal TLD-a sa ključnim rečima brenda i starošću NRD-a radi bolje preciznosti.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Preotimanje saobraćaja ka Microsoft-ovom windows.com pomoću bitflippinga](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Detaljna analiza: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 dokumentacija](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Skup podataka Web Property platforme](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Reference Search API-ja](https://urlscan.io/docs/search/)
- [9] [Pomoć za Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON odgovori za Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Taktike sa tokenima: Kako sprečiti, otkriti i reagovati na krađu cloud tokena](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ mrežno fingerprintingovanje](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Pronalaženje phishinga: alati i tehnike](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Predstavljanje CertStream-a](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
