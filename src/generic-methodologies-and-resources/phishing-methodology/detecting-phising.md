# Otkrivanje phishing-a

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Da biste otkrili phishing pokušaj, važno je **razumeti phishing tehnike koje se danas koriste**. Ove informacije možete pronaći na roditeljskoj stranici ovog posta. Ako niste upoznati s tehnikama koje se danas koriste, preporučujem da posetite roditeljsku stranicu i pročitate bar taj odeljak.

Ovaj post se zasniva na ideji da će **napadači pokušati da na neki način oponašaju ili koriste ime domena žrtve**. Ako se vaš domen zove `example.com`, a neko vas phishuje koristeći potpuno drugačije ime domena, na primer `youwonthelottery.com`, ove tehnike to neće otkriti.

## Varijacije imena domena

Prilično je **lako** **otkriti** one **phishing** pokušaje koji u email-u koriste **slično ime domena**.\
Dovoljno je **generisati listu najverovatnijih phishing imena** koja bi napadač mogao da koristi i **proveriti** da li su **registrovana** ili samo proveriti da li ih koristi neka **IP** adresa.

### Pronalaženje sumnjivih domena

U tu svrhu možete koristiti bilo koji od sledećih alata. Oba razrešavaju potencijalne domene da bi proverila da li su u upotrebi.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Savet: Ako generišete listu potencijalnih domena, prosledite je i svojim DNS resolver logovima da biste otkrili **NXDOMAIN upite iz vaše organizacije** (korisnici pokušavaju da posete pogrešno otkucan domen pre nego što ga napadač registruje). Ako politika to dozvoljava, preusmerite te domene na sinkhole ili ih unapred blokirajte.

### Bitflipping

**Kratko objašnjenje potražite na roditeljskoj stranici; za primarno istraživanje bitsquatting-a na Windows.com pogledajte [Remy Hax-ov tekst](https://remyhax.xyz/posts/bitsquatting-windows/) i [izveštaj BleepingComputer-a](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Na primer, izmena jednog bita u domenu microsoft.com može da ga pretvori u _windnws.com._\
**Napadači mogu da registruju što više domena nastalih bitflipping-om koji su povezani sa žrtvom, kako bi preusmerili legitimne korisnike na svoju infrastrukturu**.<sup>[[1]](#references)[[2]](#references)</sup>

**Treba pratiti i sva moguća imena domena nastala bitflipping-om.**

Ako treba da uzmete u obzir i homograph/IDN lookalikes (npr. mešanje latiničnih i ćiriličnih znakova), pogledajte:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Osnovne provere

Kada imate listu potencijalno sumnjivih imena domena, trebalo bi da ih **proverite** (uglavnom portove HTTP i HTTPS) da biste **videli da li koriste neki obrazac za prijavu sličan onom na domenu žrtve**.\
Možete proveriti i da li je port 3333 otvoren i da li na njemu radi instanca `gophish`.\
Takođe je korisno znati **koliko su stari otkriveni sumnjivi domeni**; što su mlađi, to su rizičniji.\
Možete napraviti i **snimke ekrana** sumnjive HTTP i/ili HTTPS veb-stranice da biste utvrdili da li je sumnjiva, a ako jeste, **pristupiti joj radi detaljnijeg pregleda**.

### Napredne provere

Ako želite da odete korak dalje, preporučujem da **nadgledate te sumnjive domene i povremeno tražite nove** (svakog dana? potrebno je samo nekoliko sekundi/minuta). Trebalo bi i da **proverite** otvorene **portove** povezanih IP adresa, **potražite instance `gophish`-a ili sličnih alata** (da, i napadači greše) i **nadgledate HTTP i HTTPS veb-stranice sumnjivih domena i poddomena** da biste videli da li su kopirali neki obrazac za prijavu sa veb-stranica žrtve.\
Da biste ovo **automatizovali**, preporučujem da napravite listu obrazaca za prijavu na domenima žrtve, pokrenete spider nad sumnjivim veb-stranicama i uporedite svaki pronađeni obrazac za prijavu na sumnjivim domenima sa svakim obrascem za prijavu na domenu žrtve, koristeći nešto poput `ssdeep`.\
Ako ste pronašli obrasce za prijavu na sumnjivim domenima, možete pokušati da **pošaljete nasumične kredencijale** i **proverite da li vas preusmeravaju na domen žrtve**.

---

### Potraga pomoću favicon-a i web otisaka (Shodan/Censys)

Mnogi phishing kit-ovi ponovo koriste favicon brenda koji imitiraju. Shodan hešira svoje base64-kodirane favicon podatke pomoću MurmurHash3, dok Censys izlaže svoja polja za favicon hash.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Možete generisati hash kompatibilan sa Shodan-om i pretraživati na osnovu njega:

Python primer (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Pretražite Shodan: `http.favicon.hash:309020573`
- Pomoću alata: pogledajte alate zajednice kao što je favfreak za izračunavanje hash vrednosti i generisanje Shodan dork upita.<sup>[[16]](#references)</sup>

Napomene
- Favikone se ponovo koriste; tretirajte podudaranja kao tragove i proverite sadržaj i sertifikate pre nego što nešto preduzmete.
- Kombinujte sa heuristikama za starost domena i ključne reči radi veće preciznosti.

### Lov na URL telemetriju (urlscan.io)

`urlscan.io` čuva istorijske snimke ekrana, DOM, zahteve i TLS metapodatke za poslate URL-ove. Možete tražiti zloupotrebu brenda i klonove:<sup>[[8]](#references)</sup>

Primeri upita (UI ili API):
- Pronađite slične domene, izuzimajući vaše legitimne domene: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Pronađite sajtove koji direktno koriste vaše resurse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ograničite rezultate na novije: dodajte `AND date:>now-7d`

Primer API-ja:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Iz JSON-a izdvojite:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` da biste uočili veoma nove sertifikate za domene koji imitiraju druge
- vrednosti `task.source`, poput `certstream-suspicious`, da biste povezali nalaze sa CT monitoringom

### Starost domena preko RDAP-a (može se skriptovati)

RDAP vraća mašinski čitljive događaje registracije. Koristan je za označavanje **novoregistrovanih domena (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Obogatite svoj pipeline tako što ćete domenima dodeliti kategorije prema starosti registracije (npr. <7 dana, <30 dana) i u skladu s tim odrediti prioritet trijaže.

### TLS/JAx otisci za otkrivanje AiTM infrastrukture

Phishing za krađu akreditiva može da koristi **Adversary-in-the-Middle (AiTM)** reverse proxy-je (npr. Evilginx) za krađu tokena sesije.<sup>[[11]](#references)</sup> Možete dodati detekcije na mrežnom nivou:

- Beležite TLS/HTTP otiske (JA3/JA4/JA4S/JA4H) na izlaznom saobraćaju. Primećeno je da neke Evilginx verzije imaju stabilne JA4 vrednosti klijenta/servera. Upozorenja za poznate zlonamerne otiske koristite samo kao slab signal i uvek ih potvrdite analizom sadržaja i podataka o domenu.<sup>[[12]](#references)</sup>
- Proaktivno beležite metapodatke TLS sertifikata (izdavaoca, broj SAN unosa, korišćenje wildcard-a, period važenja) za domene nalik pravim, otkrivene putem CT-a ili urlscan-a, i korelišite ih sa starošću DNS zapisa i geolokacijom.

> Napomena: Otiske koristite za obogaćivanje podataka, a ne kao jedini osnov za blokiranje; okviri se razvijaju i mogu da nasumično menjaju ili prikrivaju ove vrednosti.

### Nazivi domena koji sadrže ključne reči

Na nadređenoj stranici se pominje i tehnika varijacije naziva domena koja podrazumeva **ubacivanje naziva domena žrtve u veći domen** (npr. paypal-financial.com za paypal.com).

#### Certificate Transparency

CT dnevnici otkrivaju identitete sertifikata, pa pretraga naziva brenda u poljima Subject ili SAN može da otkrije domene nalik pravim (na primer, sertifikat za `paypal-financial.com` otkriva ključnu reč `paypal`). Po potrebi filtrirajte rezultate prema datumu izdavanja i CA-u i proverite kandidate, jer podudaranja ključnih reči mogu biti lažno pozitivna.<sup>[[13]](#references)</sup>

Originalni [tekst Patrika Hudaka o pronalaženju phishing domena](https://0xpatrik.com/phishing-domains/) prikazuje ovaj postupak u Censys-u, uključujući filtere za datum sertifikata i izdavaoca, kao što je Let's Encrypt.<sup>[[13]](#references)</sup>

![Rezultati pretrage sertifikata u Censys-u korišćeni za identifikovanje domena nalik pravim](<../../images/image (1115).png>)

Možete koristiti i besplatnu uslugu [**crt.sh**](https://crt.sh) za pretragu ključne reči i filtriranje rezultata prema datumu i CA-u.<sup>[[13]](#references)</sup>

![Pretraga ključne reči na crt.sh-u za sumnjive identitete sertifikata](<../../images/image (519).png>)

Polje Matching Identities može pomoći u poređenju identiteta stvarnog domena sa sumnjivim domenima, ali podudaranja tretirajte kao tragove, a ne kao dokaz.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) prenosi CT ažuriranja gotovo u realnom vremenu, a [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) koristi taj tok za ocenjivanje sumnjivih naziva u sertifikatima.<sup>[[14]](#references)[[15]](#references)</sup>

Praktičan savet: pri trijaži CT pogodaka dajte prednost NRD-ovima, registratorima kojima se ne veruje ili koji su nepoznati, WHOIS zapisima sa privacy-proxy zaštitom i sertifikatima sa veoma skorim vremenom `NotBefore`. Održavajte listu dozvoljenih domena/brendova u svom vlasništvu da biste smanjili broj lažno pozitivnih rezultata.

#### **Novi domeni**

Druga opcija je prikupljanje novoregistrovanih domena po TLD-u (na primer, preko [Whoxy](https://www.whoxy.com/newly-registered-domains/)) i filtriranje prema ključnim rečima brenda. Ovim se propušta phishing hostovan na poddomenima kada ključna reč nije prisutna u registrovanom domenu.<sup>[[13]](#references)</sup>

Dodatna heuristika: pri obradi upozorenja tretirajte određene **TLD-ove sa ekstenzijama datoteka** (npr. `.zip`, `.mov`) sa dodatnim oprezom. U mamcima se često mogu pomešati sa nazivima datoteka; za veću preciznost kombinujte signal TLD-a sa ključnim rečima brenda i starošću NRD-a.

## References

- [1] [Remy Hax – Bit-skvotovanje Windows.com-a](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Preusmeravanje saobraćaja ka Microsoftovom windows.com pomoću bit-flippinga](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Detaljan pregled: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 dokumentacija](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Skup podataka o veb-svojstvima platformi](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – referenca za Search API](https://urlscan.io/docs/search/)
- [9] [Pomoć za Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON odgovori za Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Taktike sa tokenima: kako sprečiti, otkriti i odgovoriti na krađu cloud tokena](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ mrežno otiskivanje](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Pronalaženje phishinga: alati i tehnike](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Predstavljamo CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
