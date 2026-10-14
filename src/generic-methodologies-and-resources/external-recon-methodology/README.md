# Metodologija spoljnog izviđanja

{{#include ../../banners/hacktricks-training.md}}

## Otkrivanje resursa

> Rečeno vam je da je sve što pripada nekoj kompaniji u scope-u, a želite da utvrdite šta ta kompanija zapravo poseduje.

Cilj ove faze je da pronađete sve **kompanije u vlasništvu glavne kompanije**, a zatim sve **resurse** tih kompanija. Da biste to uradili, potrebno je da:<sup>[[1]](#references)</sup>

1. Pronađete akvizicije glavne kompanije. Tako ćete saznati koje su kompanije u scope-u.
2. Pronađete ASN (ako postoji) svake kompanije. Tako ćete saznati opsege IP adresa u vlasništvu svake kompanije.
3. Koristite reverse whois pretrage da biste pronašli druge stavke (nazive organizacija, domene...) povezane sa prvom stavkom (ovo se može raditi rekurzivno).
4. Koristite druge tehnike, kao što su Shodan `org` i `ssl` filteri, da biste pretražili druge resurse (trik sa `ssl` može se primenjivati rekurzivno).

### **Akvizicije**

Pre svega, treba da saznamo **koje su druge kompanije u vlasništvu glavne kompanije**.\
Jedna mogućnost je da posetite [https://www.crunchbase.com/](https://www.crunchbase.com), **potražite** **glavnu kompaniju** i **kliknete** na "**acquisitions**". Tamo ćete videti druge kompanije koje je glavna kompanija preuzela.\
Druga mogućnost je da posetite stranicu glavne kompanije na **Wikipediji** i potražite **acquisitions**.\
Za javna preduzeća proverite **SEC/EDGAR prijave**, stranice **za odnose sa investitorima** ili lokalne registre kompanija (npr. **Companies House** u UK).\
Za globalne korporativne strukture i podružnice isprobajte **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) i bazu podataka **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> U redu, u ovom trenutku bi trebalo da znate sve kompanije koje su u scope-u. Hajde da vidimo kako da pronađemo njihove resurse.

### **ASN-ovi**

Autonomni sistemski broj (**ASN**) je **jedinstven broj** koji **Internet Assigned Numbers Authority (IANA)** dodeljuje **autonomnom sistemu** (AS).\
**AS** se sastoji od **blokova** **IP adresa** koji imaju jasno definisanu politiku pristupa spoljnim mrežama i kojima upravlja jedna organizacija, ali mogu da obuhvataju više operatora.

Vredno je proveriti da li je **kompaniji dodeljen neki ASN** kako biste pronašli njene **opsege IP adresa**. Bilo bi korisno sprovesti **test ranjivosti** nad svim **hostovima** u **scope-u** i **potražiti domene** unutar tih IP adresa.\
Možete da pretražujete po **nazivu** kompanije, **IP adresi** ili **domenu** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **ili** [**https://ipinfo.io/**](https://ipinfo.io/).\
**U zavisnosti od regiona u kojem se kompanija nalazi, ove veze mogu biti korisne za prikupljanje dodatnih podataka:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Severna Amerika),** [**APNIC**](https://www.apnic.net) **(Azija),** [**LACNIC**](https://www.lacnic.net) **(Latinska Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Evropa). U svakom slučaju, verovatno se sve** korisne informacije **(opsezi IP adresa i Whois)** već nalaze na prvoj vezi.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Takođe, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-ova** enumeracija automatski objedinjuje i sažima ASN-ove na kraju skeniranja.

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

Možete pronaći IP opsege organizacije i pomoću [http://asnlookup.com/](http://asnlookup.com) (ima besplatan API).\
Možete pronaći IP adresu i ASN domena pomoću [http://ipv4info.com/](http://ipv4info.com).

### **Traženje ranjivosti**

U ovom trenutku znamo **sva sredstva obuhvaćena opsegom**, pa ako imate dozvolu, možete pokrenuti neki **skener ranjivosti** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) nad svim hostovima.\
Takođe, možete pokrenuti [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **ili koristiti servise poput** Shodan, Censys ili ZoomEye **da biste pronašli** otvorene portove **i, u zavisnosti od toga šta pronađete, trebalo bi da** pogledate u ovoj knjizi kako da pentestujete razne moguće servise koji su pokrenuti.\
**Takođe, vredi pomenuti da možete pripremiti liste** podrazumevanih korisničkih imena **i** lozinki **i pokušati da** bruteforceujete servise pomoću [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeni

> Znamo sve kompanije obuhvaćene opsegom i njihova sredstva, vreme je da pronađemo domene obuhvaćene opsegom.

_Imajte na umu da pomoću predloženih tehnika možete pronaći i poddomene i da te informacije ne treba potcenjivati._

Pre svega, trebalo bi da potražite **glavni domen**(e) svake kompanije. Na primer, za _Tesla Inc._ to će biti _tesla.com_.

### **Reverse DNS**

Pošto ste pronašli sve IP opsege domena, možete pokušati da izvršite **reverse dns lookups** nad tim **IP adresama kako biste pronašli još domena obuhvaćenih opsegom**. Pokušajte da koristite neki DNS server žrtve ili neki poznati DNS server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Da bi ovo funkcionisalo, administrator mora ručno da omogući PTR.\
Za ove informacije možete koristiti i online alat: [http://ptrarchive.com/](http://ptrarchive.com).\
Za velike opsege, alati kao što su [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) korisni su za automatizaciju obrnutih DNS upita i obogaćivanje podataka.

### **Reverse Whois (loop)**

U **whois** zapisima možete pronaći mnogo zanimljivih **informacija**, kao što su **naziv organizacije**, **adresa**, **imejlovi**, brojevi telefona... Još je zanimljivije to što možete pronaći **dodatne resurse povezane sa kompanijom** ako izvršite **reverse whois pretrage na osnovu bilo kog od tih polja** (na primer, druge whois registre u kojima se pojavljuje ista imejl adresa).\
Možete koristiti online alate kao što su:

- [https://ip.thc.org/](https://ip.thc.org/) - **Besplatno** (veb i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Besplatno**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Besplatno**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Besplatno**
- [https://www.whoxy.com/](https://www.whoxy.com) - veb je **besplatan**, API se naplaćuje.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nije besplatno
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nije besplatno (samo **100 besplatnih** pretraga)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nije besplatno
- [https://securitytrails.com/](https://securitytrails.com/) - Nije besplatno (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Nije besplatno (API)

Ovaj zadatak možete automatizovati pomoću alata [**DomLink** ](https://github.com/vysecurity/DomLink)(zahteva whoxy API ključ).\
Automatsko otkrivanje putem reverse whois-a možete obaviti i pomoću alata [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Imajte na umu da ovom tehnikom možete otkriti dodatne nazive domena svaki put kada pronađete novi domen.**

### **Trackeri**

Ako pronađete **isti ID istog trackera** na 2 različite stranice, možete pretpostaviti da **obema stranicama** **upravlja isti tim**.\
Na primer, ako na više stranica vidite isti **Google Analytics ID** ili isti **Adsense ID**.

Postoje stranice i alati koji omogućavaju pretragu pomoću ovih i drugih trackera:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (pronalazi povezane sajtove na osnovu zajedničke analitike/trackera)
- [**StackScan**](https://www.stackscan.com) - **Besplatni paket** (veb i API). Pretragu možete zasnovati na bilo kom isporučenom resursu, ne samo na ID-jevima trackera: putanji skripte, nazivu samostalno hostovanog paketa ili hostu sa kog se učitava resurs. Alat vraća sve sajtove na kojima se taj resurs nalazi.

API vraća stek za pojedinačni domen, što je korisno za potvrdu da potencijalni resurs pripada istoj infrastrukturi:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Vraća svaku otkrivenu tehnologiju i njenu kategoriju. Asset pivoting je trenutno dostupan samo za web; API omogućava pretragu po domenu.

### **Favicon**

Da li ste znali da možemo da pronađemo povezane domene i poddomene našeg cilja tako što ćemo potražiti isti hash favicon ikone? Upravo to radi alat [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), koji je napravio [@m4ll0k2](https://twitter.com/m4ll0k2). Evo kako da ga koristite:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Jednostavno rečeno, favihash nam omogućava da otkrijemo domene koji imaju isti hash favicon ikone kao naša meta.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Koristite poznati hash favicon ikone kao Shodan ili FOFA polazište za pronalaženje drugih izloženih instanci iste tehnologije.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ovako možete **izračunati hash favicon-a** veb-sajta (MMH3 nad **base64-enkodiranim** bajtovima favicon-a):

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url, timeout=10)
    favicon = codecs.encode(response.content, "base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

Takođe možete pribaviti favicon hash vrednosti u velikom obimu pomoću alata [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a zatim potražiti povezane rezultate na Shodan/Censys.

Favicon otiske tretirajte kao tragove i proverite ih pomoću okolnih signala.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash tretirajte kao indikator, a ne kao dokaz**: MMH3 je kompaktan; mogući su sudari, ponovo korišćene ikone i namerno lažiranje.
- **Proverite više putanja od** `/favicon.ico`: pregledajte putanje framework-a/build-a, manifest datoteke, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-ove i HTML oznake `<link rel="icon">`.
- **Statički resursi mogu ostati dostupni iza WAF/SSO/IdP kontrola**: direktno zatražite ikonu i proverite `ETag`, `Last-Modified`, preusmerenja i cache zaglavlja.
- **Proverite podudaranja pomoću okolnih signala**: uporedite naslov, HTML/body hash, zaglavlja, subjekte/SAN-ove TLS sertifikata, komponente proizvoda i izložene portove.
- **Grupišite rezultate prema HTML/body hash-u**: dosledan šablon jača otisak; različiti šabloni ukazuju na generičku ili deljenu ikonu.
- **Hash koji se pojavljuje uz nepovezane potpise, portove i proizvode tretirajte kao mogući honeypot ili placeholder.**
- **Kod nejasnih ciljeva uporedite stvarnu stranicu sa nepostojećom putanjom**, kao što je `/_favicon_probe_<8-hex>`; podudarni odgovori hosting ili parking stranice mogu objasniti deljenu ikonu.
- **Počnite trijažu pomoću Nuclei pravila za detekciju ili javnih skupova podataka** koji povezuju favicon hash vrednosti sa proizvodima i CPE-ovima.
- **Imajte na umu ograničenja pokrivenosti zasnovane na IP adresama**: površine iza CDN-a, rutirane preko SNI-ja, anycast i samo domenom dostupne površine mogu izostati iz skupova podataka nalik Shodan-u.

### **Autorsko pravo / Jedinstveni string**

Pretražite veb-stranice i pronađite **stringove koji se mogu deliti između različitih sajtova iste organizacije**. Dobar primer može biti **string o autorskim pravima**. Zatim taj string potražite na **google-u**, u drugim **pregledačima** ili čak na **shodan-u**: `shodan search http.html:"Copyright string"`

### **CRT vreme**

Uobičajeno je imati cron job kao što je

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

za obnavljanje svih sertifikata na serveru istovremeno. Povezivanje vremenskih oznaka sertifikata ili njihovih pozicija u Certificate Transparency logovima može otkriti povezane domene.<sup>[[6]](#references)</sup>

Takođe, direktno koristite logove **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacije o DMARC-u za poštu

Možete da koristite veb-sajt kao što je [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ili alat kao što je [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) da biste pronašli **domene i poddomene koji dele iste DMARC informacije**.\
Drugi korisni alati su [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Napusteni A zapis može ponovo postati dostupan kada cloud provajder dodeli njegovu IP adresu drugom korisniku. Navedeno istraživanje prikazuje oportunistički postupak koji pokreće instancu i upoređuje njenu adresu sa podacima pasivnog DNS-a; scenarije preuzimanja testirajte samo u okviru odobrenog opsega.<sup>[[7]](#references)</sup>

### **Drugi načini**

Ponovite odgovarajuće korake otkrivanja svaki put kada pronađete novi domen: svaki rezultat može otkriti dodatna imena iz sertifikata, veze u pasivnom DNS-u, poklapanja favicon-a i identifikatore organizacije koji nisu bili vidljivi na osnovu početnog domena.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Kao što već znate ime organizacije koja poseduje IP prostor, te podatke možete da pretražite u Shodanu koristeći: `org:"Tesla, Inc."` Proverite pronađene hostove da biste otkrili nove, neočekivane domene u TLS sertifikatu.

Možete da pristupite **TLS sertifikatu** glavne veb-stranice, pribavite **naziv organizacije**, a zatim potražite taj naziv u **TLS sertifikatima** svih veb-stranica poznatih alatu **Shodan** pomoću filtera: `ssl:"Tesla Motors"` ili koristite alat kao što je [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)je alat koji traži **domene povezane** sa glavnim domenom i njihove **poddomene**; zaista je sjajan.

**Pasivni DNS / Istorijski DNS**

Podaci pasivnog DNS-a su odlični za pronalaženje **starih i zaboravljenih zapisa** koji se i dalje razrešavaju ili mogu da se preuzmu. Pogledajte:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Traženje ranjivosti**

Proverite da li postoji neki slučaj [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Možda neka kompanija **koristi domen**, ali je **izgubila vlasništvo nad njim**. Samo ga registrujte (ako je dovoljno jeftin) i obavestite kompaniju.

Ako pronađete bilo koji **domen sa IP adresom različitom** od onih koje ste već pronašli tokom otkrivanja resursa, trebalo bi da obavite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Imajte na umu da je domen ponekad hostovan na IP adresi koju klijent ne kontroliše, pa nije u opsegu; budite oprezni._

## Poddomeni

> Znamo sve kompanije u opsegu, sve resurse svake kompanije i sve domene povezane sa tim kompanijama.

Vreme je da pronađemo sve moguće poddomene svakog pronađenog domena.

> [!TIP]
> Imajte na umu da neki alati i tehnike za pronalaženje domena mogu da pomognu i u pronalaženju poddomena

### **DNS**

Pokušajmo da pronađemo **poddomene** iz **DNS** zapisa. Trebalo bi da pokušamo i sa **Zone Transfer**-om (ako je ranjiv, prijavite to).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Za API-je i platforme koje obuhvataju infrastrukturu, reputaciju, evidenciju o curenju podataka i obogaćivanje podataka izvan otkrivanja poddomena, pogledajte [katalog API-ja za izviđanje i obaveštajne podatke o pretnjama](reconnaissance-and-threat-intelligence-apis.md).

Najbrži način da pronađete mnogo poddomena jeste pretraga eksternih izvora. Najčešće korišćeni **alati** su sledeći (za bolje rezultate podesite API ključeve):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/OWASP/Amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Edu4rdSHL/findomain/)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

- [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

- [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

- [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

- [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

Postoje **i drugi zanimljivi alati/API-ji** koji, iako nisu direktno specijalizovani za pronalaženje poddomena, mogu biti korisni za njihovo pronalaženje, kao što je:

- [**IP.THC.ORG**](https://ip.thc.org) besplatan API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Koristi API [https://sonar.omnisint.io](https://sonar.omnisint.io) za pribavljanje poddomena

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**Besplatni JLDC API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) besplatan API

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

- [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

- [**gau**](https://github.com/lc/gau)**:** preuzima poznate URL-ove sa AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl za bilo koji domen.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Pretražuju web u potrazi za JS fajlovima i iz njih izdvajaju poddomene.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

- [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) ima besplatan API za pretragu poddomena i istorije IP adresa
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ovaj projekat besplatno nudi **sve poddomene povezane sa bug-bounty programima**. Ovim podacima možete pristupiti i pomoću [chaospy](https://github.com/dr-0x0x/chaospy), ili možete direktno pristupiti opsegu koji koristi ovaj projekat: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Poređenje** mnogih ovih alata možete pronaći ovde: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Pokušajmo da pronađemo nove **poddomenе** primenom brute force metode nad DNS serverima, koristeći moguće nazive poddomena.

Za ovu radnju biće vam potrebne neke **uobičajene liste reči za poddomene, kao što su**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrebne su vam i IP adrese dobrih DNS resolvera. Da biste napravili listu pouzdanih DNS resolvera, možete preuzeti resolvere sa [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i filtrirati ih pomoću alata [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Možete koristiti i: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najpreporučeniji alati za DNS brute force su:

- [**massdns**](https://github.com/blechschmidt/massdns): Ovo je bio prvi alat koji je efikasno obavljao DNS brute force. Veoma je brz, ali je sklon davanju lažno pozitivnih rezultata.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Mislim da ovaj koristi samo 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) je wrapper za `massdns`, napisan u go-u, koji omogućava enumeraciju validnih poddomena pomoću aktivnog bruteforce-a, kao i razrešavanje poddomena uz rukovanje wildcard-om i jednostavnu podršku za ulaz i izlaz.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Takođe koristi `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) koristi asyncio za asinhroni brute force naziva domena.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Drugi DNS Brute-Force krug

Nakon što pronađete poddomene pomoću otvorenih izvora i brute-force tehnika, možete generisati varijacije pronađenih poddomena kako biste pokušali da pronađete još više. Nekoliko alata je korisno za ovu svrhu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na osnovu domena i poddomena generiše permutacije.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Generiše permutacije na osnovu domena i poddomena.
  - [**Ovde**](https://github.com/subfinder/goaltdns/blob/master/words.txt) možete pronaći goaltdns **wordlist** za permutacije.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na osnovu domena i poddomena generiše permutacije. Ako nije navedena datoteka sa permutacijama, gotator će koristiti sopstvenu.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Osim što generiše permutacije poddomena, može i da pokuša da ih razreši (ali je bolje koristiti prethodno navedene alate).
  - **wordlist** za altdns permutacije možete pronaći [**ovde**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Još jedan alat za izvođenje permutacija, mutacija i izmena poddomena. Ovaj alat će brute force-om pronaći rezultate (ne podržava DNS wildcard).
  - dmut listu reči za permutacije možete preuzeti [**ovde**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na osnovu domena **generiše nazive potencijalnih poddomena** prema navedenim obrascima, kako bi pokušao da otkrije još poddomena.

#### Pametno generisanje permutacija

- [**regulator**](https://github.com/cramppet/regulator): Uči regex obrasce na osnovu otkrivenih poddomena i generiše kandidatska imena za rezoluciju.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ je fuzzer za brute-force pronalaženje poddomena, uparen sa izuzetno jednostavnim, ali efikasnim algoritmom vođenim DNS odgovorima. Koristi dostavljeni skup ulaznih podataka, kao što su prilagođena wordlist-a ili istorijski DNS/TLS zapisi, da precizno generiše slične nazive domena i dalje ih proširuje u petlji na osnovu informacija prikupljenih tokom DNS skeniranja.

```
echo www | subzuf facebook.com
```

### **Tok rada za otkrivanje poddomena**

Primeri Trickest tokova rada kombinuju OSINT, DNS brute force i faze permutacija za ponovljivu enumeraciju poddomena.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Ako ste pronašli IP adresu koja sadrži **jednu ili više veb-stranica** koje pripadaju poddomenima, možete pokušati da **pronađete druge poddomene sa veb-stranicama na toj IP adresi** tako što ćete u **OSINT izvorima** tražiti domene na toj IP adresi ili izvršiti **brute force naziva VHost domena na toj IP adresi**.

#### OSINT

Neke **VHosts na IP adresama možete pronaći pomoću** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ili drugih API-ja**.

**Brute Force**

Ako sumnjate da je neki poddomen skriven na veb-serveru, možete pokušati da ga pronađete pomoću brute force metode:

Za vhostove zasnovane na imenu, fuzzujte zaglavlje `Host` i koristite ffuf-ovu automatsku kalibraciju za filtriranje podrazumevanog odgovora.<sup>[[2]](#references)</sup>

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

> [!TIP]
> Ovom tehnikom možda ćete čak moći da pristupite internim/skrivenim endpoint-ima.

### **CORS Brute Force**

Ponekad ćete pronaći stranice koje vraćaju zaglavlje _**Access-Control-Allow-Origin**_ samo kada je u zaglavlju _**Origin**_ postavljen validan domen/poddomen. U ovakvim slučajevima možete da zloupotrebite ovo ponašanje da biste **otkrili** nove **poddome­ne**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Dok tražite **subdomene**, obratite pažnju na to da li neki **usmerava** na neku vrstu **bucket-a**; ako je tako, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Takođe, pošto ćete u ovom trenutku znati sve domene u opsegu, pokušajte da [**brute force-ujete moguća imena bucket-a i proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Praćenje**

Možete **pratiti** da li se kreiraju **novi poddomeni** domena tako što ćete pratiti **Certificate Transparency** logove, kao što to radi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Traženje ranjivosti**

Proverite da li je moguće izvršiti [**preuzimanje poddomena**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Ako **poddomen** usmerava na neki **S3 bucket**, [**proverite dozvole**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Ako pronađete **poddomen sa IP adresom koja se razlikuje** od onih koje ste već pronašli tokom otkrivanja sredstava, trebalo bi da izvršite **osnovno skeniranje ranjivosti** (pomoću Nessus-a ili OpenVAS-a) i [**skeniranje portova**](../pentesting-network/index.html#discovering-hosts-from-the-outside) pomoću **nmap/masscan/shodan**. U zavisnosti od pokrenutih servisa, u **ovoj knjizi možete pronaći neke trikove za njihov „napad“**.\
_Imajte na umu da se poddomen ponekad hostuje na IP adresi koju klijent ne kontroliše, pa nije u opsegu. Budite oprezni._

## IP adrese

U početnim koracima ste možda **pronašli neke IP opsege, domene i poddomene**.\
Vreme je da **prikupite sve IP adrese iz tih opsega** i za **domene/poddomenе (DNS upiti).**

Pomoću servisa iz sledećih **besplatnih API-ja** možete pronaći i **prethodne IP adrese koje su koristili domeni i poddomeni**. Klijent je možda još uvek vlasnik tih IP adresa (što bi vam moglo pomoći da pronađete [**zaobilaženja CloudFlare-a**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Možete proveriti i koji domeni upućuju na određenu IP adresu pomoću alata [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Traženje ranjivosti**

**Skenirajte portove na svim IP adresama koje ne pripadaju CDN-ovima** (jer najverovatnije nećete pronaći ništa zanimljivo na njima). Među otkrivenim pokrenutim servisima možda ćete **pronaći ranjivosti**.

**Pronađite** [**vodič**](../pentesting-network/index.html) **o tome kako skenirati hostove.**

## Traženje web servera

> Pronašli smo sve kompanije i njihova sredstva i znamo IP opsege, domene i poddomene u opsegu. Vreme je da potražimo web servere.

U prethodnim koracima ste verovatno već izvršili **izviđanje otkrivenih IP adresa i domena**, pa ste možda **već pronašli sve moguće web servere**. Međutim, ako niste, sada ćemo pogledati nekoliko **brzih trikova za traženje web servera** u opsegu.

Imajte na umu da je ovo **usmereno na otkrivanje web aplikacija**, pa bi trebalo da izvršite i **skeniranje ranjivosti** i **portova** (**ako je to dozvoljeno** u opsegu).

**Brz metod** za otkrivanje **otvorenih portova** povezanih sa **web** serverima pomoću [**masscan-a možete pronaći ovde**](../pentesting-network/index.html#http-port-discovery).\
Još jedan praktičan alat za traženje web servera je [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Dovoljno je da prosledite listu domena, a alat će pokušati da se poveže na port 80 (http) i 443 (https). Pored toga, možete navesti i druge portove koje želite da proveri:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Sada kada ste otkrili **sve web servere** u scope-u (među **IP-ovima** kompanije i svim **domenima** i **subdomenima**), verovatno **ne znate odakle da počnete**. Zato ćemo pojednostaviti stvari i početi tako što ćemo napraviti screenshotove svih njih. Samo **pregledom** **glavne stranice** možete pronaći **čudne** endpoint-e koji su podložniji tome da budu **ranjivi**.

Za ovu ideju možete koristiti [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ili [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Pored toga, možete pokrenuti [**eyeballer**](https://github.com/BishopFox/eyeballer) nad svim **screenshotovima** da biste saznali **šta verovatno sadrži ranjivosti**, a šta ne.

## Javni Cloud resursi

Da biste pronašli potencijalne cloud resurse koji pripadaju kompaniji, trebalo bi da **počnete od liste ključnih reči koje identifikuju tu kompaniju**. Na primer, za kripto kompaniju mogli biste da koristite reči poput: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Biće vam potrebne i wordliste **uobičajenih reči koje se koriste u nazivima bucket-a**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Zatim bi trebalo da generišete **permutacije** od tih reči (za više informacija pogledajte [**Drugi krug DNS brute-force-a**](#second-dns-bruteforce-round)).

Dobijene wordliste možete koristiti uz alate kao što su [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ili** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Imajte na umu da pri traženju Cloud resursa treba da **tražite i više od samih bucket-a na AWS-u**.

### **Traženje ranjivosti**

Ako pronađete stvari poput **otvorenih bucket-a ili izloženih cloud funkcija**, trebalo bi da im **pristupite** i pokušate da utvrdite šta nude i da li možete da ih zloupotrebite.

## Imejlovi

Uz **domene** i **subdomene** obuhvaćene scope-om, imate praktično sve što vam je **potrebno da počnete da tražite imejlove**. Evo **API-ja** i **alata** koji su mi se pokazali najkorisnijim za pronalaženje imejlova neke kompanije:

- [**theHarvester**](https://github.com/laramies/theHarvester) - uz API-je
- API za [**https://hunter.io/**](https://hunter.io/) (besplatna verzija)
- API za [**https://app.snov.io/**](https://app.snov.io/) (besplatna verzija)
- API za [**https://minelead.io/**](https://minelead.io/) (besplatna verzija)

### **Traženje ranjivosti**

Imejlovi će vam kasnije dobro doći za **brute-force napade na web prijave i auth servise** (kao što je SSH). Potrebni su i za **phishing**. Pored toga, ovi API-ji će vam dati još **informacija o osobi** koja stoji iza imejla, što je korisno za phishing kampanju.

## Credential Leaks

Uz **domene,** **subdomene** i **imejlove** možete početi da tražite credential leaks iz prošlosti koji se odnose na te imejlove:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Traženje ranjivosti**

Ako pronađete **važeće leaked** akreditive, to je veoma laka pobeda.

## Secrets Leaks

Credential leaks se odnose na hakovanja kompanija pri kojima su **osetljive informacije procurele i bile prodate**. Međutim, kompanije mogu biti pogođene i **drugim leakovima** čije informacije nisu u tim bazama podataka:

### Github Leaks

Akreditivi i API-ji mogu procureti u **javnim repozitorijumima** **kompanije** ili **korisnika** koji rade za tu Github kompaniju.\
Možete koristiti alat [**Leakos**](https://github.com/carlospolop/Leakos) da **preuzmete** sve **javne repozitorijume** neke **organizacije** i njenih **developera**, pa da automatski pokrenete [**gitleaks**](https://github.com/zricethezav/gitleaks) nad njima.

**Leakos** se može koristiti i za pokretanje **gitleaks** nad svim **tekstualnim** URL-ovima koji su mu prosleđeni, jer i **web stranice ponekad sadrže secrets**.

#### Github Dorks

Pogledajte stranicu [GitHub dorks and leaks](github-leaked-secrets.md) da biste pronašli potencijalne **GitHub dorks** za pretragu organizacije.

### Pastes Leaks

Ponekad napadači ili zaposleni **objave sadržaj kompanije na paste sajtu**. On može, ali i ne mora da sadrži **osetljive informacije**, ali svakako vredi pretražiti ga.\
Možete koristiti alat [**Pastos**](https://github.com/carlospolop/Pastos) da istovremeno pretražite više od 80 paste sajtova.

### Google Dorks

Stari, ali zlatni Google dorks uvek su korisni za pronalaženje **izloženih informacija koje ne bi trebalo da budu dostupne**. Jedini problem je što [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) sadrži nekoliko **hiljada** mogućih upita koje ne možete ručno da pokrenete. Zato možete odabrati svojih omiljenih 10 ili koristiti **alat kao što je** [**Gorks**](https://github.com/carlospolop/Gorks) **da ih pokrenete sve**.

_Napomena: alati koji pokušavaju da pretraže celu bazu podataka koristeći običan Google browser nikada neće završiti, jer će vas Google veoma brzo blokirati._

### **Traženje ranjivosti**

Ako pronađete **važeće leaked** akreditive ili API tokene, to je veoma laka pobeda.

## Ranjivosti u javno dostupnom kodu

Ako otkrijete da kompanija ima **open-source kod**, možete da ga **analizirate** i potražite **ranjivosti**.

**U zavisnosti od jezika**, možete koristiti različite **alate**; pogledajte listu [alata za pregled izvornog koda](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Postoje i besplatni servisi koji vam omogućavaju da **skenirate javne repozitorijume**, kao što je:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting metodologija za web aplikacije**](../../network-services-pentesting/pentesting-web/index.html)

**Većina ranjivosti** koje pronađu bug hunter-i nalazi se u **web aplikacijama**, pa bih u ovom trenutku želeo da predstavim **metodologiju testiranja web aplikacija**; [**ove informacije možete pronaći ovde**](../../network-services-pentesting/pentesting-web/index.html).

Želim posebno da pomenem i odeljak [**Open-source alati za automatsko skeniranje web aplikacija**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), jer, iako ne treba očekivati da će pronaći veoma osetljive ranjivosti, korisni su za uključivanje u **workflow-e radi prikupljanja početnih informacija o web aplikacijama.**

## Rekapitulacija

> Čestitamo! Do ovog trenutka već ste obavili **osnovnu enumeraciju**. Da, osnovnu, jer može da se uradi još mnogo enumeracije (kasnije ćemo videti još trikova).

Dakle, već ste:

1. Pronašli sve **kompanije** obuhvaćene scope-om
2. Pronašli sve **resurse** koji pripadaju kompanijama (i izvršili vuln scan ako je obuhvaćen scope-om)
3. Pronašli sve **domene** koji pripadaju kompanijama
4. Pronašli sve **subdomene** tih domena (ima li subdomain takeover-a?)
5. Pronašli sve **IP adrese** (sa **CDN-ova** i van njih) obuhvaćene scope-om.
6. Pronašli sve **web servere** i napravili njihove **screenshotove** (ima li nečeg čudnog što vredi detaljnije istražiti?)
7. Pronašli sve **potencijalne javne cloud resurse** koji pripadaju kompaniji.
8. **Imejlove**, **credential leaks** i **secret leaks** koji bi vam mogli doneti **veliku pobedu uz vrlo malo truda**.
9. **Izvršili pentesting svih pronađenih web aplikacija**

## **Alati za automatski Full Recon**

Postoji nekoliko alata koji će izvršiti deo predloženih radnji nad zadatim scope-om.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Nešto je zastareo i više se ne ažurira

## References

- [1] [Jason Haddix – Metodologija bug hunter-a, v4.0: Recon izdanje](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O favicon-ima: od ikona browser-a do obaveštajnih podataka o površini napada](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Pretvaranje favicon.ico u oružje za Bug Bounties, OSINT i sve ostalo](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Otkrivanje domena pomoću napada vremenske korelacije na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasivno preuzimanje: otkrivanje (i imitiranje) skupe kampanje za preuzimanje subdomena](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: jedinstvena metoda enumeracije subdomena](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Kompletan workflow za otkrivanje subdomena, prvi deo](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automatsko otkrivanje subdomena brute-force-om pomoću Trickest workflow-a, drugi deo](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Screenshot izlaza favihash-a](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
